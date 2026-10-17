// Read-only MySQL/MariaDB + PostgreSQL browsing over an existing SSH connection.
// Runs the server's own CLI clients (mysql/mariadb/psql) via ssh exec; no DB port is exposed.
'use strict';

const SAFE_IDENT = /^[A-Za-z0-9_$.-]{1,64}$/;
const shq = s => "'" + String(s).replace(/'/g, "'\\''") + "'";
const FORBID = /\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|into|lock|unlock|kill|vacuum|analy[sz]e|reindex|cluster|prepare|execute|listen|notify|begin|commit|rollback|savepoint|declare|attach|install|shutdown|sleep|benchmark|pg_sleep|load_file|pg_read_file|pg_read_binary_file|pg_ls_dir|lo_import|lo_export|dblink|get_lock|release_lock|pg_terminate_backend|pg_cancel_backend|set_config|nextval|setval|handler|flush|reset)\b/i;

function validateSql(sql) {
  const s = String(sql).trim().replace(/;\s*$/, '');
  if (!s) return 'Empty query';
  if (s.length > 4000) return 'Query too long (4000 characters max)';
  if (/\0/.test(s)) return 'Invalid character';
  const bare = s.replace(/'(?:[^'\\]|\\.|'')*'/g, "''").replace(/"(?:[^"\\]|\\.|"")*"/g, '""').replace(/`[^`]*`/g, '``');
  if (bare.includes(';')) return 'Only one statement at a time';
  if (/\/\*|--|#/.test(bare)) return 'Comments are not allowed';
  if (!/^\s*\(*\s*(select|show|describe|desc|explain|with|table|values)\b/i.test(bare)) return 'Read-only: only SELECT, SHOW, DESCRIBE, EXPLAIN and WITH are allowed';
  if (FORBID.test(bare)) return 'That query uses a keyword that is not allowed in read-only mode';
  return null;
}

const FIXED = {
  mysql: {
    dbs: () => `SELECT table_schema AS name, ROUND(SUM(data_length+index_length)/1048576,1) AS size_mb, COUNT(*) AS tables_count FROM information_schema.tables GROUP BY table_schema ORDER BY SUM(data_length+index_length) DESC`,
    tables: db => `SELECT table_name AS name, table_rows AS row_estimate, ROUND((data_length+index_length)/1048576,2) AS size_mb, engine FROM information_schema.tables WHERE table_schema='${db}' ORDER BY (data_length+index_length) DESC`,
    procs: () => `SELECT id, user, host, IFNULL(db,'') AS db, command, time AS secs, LEFT(IFNULL(info,''),200) AS query FROM information_schema.processlist ORDER BY time DESC`,
    version: 'SELECT VERSION()',
  },
  postgres: {
    dbs: () => `SELECT datname AS name, ROUND(pg_database_size(datname)/1048576.0,1) AS size_mb FROM pg_database WHERE NOT datistemplate ORDER BY pg_database_size(datname) DESC`,
    tables: () => `SELECT schemaname||'.'||relname AS name, n_live_tup AS row_estimate, ROUND(pg_total_relation_size(relid)/1048576.0,2) AS size_mb FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC`,
    procs: () => `SELECT pid, usename AS user, COALESCE(client_addr::text,'local') AS host, datname AS db, state, COALESCE(EXTRACT(EPOCH FROM now()-query_start)::int,0) AS secs, LEFT(query,200) AS query FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND datname IS NOT NULL ORDER BY 6 DESC`,
    version: 'SHOW server_version',
  },
};

function createDb(run) {
  const ctx = {};       // engine -> { method, user, pw, client }
  let creds = {};

  function buildCmd(engine, c, sql, { db, header = true } = {}) {
    const env = []; const sudo = c.method === 'sudo' ? (engine === 'postgres' ? 'sudo -n -u postgres ' : 'sudo -n ') : '';
    if (engine === 'mysql') {
      let args = '';
      if (c.method === 'creds') { args = ` -h 127.0.0.1 -u ${shq(c.user)}`; env.push(shq('MYSQL_PWD=' + c.pw)); }
      return `${sudo}env ${env.join(' ')} timeout 20 ${c.client}${args}${db ? ' -D ' + shq(db) : ''} -B --default-character-set=utf8mb4${header ? '' : ' -N'} -e ${shq('SET SESSION TRANSACTION READ ONLY; ' + sql)} 2>&1; echo __rc=$?`;
    }
    env.push(shq('PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=15000'));
    let args = '';
    if (c.method === 'creds') { args = ` -h 127.0.0.1 -U ${shq(c.user)}`; env.push(shq('PGPASSWORD=' + c.pw)); }
    return `${sudo}env ${env.join(' ')} timeout 20 psql -X -A -F "$(printf '\\t')" -P footer=off${header ? '' : ' -t'}${args} -d ${shq(db || 'postgres')} -c ${shq(sql)} 2>&1; echo __rc=$?`;
  }

  function parse(out) {
    const m = out.match(/__rc=(\d+)\s*$/); const rc = m ? +m[1] : 1;
    const text = out.replace(/__rc=\d+\s*$/, '').replace(/\s+$/, '');
    if (rc === 124) return { error: 'Query timed out (20 s)' };
    if (rc !== 0 || /^(ERROR|psql:|mysql:|mariadb:|sudo:|FATAL)/m.test(text.split('\n')[0] || '')) return { error: (text.split('\n').find(Boolean) || 'Command failed').slice(0, 300) };
    if (!text) return { columns: [], rows: [] };
    const lines = text.split('\n'); const columns = lines[0].split('\t');
    let rows = lines.slice(1).map(l => l.split('\t').map(v => v.length > 300 ? v.slice(0, 300) + '…' : v));
    let truncated = false; if (rows.length > 500) { rows = rows.slice(0, 500); truncated = true; }
    return { columns, rows, truncated };
  }

  async function exec(engine, sql, opts) {
    const c = ctx[engine]; if (!c) return { error: 'Not connected to this database engine' };
    return parse(await run(buildCmd(engine, c, sql, opts)));
  }

  return {
    async detect(newCreds) {
      if (newCreds) creds = newCreds;
      const has = await run('for b in mysql mariadb psql; do command -v $b >/dev/null 2>&1 && echo has:$b; done');
      const bins = new Set([...has.matchAll(/has:(\w+)/g)].map(x => x[1]));
      const defs = [];
      if (bins.has('mysql') || bins.has('mariadb')) defs.push({ engine: 'mysql', label: 'MySQL / MariaDB', client: bins.has('mysql') ? 'mysql' : 'mariadb' });
      if (bins.has('psql')) defs.push({ engine: 'postgres', label: 'PostgreSQL', client: 'psql' });
      const out = [];
      for (const d of defs) {
        const methods = [];
        const cr = creds[d.engine]; if (cr && cr.user) methods.push({ method: 'creds', user: String(cr.user), pw: String(cr.pw || '') });
        methods.push({ method: 'plain' }, { method: 'sudo' });
        let last = '';
        delete ctx[d.engine];
        for (const mth of methods) {
          const c = { ...mth, client: d.client };
          const r = parse(await run(buildCmd(d.engine, c, FIXED[d.engine].version)));
          if (!r.error && r.rows && /^\d/.test((r.rows[0] || [])[0] || '')) {
            ctx[d.engine] = c; out.push({ ...d, ok: true, version: r.rows[0][0].split(' ')[0], via: { plain: 'current user', sudo: 'sudo', creds: 'saved login' }[c.method] }); last = null; break;
          }
          last = r.error || 'No response';
        }
        if (last !== null) out.push({ ...d, ok: false, error: last });
      }
      return out;
    },
    async handle(m) {
      const engine = m.engine === 'postgres' ? 'postgres' : m.engine === 'mysql' ? 'mysql' : null;
      const reply = { kind: m.kind, rid: m.rid };
      if (!engine) return { ...reply, error: 'Unknown engine' };
      const db = m.db == null || m.db === '' ? null : String(m.db);
      if (db && !SAFE_IDENT.test(db)) return { ...reply, error: 'Invalid database name' };
      const F = FIXED[engine];
      let r;
      if (m.kind === 'dbs') r = await exec(engine, F.dbs());
      else if (m.kind === 'tables') r = db ? await exec(engine, F.tables(db), { db }) : { error: 'Pick a database first' };
      else if (m.kind === 'procs') r = await exec(engine, F.procs());
      else if (m.kind === 'query') {
        const bad = validateSql(m.sql);
        r = bad ? { error: bad } : await exec(engine, String(m.sql).trim().replace(/;\s*$/, ''), { db });
      } else r = { error: 'Unknown request' };
      return { ...reply, db, ...r };
    },
    validateSql,
  };
}

module.exports = { createDb, validateSql };
