// Burrow backend: static files, vault API, SSH shell/SFTP over WebSocket, port forwarding.
// Binds to localhost only. It holds SSH credentials, so never expose it on a network.
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');
const os = require('os');
const crypto = require('crypto');
const { Client, utils } = require('ssh2');
const { WebSocketServer } = require('ws');
const { createDb } = require('./db');

const PORT = +process.env.PORT || 8765;
const BIND = '127.0.0.1';
const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
const KEYDIR = path.join(DATA, 'keys');
const STATE_FILE = path.join(DATA, 'state.json');
const SSH_DIR = path.join(os.homedir(), '.ssh');
const MAX_FILE = 64 * 1024 * 1024;

fs.mkdirSync(KEYDIR, { recursive: true, mode: 0o700 });

// ---------- state ----------
let state = { hosts: [], forwards: [], snippets: [], known: {} };
const DEFAULT_SNIPPETS = [
  { name: 'Tail app log', cmd: 'tail -f logs/app.log' },
  { name: 'Disk usage', cmd: 'df -h' },
  { name: 'Running containers', cmd: 'docker ps' },
  { name: 'Memory', cmd: 'free -h' },
  { name: 'Who is logged in', cmd: 'w' },
];
try { state = { ...state, ...JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) }; }
catch { state.snippets = DEFAULT_SNIPPETS; saveState(); }

function saveState() {
  const tmp = STATE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, STATE_FILE);
}

// ---------- keys ----------
const NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;
function keyFile(name) {
  if (typeof name !== 'string') return null;
  const sys = name.startsWith('ssh:');
  const base = sys ? name.slice(4) : name;
  if (!NAME_RE.test(base) || base.endsWith('.pub')) return null;
  const f = path.join(sys ? SSH_DIR : KEYDIR, base);
  return fs.existsSync(f) ? f : null;
}
function fingerprint(buf) { return 'SHA256:' + crypto.createHash('sha256').update(buf).digest('base64').replace(/=+$/, ''); }
function describeKey(name, file) {
  const out = { name, type: 'Unknown', fp: '(encrypted: public key file missing)', added: '' };
  try { out.added = fs.statSync(file).mtime.toLocaleDateString('en', { month: 'short', year: 'numeric' }); } catch {}
  let parsed = null;
  try { parsed = utils.parseKey(fs.readFileSync(file + '.pub')); } catch {}
  if (!parsed || parsed instanceof Error) { try { parsed = utils.parseKey(fs.readFileSync(file)); } catch {} }
  if (parsed && !(parsed instanceof Error)) {
    const k = Array.isArray(parsed) ? parsed[0] : parsed;
    out.type = k.type === 'ssh-ed25519' ? 'ED25519' : k.type === 'ssh-rsa' ? 'RSA' : k.type.replace(/^ssh-|^ecdsa-sha2-/, '').toUpperCase();
    out.fp = fingerprint(k.getPublicSSH());
  } else if (parsed instanceof Error && /passphrase/i.test(parsed.message)) out.type = 'Encrypted';
  return out;
}
function listKeys() {
  const keys = [];
  for (const f of safeDir(KEYDIR)) if (!f.endsWith('.pub')) keys.push(describeKey(f, path.join(KEYDIR, f)));
  for (const f of safeDir(SSH_DIR)) {
    if (/^id_[A-Za-z0-9_]+$/.test(f)) keys.push(describeKey('ssh:' + f, path.join(SSH_DIR, f)));
  }
  return keys;
}
function safeDir(d) { try { return fs.readdirSync(d); } catch { return []; } }

function generateKey(wanted) {
  let name = NAME_RE.test(wanted || '') && !(wanted || '').endsWith('.pub') ? wanted : '';
  if (!name) { let n = 1; while (fs.existsSync(path.join(KEYDIR, `key-${n}-ed25519`))) n++; name = `key-${n}-ed25519`; }
  const f = path.join(KEYDIR, name);
  if (fs.existsSync(f)) throw new Error(`Key “${name}” already exists`);
  const pair = utils.generateKeyPairSync('ed25519', { comment: `burrow-${name}` });
  fs.writeFileSync(f, pair.private, { mode: 0o600 });
  fs.writeFileSync(f + '.pub', pair.public.trim() + '\n');
  return describeKey(name, f);
}

// ---------- ssh connections ----------
function buildConfig(h, log) {
  const port = h.port || 22;
  const cfg = {
    host: h.addr, port, username: h.user, readyTimeout: 15000, keepaliveInterval: 15000, tryKeyboard: h.auth === 'password',
    hostVerifier: key => {
      const fp = fingerprint(key); const id = `${h.addr}:${port}`; const known = state.known[id];
      if (!known) { state.known[id] = fp; saveState(); log(`Host key ${fp} saved (first connection)`, 'dim'); return true; }
      if (known === fp) return true;
      log(`WARNING: host key for ${id} changed (was ${known}, now ${fp}). Refusing to connect. If this is expected, delete that entry from "known" in data/state.json.`, 'err');
      return false;
    },
  };
  if (h.auth === 'password') {
    if (!h.pw) throw new Error('No password saved for this host. Edit the host and set one.');
    cfg.password = h.pw; log('Authenticating with password', 'dim');
  } else if (h.auth === 'agent') {
    cfg.agent = process.env.SSH_AUTH_SOCK || (process.platform === 'win32' ? '\\\\.\\pipe\\openssh-ssh-agent' : undefined);
    if (!cfg.agent) throw new Error('No SSH agent found (SSH_AUTH_SOCK is not set).');
    log('Authenticating with SSH agent', 'dim');
  } else {
    const name = h.key || (listKeys()[0] || {}).name;
    if (!name) throw new Error('No SSH key available. Generate one under Keys.');
    const f = keyFile(name);
    if (!f) throw new Error(`Key “${name}” not found.`);
    cfg.privateKey = fs.readFileSync(f); log(`Authenticating with key “${name}”`, 'dim');
  }
  return cfg;
}
function newClient(h, log) {
  const conn = new Client();
  const cfg = buildConfig(h, log);
  if (h.auth === 'password') conn.on('keyboard-interactive', (n, i, l, prompts, finish) => finish(prompts.map(() => h.pw)));
  return { conn, cfg };
}
function friendlyError(e) {
  const m = e.message || String(e);
  if (/ETIMEDOUT|Timed out/i.test(m)) return `Connection timed out`;
  if (/ECONNREFUSED/.test(m)) return 'Connection refused';
  if (/ENOTFOUND/.test(m)) return 'Host not found';
  if (/authentication methods failed/i.test(m)) return 'Authentication failed (check username, key or password)';
  return m;
}

// ---------- remote ports ----------
function parsePorts(out) {
  const rows = [];
  for (const line of out.split('\n')) {
    const f = line.trim().split(/\s+/); if (f.length < 5) continue;
    let proto, local, rest;
    if (/^(tcp|udp)/.test(f[0]) && /^[A-Z-]+$/.test(f[1] || '')) { proto = f[0]; local = f[4]; rest = f.slice(6).join(' '); }   // ss
    else if (/^(tcp|udp)/.test(f[0])) { proto = f[0]; local = f[3]; rest = f.slice(5).join(' '); }                                // netstat
    else continue;
    const i = local.lastIndexOf(':'); if (i < 0) continue;
    const port = +local.slice(i + 1); if (!port) continue;
    const ssm = rest.match(/users:\(\("([^"]+)",pid=(\d+)/); const nsm = rest.match(/(\d+)\/(\S+)/);
    const proc = ssm ? `${ssm[1]} (${ssm[2]})` : nsm ? `${nsm[2]} (${nsm[1]})` : '';
    rows.push({ proto: proto.replace(/6$/, ''), addr: local.slice(0, i).replace(/^\[|\]$/g, '') || '*', port, proc });
  }
  const seen = new Set();
  return rows.filter(r => { const k = r.proto + r.addr + r.port; if (seen.has(k)) return false; seen.add(k); return true; }).sort((a, b) => a.port - b.port);
}

// ---------- remote cron ----------
const SCHED_RE = /^(@[a-z]+|[0-9*/,\-A-Za-z?]+(?:\s+[0-9*/,\-A-Za-z?]+){4})$/;
function parseCron(out) {
  const sec = { user: '', sys: [], timers: '' };
  let cur = null, file = '/etc/crontab';
  const sysLines = [];
  for (const line of out.split('\n')) {
    if (line === '__USER__') { cur = 'user'; continue; }
    if (line === '__SYS__') { cur = 'sys'; file = '/etc/crontab'; continue; }
    if (line === '__TIMERS__') { cur = 'timers'; continue; }
    if (cur === 'sys' && line.startsWith('__FILE ')) { file = line.slice(7); continue; }
    if (cur === 'user') sec.user += line + '\n';
    else if (cur === 'sys') sysLines.push([file, line]);
    else if (cur === 'timers') sec.timers += line + '\n';
  }
  let rawText = sec.user;
  if (/^no crontab for /m.test(rawText)) rawText = '';
  const raw = rawText.replace(/\s+$/, '');
  const jobs = [];
  raw.split('\n').forEach((line, idx) => {
    const m = line.match(/^(#burrow-off#\s*)?(@[a-z]+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(.+)$/);
    if (!m || (!m[1] && line.trim().startsWith('#')) || /^\w+=/.test(line.trim())) return;
    if (!SCHED_RE.test(m[2])) return;
    jobs.push({ line: idx, schedule: m[2], cmd: m[3], enabled: !m[1] });
  });
  const sys = [];
  for (const [f, line] of sysLines) {
    const t = line.trim(); if (!t || t.startsWith('#') || /^\w+=/.test(t)) continue;
    const m = t.match(/^(@[a-z]+|\S+\s+\S+\s+\S+\s+\S+\s+\S+)\s+(\S+)\s+(.+)$/);
    if (m && SCHED_RE.test(m[1])) sys.push({ file: f, schedule: m[1], user: m[2], cmd: m[3] });
  }
  const timers = [];
  for (const line of sec.timers.split('\n')) {
    const f = line.trim().split(/\s+/); if (f.length < 2 || !/\.timer$/.test(f[f.length - 2])) continue;
    timers.push({ unit: f[f.length - 2], runs: f[f.length - 1], next: f[0] === 'n/a' ? 'n/a' : f.slice(0, 3).join(' ') });
  }
  return { raw, jobs, sys, timers };
}

// ---------- remote services ----------
function runCmd(conn, cmd, cb) {
  conn.exec(cmd, (err, ch) => {
    if (err) return cb(err);
    let out = ''; ch.on('data', d => { out += d; }); ch.stderr.on('data', d => { out += d; });
    ch.on('close', () => cb(null, out));
  });
}
function parseServices(out) {
  const rows = [];
  for (const line of out.split('\n')) {
    const m = line.trim().match(/^(\S+\.service)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$/);
    if (!m || m[2] === 'not-found') continue;
    rows.push({ unit: m[1], name: m[1].replace(/\.service$/, ''), active: m[3], sub: m[4], desc: m[5] });
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name));
}

// ---------- ws sessions ----------
function onSocket(ws) {
  let conn = null, stream = null, sftp = null, ending = false, dbh = null, sysT = null;
  const getDb = () => dbh || (dbh = createDb(cmd => new Promise((res, rej) => runCmd(conn, cmd, (e, o) => e ? rej(e) : res(o)))));
  const send = o => ws.readyState === 1 && ws.send(JSON.stringify(o));
  const log = (text, kind = 'dim') => send({ type: 'log', text, kind });
  const status = (s, message) => send({ type: 'status', status: s, message });

  function getSftp(cb) {
    if (sftp) return cb(null, sftp);
    if (!conn) return cb(new Error('Not connected'));
    conn.sftp((err, s) => { if (err) return cb(err); sftp = s; s.on('close', () => { sftp = null; }); cb(null, s); });
  }
  function pollSys() {
    if (!conn || !stream) return;
    runCmd(conn, "who | awk '{print $1}' | sort -u | wc -l; who | wc -l; cut -d. -f1 /proc/uptime 2>/dev/null", (e, o) => {
      if (e) return;
      const [users, sessions, up] = o.trim().split('\n').map(Number);
      send({ type: 'sysinfo', users: Number.isFinite(users) ? users : null, sessions: Number.isFinite(sessions) ? sessions : null, uptimeSec: Number.isFinite(up) ? up : null });
    });
  }
  function end() { clearInterval(sysT); ending = true; try { stream && stream.end(); } catch {} try { conn && conn.end(); } catch {} }

  function connect(m) {
    const h0 = state.hosts.find(x => x.id === m.hostId);
    if (!h0) return status('failed', 'Unknown host');
    if (h0.altAddr && !m._resolved) {
      status('connecting'); log('Checking which address is reachable…');
      return pickAddr(h0).then(r => { log(`Using ${r.addr}${r.alt ? ' (alternate address)' : ''}`, r.online ? 'dim' : 'warn'); connect({ ...m, _resolved: r.addr }); });
    }
    const h = { ...h0, addr: m._resolved || h0.addr };
    status('connecting');
    let made;
    try { made = newClient(h, log); } catch (e) { return status('failed', e.message); }
    conn = made.conn;
    log(`ssh ${h.user}@${h.addr}${h.port && h.port !== 22 ? ' -p ' + h.port : ''}`);
    conn.on('ready', () => {
      conn.shell({ term: 'xterm-256color', cols: m.cols || 80, rows: m.rows || 24 }, (err, s) => {
        if (err) return status('failed', friendlyError(err));
        stream = s;
        status('connected');
        pollSys(); sysT = setInterval(pollSys, 30000);
        s.on('data', d => ws.readyState === 1 && ws.send(d));
        s.stderr && s.stderr.on('data', d => ws.readyState === 1 && ws.send(d));
        s.on('close', () => { status('closed'); end(); });
      });
    });
    conn.on('error', e => { if (!ending) status(stream ? 'closed' : 'failed', friendlyError(e)); });
    conn.on('close', () => { if (!ending) status(stream ? 'closed' : 'failed', stream ? undefined : 'Connection closed'); });
    try { conn.connect(made.cfg); } catch (e) { status('failed', e.message); }
  }

  ws.on('message', (raw, isBinary) => {
    if (isBinary) return;
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    switch (m.type) {
      case 'connect': if (!conn) connect(m); break;
      case 'in': if (stream && typeof m.data === 'string') stream.write(m.data); break;
      case 'resize': if (stream && m.cols > 0 && m.rows > 0) stream.setWindow(m.rows, m.cols, 0, 0); break;
      case 'disconnect': end(); status('closed'); break;
      case 'ports': {
        if (!conn || !stream) return send({ type: 'ports', error: 'Not connected', rows: [] });
        const cmd = 'ss -H -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null | tail -n +3';
        conn.exec(cmd, (err, ch) => {
          if (err) return send({ type: 'ports', error: friendlyError(err), rows: [] });
          let out = ''; ch.on('data', d => { out += d; }); ch.stderr.on('data', () => {});
          ch.on('close', () => send({ type: 'ports', rows: parsePorts(out), error: out.trim() ? '' : 'Neither ss nor netstat is available on this server' }));
        });
        break;
      }
      case 'services': {
        if (!conn || !stream) return send({ type: 'services', error: 'Not connected', rows: [] });
        runCmd(conn, 'systemctl list-units --type=service --all --no-legend --no-pager --plain 2>&1', (err, out) => {
          if (err) return send({ type: 'services', error: friendlyError(err), rows: [] });
          const rows = parseServices(out);
          send({ type: 'services', rows, error: rows.length ? '' : 'No systemd services found (is this a systemd host?)' });
        });
        break;
      }
      case 'docker': {
        if (!conn || !stream) return send({ type: 'docker', error: 'Not connected', rows: [] });
        const fmt = "--format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}|{{.Ports}}'";
        runCmd(conn, `docker ps -a ${fmt} 2>/dev/null || sudo -n docker ps -a ${fmt} 2>&1`, (err, out) => {
          if (err) return send({ type: 'docker', error: friendlyError(err), rows: [] });
          const rows = out.split('\n').map(l => l.trim().split('|')).filter(f => f.length >= 6 && /^[0-9a-f]{6,}$/.test(f[0]))
            .map(f => ({ id: f[0], name: f[1], image: f[2], state: f[3], status: f[4], ports: f.slice(5).join('|') }));
          let error = '';
          if (!rows.length) error = /not found|command not found/i.test(out) ? 'Docker is not installed on this server' : /permission denied|password is required|a terminal is required/i.test(out) ? 'Docker needs root, docker group membership or passwordless sudo' : /^\s*$/.test(out) || /CONTAINER/.test(out) ? '' : out.trim().split('\n')[0].slice(0, 160);
          send({ type: 'docker', rows, error });
        });
        break;
      }
      case 'docker-action': {
        const unit = String(m.id || ''); const action = String(m.action || '');
        if (!conn || !stream) return send({ type: 'service-result', unit, action, ok: false, output: 'Not connected' });
        if (!/^[A-Za-z0-9_.-]{1,128}$/.test(unit) || !['start', 'stop', 'restart'].includes(action)) return send({ type: 'service-result', unit, action, ok: false, output: 'Invalid request' });
        runCmd(conn, `docker ${action} ${unit} 2>/dev/null || sudo -n docker ${action} ${unit} 2>&1; echo "__rc=$?"`, (err, out) => {
          if (err) return send({ type: 'service-result', unit, action, ok: false, output: friendlyError(err) });
          const rc = (out.match(/__rc=(\d+)\s*$/) || [])[1];
          const text = out.replace(/__rc=\d+\s*$/, '').trim();
          send({ type: 'service-result', unit, action, ok: rc === '0', kind: 'docker', output: rc === '0' ? '' : (text.split('\n').pop() || 'Command failed').slice(0, 200) });
        });
        break;
      }
      case 'cron': {
        if (!conn || !stream) return send({ type: 'cron', error: 'Not connected', jobs: [], sys: [], timers: [], raw: '' });
        const cmd = "echo '__USER__'; crontab -l 2>&1; echo '__SYS__'; cat /etc/crontab 2>/dev/null; for f in /etc/cron.d/*; do [ -f \"$f\" ] && { echo \"__FILE $f\"; cat \"$f\"; }; done 2>/dev/null; echo '__TIMERS__'; systemctl list-timers --all --no-pager --no-legend 2>/dev/null";
        runCmd(conn, cmd, (err, out) => err ? send({ type: 'cron', error: friendlyError(err), jobs: [], sys: [], timers: [], raw: '' }) : send({ type: 'cron', ...parseCron(out), error: '' }));
        break;
      }
      case 'cron-save': {
        if (!conn || !stream) return send({ type: 'cron-result', ok: false, output: 'Not connected' });
        const lines = Array.isArray(m.lines) ? m.lines.map(String) : null;
        if (!lines || lines.length > 2000 || lines.some(l => l.length > 2000 || /[\0\r\n]/.test(l))) return send({ type: 'cron-result', ok: false, output: 'Invalid crontab content' });
        runCmd(conn, 'crontab -l 2>/dev/null', (e1, cur) => {
          if (e1) return send({ type: 'cron-result', ok: false, output: friendlyError(e1) });
          const norm = s => String(s).replace(/\s+$/, '');
          if (norm(cur) !== norm(m.expect || '')) return send({ type: 'cron-result', ok: false, output: 'Crontab changed on the server since it was loaded. Refresh and try again.' });
          conn.exec('crontab -l > "$HOME/.burrow-crontab.bak" 2>/dev/null; crontab - 2>&1', (e2, ch) => {
            if (e2) return send({ type: 'cron-result', ok: false, output: friendlyError(e2) });
            let out = ''; ch.on('data', d => { out += d; }); ch.stderr.on('data', d => { out += d; });
            ch.on('close', code => send({ type: 'cron-result', ok: code === 0, output: code === 0 ? '' : (out.trim() || 'crontab failed').slice(0, 300) }));
            ch.end(lines.join('\n') + (lines.length ? '\n' : ''));
          });
        });
        break;
      }
      case 'db-detect': {
        if (!conn || !stream) return send({ type: 'db-info', error: 'Not connected', engines: [] });
        const c = m.creds && typeof m.creds === 'object' ? { mysql: m.creds.mysql, postgres: m.creds.postgres } : undefined;
        getDb().detect(c).then(engines => send({ type: 'db-info', engines, error: engines.length ? '' : 'No mysql, mariadb or psql client found on this server' }))
          .catch(e => send({ type: 'db-info', engines: [], error: friendlyError(e) }));
        break;
      }
      case 'db-query': {
        if (!conn || !stream) return send({ type: 'db-result', kind: m.kind, rid: m.rid, error: 'Not connected' });
        getDb().handle({ kind: ['dbs', 'tables', 'procs', 'query'].includes(m.kind) ? m.kind : '', rid: m.rid, engine: m.engine, db: m.db, sql: m.sql })
          .then(r => send({ type: 'db-result', ...r })).catch(e => send({ type: 'db-result', kind: m.kind, rid: m.rid, error: friendlyError(e) }));
        break;
      }
      case 'service-action': {
        const unit = String(m.unit || ''); const action = String(m.action || '');
        if (!conn || !stream) return send({ type: 'service-result', unit, action, ok: false, output: 'Not connected' });
        if (!/^[A-Za-z0-9@._:-]{1,128}$/.test(unit) || !['start', 'stop', 'restart'].includes(action)) return send({ type: 'service-result', unit, action, ok: false, output: 'Invalid request' });
        runCmd(conn, `systemctl ${action} ${unit} 2>/dev/null || sudo -n systemctl ${action} ${unit} 2>&1; echo "__rc=$?"`, (err, out) => {
          if (err) return send({ type: 'service-result', unit, action, ok: false, output: friendlyError(err) });
          const rc = (out.match(/__rc=(\d+)\s*$/) || [])[1];
          const text = out.replace(/__rc=\d+\s*$/, '').trim();
          const ok = rc === '0';
          send({ type: 'service-result', unit, action, ok, output: ok ? '' : (/password is required|a terminal is required|interactive authentication/i.test(text) ? 'Needs root or passwordless sudo on this server (sudo -n failed).' : text || 'Command failed') });
        });
        break;
      }
      case 'sftp-list': getSftp((err, s) => {
        if (err) return send({ type: 'sftp-error', message: friendlyError(err) });
        const req = !m.path || m.path === '.' || m.path === '~' ? '.' : m.path;
        s.realpath(req, (e1, real) => {
          if (e1) return send({ type: 'sftp-error', message: e1.message });
          s.readdir(real, (e2, list) => {
            if (e2) return send({ type: 'sftp-error', message: e2.message });
            const entries = list.filter(f => f.filename !== '.' && f.filename !== '..').map(f => ({ name: f.filename, dir: f.attrs.isDirectory(), size: f.attrs.size, mtime: f.attrs.mtime }))
              .sort((a, b) => (b.dir - a.dir) || a.name.localeCompare(b.name));
            send({ type: 'sftp-list', path: real, entries });
          });
        });
      }); break;
      case 'sftp-get': getSftp((err, s) => {
        if (err) return send({ type: 'sftp-error', message: friendlyError(err) });
        s.stat(m.path, (e1, st) => {
          if (e1) return send({ type: 'sftp-error', message: e1.message });
          if (st.size > MAX_FILE) return send({ type: 'sftp-error', message: 'File is larger than 64 MB' });
          s.readFile(m.path, (e2, buf) => {
            if (e2) return send({ type: 'sftp-error', message: e2.message });
            send({ type: 'sftp-file', name: path.posix.basename(m.path), data: buf.toString('base64') });
          });
        });
      }); break;
      case 'sftp-put': getSftp((err, s) => {
        if (err) return send({ type: 'sftp-error', message: friendlyError(err) });
        const dest = path.posix.join(m.dir, path.posix.basename(String(m.name)));
        s.writeFile(dest, Buffer.from(m.data, 'base64'), e => send(e ? { type: 'sftp-error', message: e.message } : { type: 'sftp-put', name: m.name }));
      }); break;
    }
  });
  ws.on('close', end);
  ws.on('error', end);
}

// ---------- port forwarding ----------
const tunnels = new Map(); // id -> { conn, server }
const fwdStatus = {};      // id -> { state, error }

function socks5(sock, conn) {
  sock.on('error', () => {});
  sock.once('data', b => {
    if (b[0] !== 5) return sock.destroy();
    sock.write(Buffer.from([5, 0]));
    sock.once('data', r => {
      if (r[1] !== 1) return sock.end(Buffer.from([5, 7, 0, 1, 0, 0, 0, 0, 0, 0]));
      let host, off;
      if (r[3] === 1) { host = [...r.subarray(4, 8)].join('.'); off = 8; }
      else if (r[3] === 3) { const l = r[4]; host = r.subarray(5, 5 + l).toString(); off = 5 + l; }
      else if (r[3] === 4) { host = Array.from({ length: 8 }, (_, i) => r.readUInt16BE(4 + i * 2).toString(16)).join(':'); off = 20; }
      else return sock.destroy();
      const port = r.readUInt16BE(off);
      conn.forwardOut('127.0.0.1', 0, host, port, (err, st) => {
        if (err) return sock.end(Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]));
        sock.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
        st.on('error', () => sock.destroy()); st.on('close', () => sock.destroy());
        sock.pipe(st).pipe(sock);
      });
    });
  });
}

function stopTunnel(id) {
  const t = tunnels.get(id); if (!t) return;
  tunnels.delete(id);
  try { t.server && t.server.close(); } catch {} try { t.conn.end(); } catch {}
  delete fwdStatus[id];
}
async function startTunnel(id) {
  const f0 = state.forwards.find(x => x.id === id); const h0 = f0 && state.hosts.find(x => x.id === f0.via);
  const r = h0 ? await pickAddr(h0) : null;
  return startTunnelInner(id, h0 && { ...h0, addr: r.addr });
}
function startTunnelInner(id, hOverride) {
  return new Promise(resolve => {
    stopTunnel(id);
    const f = state.forwards.find(x => x.id === id);
    const h = hOverride || (f && state.hosts.find(x => x.id === f.via));
    if (!f) return resolve({ ok: false, error: 'Unknown forward' });
    if (!h) return resolve({ ok: false, error: 'Jump host no longer exists' });
    let made;
    try { made = newClient(h, () => {}); } catch (e) { return resolve({ ok: false, error: e.message }); }
    const { conn, cfg } = made;
    const t = { conn, server: null }; tunnels.set(id, t);
    let settled = false;
    const fail = msg => { if (!settled) { settled = true; resolve({ ok: false, error: msg }); } fwdStatus[id] = { state: 'error', error: msg }; stopTunnelKeepStatus(id); };
    conn.on('ready', () => {
      const server = net.createServer(sock => {
        if (f.type === 'Dynamic') return socks5(sock, conn);
        sock.on('error', () => {});
        conn.forwardOut(sock.remoteAddress || '127.0.0.1', sock.remotePort || 0, f.remoteHost, +f.remotePort, (err, st) => {
          if (err) return sock.destroy();
          st.on('error', () => sock.destroy()); st.on('close', () => sock.destroy());
          sock.pipe(st).pipe(sock);
        });
      });
      server.on('error', e => fail(e.code === 'EADDRINUSE' ? `Port ${f.localPort} is already in use` : e.message));
      server.listen(+f.localPort, '127.0.0.1', () => {
        t.server = server; fwdStatus[id] = { state: 'listening' };
        if (!settled) { settled = true; resolve({ ok: true }); }
      });
    });
    conn.on('error', e => fail(friendlyError(e)));
    conn.on('close', () => { if (tunnels.get(id) === t) fail('Jump host connection closed'); });
    conn.connect(cfg);
  });
}
function stopTunnelKeepStatus(id) {
  const st = fwdStatus[id]; stopTunnel(id); if (st) fwdStatus[id] = st;
}

// ---------- probe ----------
function probe(h) {
  return new Promise(resolve => {
    const t0 = Date.now(); const s = net.connect({ host: h.addr, port: h.port || 22 });
    const done = ok => { s.destroy(); resolve({ online: ok, latency: ok ? Date.now() - t0 : null }); };
    s.setTimeout(2500, () => done(false)); s.on('connect', () => done(true)); s.on('error', () => done(false));
  });
}

// Picks the reachable address for a host: primary first, then the alternate one.
async function pickAddr(h) {
  const cands = [h.addr, ...(h.altAddr && h.altAddr !== h.addr ? [h.altAddr] : [])];
  const rs = await Promise.all(cands.map(a => probe({ addr: a, port: h.port })));
  const i = rs.findIndex(r => r.online);
  return i < 0 ? { addr: h.addr, online: false, latency: null, alt: false } : { addr: cands[i], online: true, latency: rs[i].latency, alt: i > 0 };
}

// ---------- uptime history ----------
// Probes every host once a minute while the server runs and keeps 24 h of results.
const HIST_FILE = path.join(DATA, 'history.json');
const HIST_MS = 24 * 3600 * 1000, BUCKET_MS = 30 * 60 * 1000, BUCKETS = 48;
let hist = {}; // hostId -> [[timestamp, latencyMs | null], ...]
try { hist = JSON.parse(fs.readFileSync(HIST_FILE, 'utf8')); } catch {}
function saveHist() { try { fs.writeFileSync(HIST_FILE + '.tmp', JSON.stringify(hist)); fs.renameSync(HIST_FILE + '.tmp', HIST_FILE); } catch {} }
async function recordProbes() {
  const now = Date.now(); const ids = new Set(state.hosts.map(h => h.id));
  await Promise.all(state.hosts.map(async h => {
    const r = await pickAddr(h);
    (hist[h.id] ||= []).push([now, r.online ? r.latency : null]);
  }));
  for (const id of Object.keys(hist)) {
    if (!ids.has(id)) { delete hist[id]; continue; }
    hist[id] = hist[id].filter(p => now - p[0] < HIST_MS);
  }
}
function summarize() {
  const now = Date.now(); const out = {};
  for (const h of state.hosts) {
    const pts = hist[h.id] || [];
    const buckets = [];
    for (let i = 0; i < BUCKETS; i++) {
      const from = now - (BUCKETS - i) * BUCKET_MS, to = from + BUCKET_MS;
      const inB = pts.filter(p => p[0] >= from && p[0] < to);
      if (!inB.length) { buckets.push({ s: 'none', from }); continue; }
      const down = inB.filter(p => p[1] == null).length;
      const lat = inB.filter(p => p[1] != null).map(p => p[1]);
      buckets.push({ s: down === 0 ? 'up' : down === inB.length ? 'down' : 'warn', from, up: inB.length - down, total: inB.length, avg: lat.length ? Math.round(lat.reduce((a, b) => a + b, 0) / lat.length) : null });
    }
    const up = pts.filter(p => p[1] != null).length;
    out[h.id] = { buckets, n: pts.length, uptime: pts.length ? Math.round(up / pts.length * 1000) / 10 : null };
  }
  return out;
}
recordProbes(); setInterval(recordProbes, 60000); setInterval(saveHist, 5 * 60000);

// ---------- http ----------
const STATIC = {
  '/': ['SSH Client.dc.html', 'text/html; charset=utf-8'],
  '/SSH Client.dc.html': ['SSH Client.dc.html', 'text/html; charset=utf-8'],
  '/support.js': ['support.js', 'text/javascript; charset=utf-8'],
  '/vendor/xterm.js': ['node_modules/@xterm/xterm/lib/xterm.js', 'text/javascript; charset=utf-8'],
  '/vendor/xterm.css': ['node_modules/@xterm/xterm/css/xterm.css', 'text/css; charset=utf-8'],
  '/vendor/addon-fit.js': ['node_modules/@xterm/addon-fit/lib/addon-fit.js', 'text/javascript; charset=utf-8'],
};
const ALLOWED_HOSTS = [`localhost:${PORT}`, `127.0.0.1:${PORT}`];
function originOk(req) {
  if (!ALLOWED_HOSTS.includes(req.headers.host)) return false;       // blocks DNS rebinding
  if (!req.headers.origin) return true;
  try { return new URL(req.headers.origin).host === req.headers.host; } catch { return false; }
}
function body(req) {
  return new Promise((res, rej) => {
    let n = 0; const parts = [];
    req.on('data', c => { n += c.length; if (n > 2e6) { rej(new Error('too large')); req.destroy(); } else parts.push(c); });
    req.on('end', () => { try { res(parts.length ? JSON.parse(Buffer.concat(parts).toString()) : {}); } catch (e) { rej(e); } });
  });
}
const json = (res, code, o) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(o)); };
const publicHosts = () => state.hosts.map(({ pw, ...h }) => ({ ...h, hasPw: !!pw }));

const server = http.createServer(async (req, res) => {
  if (!originOk(req)) return json(res, 403, { error: 'forbidden' });
  const url = new URL(req.url, 'http://x'); const p = decodeURIComponent(url.pathname);
  try {
    if (req.method === 'GET' && STATIC[p]) {
      const [f, type] = STATIC[p];
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-cache' });
      return fs.createReadStream(path.join(ROOT, f)).pipe(res);
    }
    if (!p.startsWith('/api/')) return json(res, 404, { error: 'not found' });
    if (req.method !== 'GET' && !(req.headers['content-type'] || '').startsWith('application/json')) return json(res, 415, { error: 'json only' });

    if (req.method === 'GET' && p === '/api/state') {
      return json(res, 200, { hosts: publicHosts(), forwards: state.forwards, snippets: state.snippets, keys: listKeys(), fwdStatus });
    }
    if (req.method === 'PUT' && p === '/api/state') {
      const b = await body(req);
      if (Array.isArray(b.hosts)) {
        const old = new Map(state.hosts.map(h => [h.id, h]));
        state.hosts = b.hosts.map(h => {
          const o = old.get(h.id);
          const clean = { id: String(h.id), name: String(h.name || h.addr), addr: String(h.addr), port: +h.port || 22, altAddr: String(h.altAddr || '').trim(), user: String(h.user), group: String(h.group || 'Unsorted'), tags: Array.isArray(h.tags) ? h.tags.map(String) : [], auth: ['key', 'password', 'agent'].includes(h.auth) ? h.auth : 'key', key: String(h.key || '') };
          const pw = h.pw || (o && o.pw);
          if (clean.auth === 'password' && pw) clean.pw = pw;
          return clean;
        });
        for (const f of state.forwards) if (!state.hosts.some(h => h.id === f.via)) stopTunnel(f.id);
      }
      if (Array.isArray(b.forwards)) {
        const ids = new Set(b.forwards.map(f => f.id));
        for (const id of [...tunnels.keys()]) if (!ids.has(id)) stopTunnel(id);
        state.forwards = b.forwards.map(f => ({ id: String(f.id), name: String(f.name), type: f.type === 'Dynamic' ? 'Dynamic' : 'Local', localPort: +f.localPort, remoteHost: String(f.remoteHost || ''), remotePort: +f.remotePort || 0, via: String(f.via) }));
      }
      if (Array.isArray(b.snippets)) state.snippets = b.snippets.map(s => ({ name: String(s.name), cmd: String(s.cmd) }));
      saveState();
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/keys/generate') {
      const b = await body(req);
      try { return json(res, 200, generateKey(b.name)); } catch (e) { return json(res, 400, { error: e.message }); }
    }
    let m;
    if (req.method === 'GET' && (m = p.match(/^\/api\/keys\/(.+)\/pub$/))) {
      const f = keyFile(m[1]);
      if (!f) return json(res, 404, { error: 'no such key' });
      let pub;
      try { pub = fs.readFileSync(f + '.pub', 'utf8').trim(); }
      catch {
        const k = utils.parseKey(fs.readFileSync(f));
        if (k instanceof Error) return json(res, 400, { error: 'Cannot derive public key (encrypted private key)' });
        pub = `${k.type} ${k.getPublicSSH().toString('base64')}`;
      }
      return json(res, 200, { pub });
    }
    if (req.method === 'GET' && p === '/api/history') return json(res, 200, summarize());
    if (req.method === 'POST' && p === '/api/probe') {
      const out = {}; await Promise.all(state.hosts.map(async h => { const r = await pickAddr(h); out[h.id] = { online: r.online, latency: r.latency, addr: r.addr, alt: r.alt }; }));
      return json(res, 200, out);
    }
    if (req.method === 'POST' && (m = p.match(/^\/api\/forwards\/([^/]+)\/(start|stop)$/))) {
      if (m[2] === 'stop') { stopTunnel(m[1]); return json(res, 200, { ok: true }); }
      return json(res, 200, await startTunnel(m[1]));
    }
    return json(res, 404, { error: 'not found' });
  } catch (e) { return json(res, 500, { error: e.message }); }
});

const wss = new WebSocketServer({ noServer: true, maxPayload: 128 * 1024 * 1024 });
server.on('upgrade', (req, sock, head) => {
  if (!originOk(req) || !req.headers.origin || new URL(req.url, 'http://x').pathname !== '/ws') { sock.destroy(); return; }
  wss.handleUpgrade(req, sock, head, ws => onSocket(ws));
});

server.listen(PORT, BIND, () => console.log(`Burrow running at http://localhost:${PORT}`));
process.on('SIGINT', () => { saveHist(); for (const id of [...tunnels.keys()]) stopTunnel(id); process.exit(0); });
