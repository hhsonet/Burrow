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

// ---------- ws sessions ----------
function onSocket(ws) {
  let conn = null, stream = null, sftp = null, ending = false;
  const send = o => ws.readyState === 1 && ws.send(JSON.stringify(o));
  const log = (text, kind = 'dim') => send({ type: 'log', text, kind });
  const status = (s, message) => send({ type: 'status', status: s, message });

  function getSftp(cb) {
    if (sftp) return cb(null, sftp);
    if (!conn) return cb(new Error('Not connected'));
    conn.sftp((err, s) => { if (err) return cb(err); sftp = s; s.on('close', () => { sftp = null; }); cb(null, s); });
  }
  function end() { ending = true; try { stream && stream.end(); } catch {} try { conn && conn.end(); } catch {} }

  function connect(m) {
    const h = state.hosts.find(x => x.id === m.hostId);
    if (!h) return status('failed', 'Unknown host');
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
function startTunnel(id) {
  return new Promise(resolve => {
    stopTunnel(id);
    const f = state.forwards.find(x => x.id === id);
    const h = f && state.hosts.find(x => x.id === f.via);
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
          const clean = { id: String(h.id), name: String(h.name || h.addr), addr: String(h.addr), port: +h.port || 22, user: String(h.user), group: String(h.group || 'Unsorted'), tags: Array.isArray(h.tags) ? h.tags.map(String) : [], auth: ['key', 'password', 'agent'].includes(h.auth) ? h.auth : 'key', key: String(h.key || '') };
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
    if (req.method === 'POST' && p === '/api/probe') {
      const out = {}; await Promise.all(state.hosts.map(async h => { out[h.id] = await probe(h); }));
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
process.on('SIGINT', () => { for (const id of [...tunnels.keys()]) stopTunnel(id); process.exit(0); });
