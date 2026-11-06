'use strict';
/*
 * Dabba - private phone <-> laptop file drop over your local Wi-Fi.
 * Zero npm dependencies: only Node.js built-in modules are used.
 *
 * Security model
 *  - HTTPS only (self-signed certificate generated on first run, stays on this machine).
 *  - Devices must pair with a one-time code shown on the laptop. Codes expire after
 *    10 minutes, are single-use, and are rotated after 5 wrong guesses.
 *  - Paired devices get a random 256-bit session token in an HttpOnly, Secure,
 *    SameSite=Strict cookie. Only a SHA-256 hash of the token is stored on disk.
 *  - Any paired device can be revoked instantly from the Devices panel.
 *  - Requests from public (internet) IP addresses are refused, even if the port is exposed.
 *  - Strict Content-Security-Policy, CSRF checks, filename sanitising, path-traversal checks.
 */

const https = require('https');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const { execFileSync, execFile } = require('child_process');

const PORT = parseInt(process.env.PORT || '8443', 10);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const SHARED_DIR = path.resolve(process.env.SHARED_DIR || path.join(ROOT, 'SharedFiles'));
const PUBLIC_DIR = path.join(ROOT, 'public');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const PFX_FILE = path.join(DATA_DIR, 'cert.pfx');   // Windows (PowerShell) certificate
const PASS_FILE = path.join(DATA_DIR, 'cert.pass');
const KEY_FILE = path.join(DATA_DIR, 'key.pem');    // macOS / Linux (OpenSSL) certificate
const CERT_FILE = path.join(DATA_DIR, 'cert.pem');
const MAX_UPLOAD_BYTES = parseInt(process.env.MAX_UPLOAD_GB || '20', 10) * 1024 * 1024 * 1024;
const CODE_TTL_MS = 10 * 60 * 1000;
const MAX_CODE_FAILURES = 5;
const COOKIE = 'dabba_session';
const TMP_PREFIX = '.dabba-upload-';

fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
fs.mkdirSync(SHARED_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// Persistent state (paired devices + who uploaded which file)
// ---------------------------------------------------------------------------
let state = { devices: [], origins: {} };
try {
  state = Object.assign(state, JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')));
} catch (_) { /* first run */ }

function saveState() {
  const tmp = STATE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, STATE_FILE);
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------------------------------------------------------------------------
// TLS certificate (self-signed, generated once)
// ---------------------------------------------------------------------------
function lanAddresses() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list || []) {
      if (a.family === 'IPv4' && !a.internal && !a.address.startsWith('169.254.')) out.push(a.address);
    }
  }
  return out;
}

// OpenSSL path, used on macOS and Linux. Works with the LibreSSL that ships with macOS:
// the subjectAltName goes in a config file (old LibreSSL has no -addext), and the result
// stays as plain PEM files (converting to .pfx with LibreSSL gives a file Node.js rejects).
function generateCertOpenSSL(ips) {
  const confFile = path.join(DATA_DIR, `openssl-${crypto.randomBytes(4).toString('hex')}.cnf`);
  const conf = [
    '[req]', 'distinguished_name = dn', 'x509_extensions = v3', 'prompt = no',
    '[dn]', 'CN = Dabba',
    '[v3]',
    'subjectAltName = DNS:localhost,' + ips.map((i) => 'IP:' + i).join(','),
    'basicConstraints = critical,CA:FALSE',
    'keyUsage = critical,digitalSignature,keyEncipherment',
    'extendedKeyUsage = serverAuth',
    '',
  ].join('\n');
  fs.writeFileSync(confFile, conf, { mode: 0o600 });
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '825',
      '-config', confFile, '-keyout', KEY_FILE, '-out', CERT_FILE], { stdio: 'ignore' });
    fs.chmodSync(KEY_FILE, 0o600);
  } catch (e) {
    fs.rmSync(KEY_FILE, { force: true });
    fs.rmSync(CERT_FILE, { force: true });
    throw e;
  } finally {
    fs.rmSync(confFile, { force: true });
  }
}

function generateCert() {
  const ips = ['127.0.0.1', ...lanAddresses()];

  if (process.platform !== 'win32') {
    try {
      generateCertOpenSSL(ips);
      return;
    } catch (_) {
      const hint = process.platform === 'darwin'
        ? 'Install OpenSSL with "brew install openssl" and try again.'
        : 'Install OpenSSL (for example "sudo apt install openssl") and try again.';
      throw new Error('Could not create a TLS certificate with the "openssl" command. ' + hint);
    }
  }

  // Windows: PowerShell (built into Windows 10/11)
  const pass = crypto.randomBytes(24).toString('hex');
  const sanText = '2.5.29.17={text}DNS=localhost&' + ips.map((i) => 'IPAddress=' + i).join('&');
  const script = `
$ErrorActionPreference = 'Stop'
$c = New-SelfSignedCertificate -Subject 'CN=Dabba' -TextExtension @($env:SD_SAN) ` +
    `-CertStoreLocation 'Cert:\\CurrentUser\\My' -KeyAlgorithm RSA -KeyLength 2048 ` +
    `-KeyExportPolicy Exportable -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
$p = ConvertTo-SecureString -String $env:SD_PASS -Force -AsPlainText
try { Export-PfxCertificate -Cert $c -FilePath $env:SD_PFX -Password $p -CryptoAlgorithmOption AES256_SHA256 | Out-Null }
catch { Export-PfxCertificate -Cert $c -FilePath $env:SD_PFX -Password $p | Out-Null }
Remove-Item -Path ('Cert:\\CurrentUser\\My\\' + $c.Thumbprint) -DeleteKey
`;
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded], {
    stdio: 'ignore',
    env: { ...process.env, SD_PASS: pass, SD_PFX: PFX_FILE, SD_SAN: sanText },
  });
  fs.writeFileSync(PASS_FILE, pass, { mode: 0o600 });
}

const havePem = () => fs.existsSync(KEY_FILE) && fs.existsSync(CERT_FILE);
const havePfx = () => fs.existsSync(PFX_FILE) && fs.existsSync(PASS_FILE);
if (!havePem() && !havePfx()) {
  console.log('Creating a private HTTPS certificate (first run only)...');
  generateCert();
}
const tlsOptions = havePem()
  ? { key: fs.readFileSync(KEY_FILE), cert: fs.readFileSync(CERT_FILE), minVersion: 'TLSv1.2' }
  : { pfx: fs.readFileSync(PFX_FILE), passphrase: fs.readFileSync(PASS_FILE, 'utf8').trim(), minVersion: 'TLSv1.2' };

// ---------------------------------------------------------------------------
// Pairing codes
// ---------------------------------------------------------------------------
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // no 0/O/1/I/L
let pairing = null;

function newPairingCode(reason) {
  let code = '';
  for (let i = 0; i < 8; i++) code += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
  pairing = { code, expiresAt: Date.now() + CODE_TTL_MS, failures: 0 };
  console.log(`\n  ${reason ? reason + ' ' : ''}Pairing code: \x1b[1m${code.slice(0, 4)}-${code.slice(4)}\x1b[0m  (valid 10 minutes, single use)\n`);
  return pairing;
}

function currentPairing() {
  if (!pairing || Date.now() > pairing.expiresAt) newPairingCode('Previous code expired.');
  return pairing;
}

function checkPairingCode(input) {
  const p = currentPairing();
  const given = Buffer.from(String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, ''));
  const real = Buffer.from(p.code);
  const ok = given.length === real.length && crypto.timingSafeEqual(given, real);
  if (ok) {
    newPairingCode('Code used.');
    return true;
  }
  p.failures++;
  if (p.failures >= MAX_CODE_FAILURES) newPairingCode('Too many wrong attempts, code rotated.');
  return false;
}

// Simple per-IP rate limit for pairing attempts
const attempts = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const rec = attempts.get(ip) || { count: 0, start: now };
  if (now - rec.start > 60_000) { rec.count = 0; rec.start = now; }
  rec.count++;
  attempts.set(ip, rec);
  return rec.count > 10;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function clientIp(req) {
  let ip = req.socket.remoteAddress || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}

function isLoopback(ip) {
  return ip === '::1' || ip.startsWith('127.');
}

function isPrivateIp(ip) {
  if (isLoopback(ip)) return true;
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  const l = ip.toLowerCase();
  return l.startsWith('fe80:') || l.startsWith('fc') || l.startsWith('fd');
}

function isLocalHostHeader(req) {
  const host = String(req.headers.host || '').toLowerCase();
  return /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(host);
}

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

function authDevice(req) {
  const token = parseCookies(req)[COOKIE];
  if (!token || token.length > 100) return null;
  const h = sha256(token);
  return state.devices.find((d) => d.tokenHash === h) || null;
}

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; " +
    "media-src 'self'; connect-src 'self'; manifest-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
};

function send(res, status, body, headers = {}) {
  const isObj = body !== null && typeof body === 'object' && !Buffer.isBuffer(body);
  const data = isObj ? JSON.stringify(body) : body;
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Cache-Control': 'no-store',
    ...(isObj ? { 'Content-Type': 'application/json; charset=utf-8' } : {}),
    ...headers,
  });
  res.end(data);
}

function readJson(req, limit = 4096) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i;
function sanitizeFileName(name) {
  let n = String(name || '').normalize('NFC');
  n = n.replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, '_');
  n = n.replace(/^[.\s]+/, '').replace(/[.\s]+$/, '');
  if (!n || WINDOWS_RESERVED.test(n)) n = 'file_' + n;
  if (n.length > 180) {
    const ext = path.extname(n).slice(0, 20);
    n = n.slice(0, 180 - ext.length) + ext;
  }
  return n;
}

// Returns the absolute path of a shared file, or null if the name is not a plain file in SHARED_DIR.
async function resolveShared(name) {
  if (typeof name !== 'string' || !name || name !== path.basename(name) || name.startsWith('.') ||
    name.includes('/') || name.includes('\\') || name.includes('\0')) return null;
  const full = path.join(SHARED_DIR, name);
  if (path.dirname(full) !== SHARED_DIR) return null;
  try {
    const st = await fsp.lstat(full);
    return st.isFile() ? { full, st } : null;
  } catch (_) {
    return null;
  }
}

const MIME = {
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp',
  '.avif': 'image/avif', '.bmp': 'image/bmp', '.heic': 'image/heic', '.heif': 'image/heif',
  '.mp4': 'video/mp4', '.m4v': 'video/mp4', '.mov': 'video/quicktime', '.webm': 'video/webm', '.3gp': 'video/3gpp',
  '.mkv': 'video/x-matroska', '.mp3': 'audio/mpeg', '.m4a': 'audio/mp4', '.ogg': 'audio/ogg', '.wav': 'audio/wav',
  '.pdf': 'application/pdf', '.txt': 'text/plain', '.zip': 'application/zip',
};
// Only these types may be shown inline in the browser; everything else is forced to download.
const INLINE_SAFE = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif', 'image/bmp',
  'video/mp4', 'video/quicktime', 'video/webm', 'video/3gpp', 'audio/mpeg', 'audio/mp4', 'audio/ogg', 'audio/wav',
  'application/pdf']);
const mimeOf = (name) => MIME[path.extname(name).toLowerCase()] || 'application/octet-stream';

function contentDisposition(type, name) {
  const ascii = name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  return `${type}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

async function listFiles() {
  const entries = await fsp.readdir(SHARED_DIR, { withFileTypes: true });
  const files = [];
  for (const e of entries) {
    if (!e.isFile() || e.name.startsWith('.')) continue;
    try {
      const st = await fsp.stat(path.join(SHARED_DIR, e.name));
      const type = mimeOf(e.name);
      files.push({
        name: e.name,
        size: st.size,
        modified: st.mtimeMs,
        type,
        previewable: INLINE_SAFE.has(type),
        from: state.origins[e.name] || 'This laptop',
      });
    } catch (_) { /* removed meanwhile */ }
  }
  files.sort((a, b) => b.modified - a.modified);
  return files;
}

// ---------------------------------------------------------------------------
// Live updates (Server-Sent Events)
// ---------------------------------------------------------------------------
const sseClients = new Set();
function broadcast(event) {
  for (const c of sseClients) c.res.write(`event: ${event}\ndata: {}\n\n`);
}
let watchTimer = null;
function filesChanged() {
  clearTimeout(watchTimer);
  watchTimer = setTimeout(() => broadcast('files'), 300);
}
try { fs.watch(SHARED_DIR, filesChanged); } catch (_) { /* polling fallback in client */ }
setInterval(() => { for (const c of sseClients) c.res.write(': ping\n\n'); }, 25_000).unref();

// Clean leftovers from interrupted uploads
for (const f of fs.readdirSync(SHARED_DIR)) {
  if (f.startsWith(TMP_PREFIX)) fs.rmSync(path.join(SHARED_DIR, f), { force: true });
}

// ---------------------------------------------------------------------------
// Static files (served from memory, fixed whitelist)
// ---------------------------------------------------------------------------
const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/icon.svg': ['icon.svg', 'image/svg+xml'],
  '/manifest.webmanifest': ['manifest.webmanifest', 'application/manifest+json'],
};

function serveStatic(res, route) {
  const [file, type] = STATIC[route];
  fs.readFile(path.join(PUBLIC_DIR, file), (err, data) => {
    if (err) return send(res, 404, 'Not found');
    send(res, 200, data, { 'Content-Type': type, 'Cache-Control': 'no-cache' });
  });
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------
async function handleUpload(req, res, device) {
  const rawName = req.headers['x-file-name'];
  if (!rawName) return send(res, 400, { error: 'Missing file name' });
  let name;
  try { name = sanitizeFileName(decodeURIComponent(String(rawName))); } catch (_) { return send(res, 400, { error: 'Bad file name' }); }

  const declared = parseInt(req.headers['content-length'] || '0', 10);
  if (declared > MAX_UPLOAD_BYTES) return send(res, 413, { error: 'File too large' });

  const tmp = path.join(SHARED_DIR, TMP_PREFIX + crypto.randomBytes(8).toString('hex'));
  const out = fs.createWriteStream(tmp, { flags: 'wx' });
  let received = 0;
  let failed = false;
  const fail = (status, msg) => {
    if (failed) return;
    failed = true;
    out.destroy();
    fs.rm(tmp, { force: true }, () => {});
    if (!res.headersSent) send(res, status, { error: msg });
  };

  req.on('data', (chunk) => {
    received += chunk.length;
    if (received > MAX_UPLOAD_BYTES) { fail(413, 'File too large'); req.destroy(); }
  });
  req.on('aborted', () => fail(400, 'Upload aborted'));
  out.on('error', () => fail(500, 'Could not save file'));
  req.pipe(out);

  out.on('finish', async () => {
    if (failed) return;
    if (declared && received !== declared) return fail(400, 'Upload incomplete');
    // Pick a free name ("photo (1).jpg") and move into place without overwriting anything.
    const ext = path.extname(name);
    const base = name.slice(0, name.length - ext.length);
    for (let i = 0; i < 1000; i++) {
      const candidate = i === 0 ? name : `${base} (${i})${ext}`;
      const dest = path.join(SHARED_DIR, candidate);
      try {
        await fsp.link(tmp, dest);
        await fsp.rm(tmp, { force: true });
      } catch (e) {
        if (e.code === 'EEXIST') continue;
        // File systems without hard links (e.g. exFAT): fall back to an exists-check + rename.
        if (fs.existsSync(dest)) continue;
        try { await fsp.rename(tmp, dest); } catch (_) { return fail(500, 'Could not save file'); }
      }
      state.origins[candidate] = device.name;
      saveState();
      filesChanged();
      return send(res, 201, { name: candidate });
    }
    fail(500, 'Could not pick a file name');
  });
}

async function handleFile(req, res, name, url) {
  const found = await resolveShared(name);
  if (!found) return send(res, 404, { error: 'Not found' });
  const { full, st } = found;
  const type = mimeOf(name);
  const inline = url.searchParams.get('dl') !== '1' && INLINE_SAFE.has(type);
  const headers = {
    ...SECURITY_HEADERS,
    'Content-Security-Policy': "default-src 'none'; sandbox",
    'Content-Type': inline ? type : 'application/octet-stream',
    'Content-Disposition': contentDisposition(inline ? 'inline' : 'attachment', name),
    'Accept-Ranges': 'bytes',
    'Cache-Control': 'private, no-cache',
    'Last-Modified': new Date(st.mtimeMs).toUTCString(),
  };
  if (inline && type === 'application/pdf') {
    // Browsers refuse to render PDFs inside a CSP sandbox, and the preview shows them in an
    // <iframe> on our own page. So: no sandbox, but framing is allowed only by this app.
    headers['Content-Security-Policy'] = "frame-ancestors 'self'";
    headers['X-Frame-Options'] = 'SAMEORIGIN';
  }

  let start = 0;
  let end = st.size - 1;
  let status = 200;
  const range = req.headers.range;
  if (range && st.size > 0) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(range);
    if (m && (m[1] || m[2])) {
      if (m[1] === '') { start = Math.max(0, st.size - parseInt(m[2], 10)); }
      else { start = parseInt(m[1], 10); if (m[2] !== '') end = Math.min(parseInt(m[2], 10), st.size - 1); }
      if (start > end || start >= st.size) {
        res.writeHead(416, { ...headers, 'Content-Range': `bytes */${st.size}` });
        return res.end();
      }
      status = 206;
      headers['Content-Range'] = `bytes ${start}-${end}/${st.size}`;
    }
  }
  headers['Content-Length'] = st.size === 0 ? 0 : end - start + 1;
  res.writeHead(status, headers);
  if (req.method === 'HEAD' || st.size === 0) return res.end();
  const stream = fs.createReadStream(full, { start, end });
  stream.on('error', () => res.destroy());
  stream.pipe(res);
}

function publicDevice(d, me) {
  return { id: d.id, name: d.name, createdAt: d.createdAt, lastSeen: d.lastSeen, isYou: d.id === me.id };
}

async function handle(req, res) {
  const ip = clientIp(req);
  if (!isPrivateIp(ip)) { req.socket.destroy(); return; }

  const url = new URL(req.url, 'https://local');
  const p = url.pathname;
  const method = req.method;

  // CSRF protection for anything that changes data
  if (!['GET', 'HEAD'].includes(method)) {
    const origin = req.headers.origin;
    if (req.headers['x-dabba'] !== '1') return send(res, 403, { error: 'Forbidden' });
    if (origin && origin !== `https://${req.headers.host}`) return send(res, 403, { error: 'Bad origin' });
  }

  if ((method === 'GET' || method === 'HEAD') && STATIC[p]) return serveStatic(res, p);

  // ---- Unauthenticated endpoints ----
  if (method === 'GET' && p === '/api/me') {
    const d = authDevice(req);
    return send(res, 200, d ? { paired: true, name: d.name, id: d.id, local: isLoopback(ip) } : { paired: false, local: isLoopback(ip) && isLocalHostHeader(req) });
  }

  // The laptop itself (opened via https://localhost) can read the current code so it can pair in one click.
  if (method === 'GET' && p === '/api/local-code') {
    if (!isLoopback(ip) || !isLocalHostHeader(req)) return send(res, 403, { error: 'Forbidden' });
    return send(res, 200, { code: currentPairing().code });
  }

  if (method === 'POST' && p === '/api/pair') {
    if (rateLimited(ip)) return send(res, 429, { error: 'Too many attempts. Wait a minute.' });
    let body;
    try { body = await readJson(req); } catch (_) { return send(res, 400, { error: 'Bad request' }); }
    if (!checkPairingCode(body.code)) return send(res, 401, { error: 'Wrong or expired code' });
    const name = String(body.name || 'Device').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 40) || 'Device';
    const token = crypto.randomBytes(32).toString('base64url');
    const device = { id: crypto.randomUUID(), name, tokenHash: sha256(token), createdAt: Date.now(), lastSeen: Date.now() };
    state.devices.push(device);
    saveState();
    console.log(`  Paired new device: ${name} (${ip})`);
    broadcast('devices');
    return send(res, 200, { ok: true, name }, {
      'Set-Cookie': `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=31536000`,
    });
  }

  if (!p.startsWith('/api/')) return send(res, 404, 'Not found');

  // ---- Everything below requires a paired device ----
  const device = authDevice(req);
  if (!device) return send(res, 401, { error: 'Not paired' });
  if (Date.now() - device.lastSeen > 60_000) { device.lastSeen = Date.now(); saveState(); }

  if (method === 'GET' && p === '/api/events') {
    res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' });
    res.write('retry: 3000\n\n');
    const client = { res, deviceId: device.id };
    sseClients.add(client);
    req.on('close', () => sseClients.delete(client));
    return;
  }

  if (method === 'GET' && p === '/api/files') return send(res, 200, { files: await listFiles() });

  if (method === 'PUT' && p === '/api/upload') return handleUpload(req, res, device);

  const fileMatch = /^\/api\/files\/([^/]+)$/.exec(p);
  if (fileMatch) {
    let name;
    try { name = decodeURIComponent(fileMatch[1]); } catch (_) { return send(res, 400, { error: 'Bad name' }); }
    if (method === 'GET' || method === 'HEAD') return handleFile(req, res, name, url);
    if (method === 'DELETE') {
      const found = await resolveShared(name);
      if (!found) return send(res, 404, { error: 'Not found' });
      await fsp.rm(found.full, { force: true });
      delete state.origins[name];
      saveState();
      filesChanged();
      return send(res, 200, { ok: true });
    }
  }

  if (method === 'GET' && p === '/api/devices') {
    return send(res, 200, { devices: state.devices.map((d) => publicDevice(d, device)) });
  }

  const devMatch = /^\/api\/devices\/([0-9a-f-]{36})$/.exec(p);
  if (method === 'DELETE' && devMatch) {
    const idx = state.devices.findIndex((d) => d.id === devMatch[1]);
    if (idx === -1) return send(res, 404, { error: 'Not found' });
    const [removed] = state.devices.splice(idx, 1);
    saveState();
    for (const c of sseClients) if (c.deviceId === removed.id) { c.res.end(); sseClients.delete(c); }
    console.log(`  Revoked device: ${removed.name}`);
    broadcast('devices');
    return send(res, 200, { ok: true });
  }

  if (method === 'POST' && p === '/api/pair/new') {
    const pr = newPairingCode('New code requested.');
    return send(res, 200, { code: pr.code, expiresAt: pr.expiresAt, urls: lanAddresses().map((a) => `https://${a}:${PORT}`) });
  }

  if (method === 'POST' && p === '/api/open-folder') {
    if (!isLoopback(ip)) return send(res, 403, { error: 'Only available on the laptop' });
    const cmd = process.platform === 'win32' ? 'explorer.exe' : process.platform === 'darwin' ? 'open' : 'xdg-open';
    execFile(cmd, [SHARED_DIR], () => {});
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: 'Not found' });
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
const server = https.createServer(tlsOptions, (req, res) => {
  handle(req, res).catch((err) => {
    console.error(err);
    if (!res.headersSent) send(res, 500, { error: 'Server error' });
    else res.destroy();
  });
});
server.requestTimeout = 0; // large video uploads can take a while
server.headersTimeout = 30_000;

server.listen(PORT, '0.0.0.0', () => {
  // Read our own certificate fingerprint so it can be checked on the phone if wanted.
  const s = tls.connect({ host: '127.0.0.1', port: PORT, rejectUnauthorized: false }, () => {
    const fp = s.getPeerCertificate().fingerprint256;
    s.end();
    console.log('\n  Dabba is running.\n');
    console.log(`  On this laptop:  https://localhost:${PORT}`);
    for (const a of lanAddresses()) console.log(`  On your phone:   https://${a}:${PORT}`);
    console.log(`\n  Shared folder:   ${SHARED_DIR}`);
    console.log(`  Cert SHA-256:    ${fp}`);
    console.log('\n  Your browser will warn about the certificate the first time. That is expected:');
    console.log('  the certificate was created on this laptop, not bought from a public authority.');
    newPairingCode();
    if (!process.env.NO_OPEN) {
      const url = `https://localhost:${PORT}`;
      if (process.platform === 'win32') execFile('cmd.exe', ['/c', 'start', '', url], () => {});
      else if (process.platform === 'darwin') execFile('open', [url], () => {});
    }
  });
  s.on('error', () => {});
});

setInterval(() => { if (pairing && Date.now() > pairing.expiresAt) newPairingCode('Previous code expired.'); }, 30_000).unref();
