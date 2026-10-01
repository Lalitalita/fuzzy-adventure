import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { OpnsenseClient } from './opnsense.js';
import { MockClient } from './mock.js';
import { Store, buildSnapshot, parseAudit } from './analyzer.js';

const env = process.env;
const csv = (v) => (v || '').split(',').map((s) => s.trim()).filter(Boolean);
const MOCK = env.MOCK === '1';
const PORT = Number(env.PORT) || 3000;
const HOST = env.HOST || '127.0.0.1';
const POLL = Math.max(2000, Number(env.POLL_INTERVAL_MS) || 5000);
const LIMIT = Number(env.FW_LOG_LIMIT) || 2000;
const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

if (!MOCK && (!env.OPN_URL || !env.OPN_API_KEY || !env.OPN_API_SECRET)) {
  console.error('OPN_URL / OPN_API_KEY / OPN_API_SECRET manquants dans .env (ou lance avec MOCK=1)');
  process.exit(1);
}

const opn = MOCK
  ? new MockClient()
  : new OpnsenseClient({ url: env.OPN_URL, key: env.OPN_API_KEY, secret: env.OPN_API_SECRET, verifyTls: env.OPN_VERIFY_TLS !== 'false' });

const store = new Store({ wan: csv(env.WAN_INTERFACES), ignore: csv(env.IGNORE_SRC) });
const state = {
  status: { ok: false, error: 'démarrage…', lastPoll: 0 },
  system: null,
  firmware: null,
  vulns: { running: false, lastRun: 0, error: null, items: [] },
};

async function pollFirewall() {
  try {
    store.ingest(await opn.getFirewallLog(LIMIT));
    state.status = { ok: true, error: null, lastPoll: Date.now() };
  } catch (e) {
    state.status = { ok: false, error: e.message, lastPoll: Date.now() };
  }
  broadcast();
}

async function pollSlow() {
  const [ids, sys, fw] = await Promise.allSettled([opn.getIdsAlerts(), opn.getSystem(), opn.getFirmwareStatus()]);
  if (ids.status === 'fulfilled') store.setIds(ids.value); // Suricata non installé => 404, on ignore
  if (sys.status === 'fulfilled') state.system = sys.value;
  if (fw.status === 'fulfilled') state.firmware = fw.value;
}

async function runAudit() {
  if (state.vulns.running) return;
  state.vulns.running = true; state.vulns.error = null; broadcast();
  try {
    state.vulns.items = parseAudit(await opn.runAudit());
    state.vulns.lastRun = Date.now();
  } catch (e) {
    state.vulns.error = e.message;
  } finally {
    state.vulns.running = false; broadcast();
  }
}

const snapshot = () => buildSnapshot(store, { mock: MOCK, status: state.status, system: state.system, firmware: state.firmware, vulns: state.vulns });

const clients = new Set();
function broadcast() {
  if (!clients.size) return;
  const data = `data: ${JSON.stringify(snapshot())}\n\n`;
  for (const res of clients) res.write(data);
}

// --- HTTP ---
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };

function authorized(req) {
  if (!env.DASH_USER || !env.DASH_PASS) return true;
  const h = req.headers.authorization || '';
  const [u, ...p] = Buffer.from(h.replace(/^Basic /, ''), 'base64').toString().split(':');
  const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  return eq(u || '', env.DASH_USER) && eq(p.join(':'), env.DASH_PASS);
}

http.createServer((req, res) => {
  if (!authorized(req)) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="SOC"' }).end('Auth requise');
    return;
  }
  const url = new URL(req.url, 'http://x');

  if (url.pathname === '/api/stream') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.write(`data: ${JSON.stringify(snapshot())}\n\n`);
    clients.add(res);
    req.on('close', () => clients.delete(res));
    return;
  }
  if (url.pathname === '/api/snapshot') {
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify(snapshot()));
    return;
  }
  if (url.pathname === '/api/audit' && req.method === 'POST') {
    runAudit();
    res.writeHead(202).end();
    return;
  }

  const file = path.normalize(path.join(PUBLIC, url.pathname === '/' ? 'index.html' : url.pathname));
  if (!file.startsWith(PUBLIC) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    res.writeHead(404).end('Not found');
    return;
  }
  res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
}).listen(PORT, HOST, () => console.log(`SOC dashboard → http://${HOST}:${PORT}  ${MOCK ? '[MOCK]' : '[' + env.OPN_URL + ']'}`));

await pollSlow();
await pollFirewall();
setInterval(pollFirewall, POLL);
setInterval(() => pollSlow().then(broadcast), 30000);
setInterval(runAudit, 6 * 3600e3);
runAudit();
