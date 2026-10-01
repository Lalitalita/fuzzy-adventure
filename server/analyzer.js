// Normalisation des logs + scoring "tryhard" par IP source.

const SENSITIVE_PORTS = new Map([
  [21, 'FTP'], [22, 'SSH'], [23, 'Telnet'], [25, 'SMTP'], [135, 'RPC'], [139, 'NetBIOS'], [445, 'SMB'],
  [1433, 'MSSQL'], [1521, 'Oracle'], [3306, 'MySQL'], [3389, 'RDP'], [5432, 'PostgreSQL'],
  [5900, 'VNC'], [6379, 'Redis'], [8080, 'HTTP-alt'], [9200, 'Elasticsearch'], [27017, 'MongoDB'],
]);

export function portName(p) { return SENSITIVE_PORTS.get(Number(p)) || null; }

export function normalize(row) {
  const ts = Date.parse(row.__timestamp__ || row.timestamp || '');
  if (!ts || !row.src) return null;
  return {
    ts,
    action: row.action,
    iface: row.interface || row.ifname || '',
    dir: row.dir,
    proto: (row.protoname || row.proto || '').toLowerCase(),
    src: row.src,
    sport: Number(row.srcport) || 0,
    dst: row.dst,
    dport: Number(row.dstport) || 0,
    label: row.label || '',
  };
}

const evKey = (e) => `${e.ts}|${e.src}|${e.sport}|${e.dst}|${e.dport}|${e.proto}`;

export function isPrivate(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|f[cd][0-9a-f]{2}:|fe80:|::1$)/i.test(ip);
}

export class Store {
  constructor({ retentionMs = 24 * 3600e3, max = 100000, wan = [], ignore = [] } = {}) {
    this.events = [];
    this.seen = new Set();
    this.retentionMs = retentionMs;
    this.max = max;
    this.wan = wan;
    this.ignore = ignore;
    this.ids = [];
  }

  /** Ajoute les nouveaux blocages, retourne le nombre d'ajouts. */
  ingest(rows) {
    let added = 0;
    for (const row of rows) {
      const e = normalize(row);
      if (!e || e.action !== 'block') continue;
      if (this.wan.length && !this.wan.includes(e.iface)) continue;
      if (this.ignore.some((p) => e.src === p || e.src.startsWith(p))) continue;
      const k = evKey(e);
      if (this.seen.has(k)) continue;
      this.seen.add(k);
      this.events.push(e);
      added++;
    }
    if (added) {
      this.events.sort((a, b) => a.ts - b.ts);
      this.prune();
    }
    return added;
  }

  prune() {
    const cut = Date.now() - this.retentionMs;
    let i = 0;
    while (i < this.events.length && this.events[i].ts < cut) i++;
    if (i) for (const e of this.events.splice(0, i)) this.seen.delete(evKey(e));
    while (this.events.length > this.max) this.seen.delete(evKey(this.events.shift()));
  }

  setIds(rows) {
    this.ids = rows.map((r) => ({
      ts: Date.parse(r.timestamp) || Date.now(),
      src: r.src_ip,
      dst: r.dest_ip,
      dport: Number(r.dest_port) || 0,
      sig: r.alert || r.alert_signature || '',
      category: r.alert_category || '',
      severity: Number(r.alert_severity) || 3,
      action: r.alert_action || r.action || '',
    })).filter((a) => a.src);
  }

  since(ms) {
    const cut = Date.now() - ms;
    let lo = 0, hi = this.events.length;
    while (lo < hi) { const m = (lo + hi) >> 1; if (this.events[m].ts < cut) lo = m + 1; else hi = m; }
    return this.events.slice(lo);
  }
}

/** Score 0-100 + raisons explicites pour une IP. */
export function scoreSource(s) {
  let score = 0;
  const why = [];
  const nPorts = s.ports.size, nDst = s.dsts.size;

  if (nPorts >= 100) { score += 45; why.push(`Scan de ports massif (${nPorts} ports distincts)`); }
  else if (nPorts >= 15) { score += 35; why.push(`Scan de ports (${nPorts} ports distincts)`); }
  else if (nPorts >= 5) { score += 15; why.push(`Sonde plusieurs ports (${nPorts})`); }

  if (nDst >= 10) { score += 20; why.push(`Balayage de ${nDst} hôtes internes`); }
  else if (nDst >= 3) { score += 8; why.push(`Touche ${nDst} hôtes`); }

  const sens = [...s.ports].filter((p) => SENSITIVE_PORTS.has(p));
  if (sens.length) {
    score += Math.min(30, sens.length * 10);
    why.push('Services sensibles ciblés : ' + sens.slice(0, 6).map((p) => `${p}/${SENSITIVE_PORTS.get(p)}`).join(', '));
  }

  if (s.count >= 200) { score += 20; why.push(`Volume élevé (${s.count} blocages)`); }
  else if (s.count >= 50) { score += 10; why.push(`Volume notable (${s.count} blocages)`); }

  const spanMin = (s.last - s.first) / 60000;
  if (spanMin >= 10 && s.count >= 20) { score += 10; why.push(`Persistant (${Math.round(spanMin)} min d'activité)`); }

  // Rafale : beaucoup d'événements en peu de temps => outil automatisé agressif
  if (s.count >= 30 && spanMin > 0 && s.count / spanMin >= 30) { score += 10; why.push(`Rafale (~${Math.round(s.count / spanMin)}/min)`); }

  if (s.ids.length) {
    const worst = Math.min(...s.ids.map((a) => a.severity));
    score += worst === 1 ? 35 : worst === 2 ? 25 : 15;
    why.push(`${s.ids.length} alerte(s) IDS : ${s.ids[0].sig}`);
  }

  score = Math.min(100, score);
  // Un seul port, quelques paquets = bruit internet classique
  if (!why.length) why.push('Bruit de fond internet (hit isolé)');
  const level = score >= 55 ? 'tryhard' : score >= 25 ? 'suspect' : 'bruit';
  return { score, level, why };
}

export function buildSnapshot(store, extra) {
  const now = Date.now();
  const hour = store.since(3600e3);
  const fiveMin = store.since(300e3);
  const day = store.events;

  // Agrégation par IP sur 1h
  const bySrc = new Map();
  for (const e of hour) {
    let s = bySrc.get(e.src);
    if (!s) bySrc.set(e.src, (s = { ip: e.src, count: 0, ports: new Set(), dsts: new Set(), first: e.ts, last: e.ts, ids: [], protos: new Set() }));
    s.count++; s.ports.add(e.dport); s.dsts.add(e.dst); s.protos.add(e.proto);
    if (e.ts > s.last) s.last = e.ts;
  }
  for (const a of store.ids) { const s = bySrc.get(a.src); if (s && now - a.ts < 3600e3) s.ids.push(a); }

  const sources = [...bySrc.values()].map((s) => {
    const r = scoreSource(s);
    const portCounts = {};
    for (const e of hour) if (e.src === s.ip) portCounts[e.dport] = (portCounts[e.dport] || 0) + 1;
    const topPorts = Object.entries(portCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([p, c]) => ({ port: +p, count: c, name: portName(p) }));
    return { ip: s.ip, count: s.count, ports: s.ports.size, targets: s.dsts.size, first: s.first, last: s.last, topPorts, protos: [...s.protos], ...r };
  }).sort((a, b) => b.score - a.score || b.count - a.count);

  // Timeline par minute sur 60 min
  const timeline = Array.from({ length: 60 }, (_, i) => ({ t: Math.floor(now / 60000) * 60000 - (59 - i) * 60000, count: 0 }));
  const t0 = timeline[0].t;
  for (const e of hour) { const i = Math.floor((e.ts - t0) / 60000); if (i >= 0 && i < 60) timeline[i].count++; }

  const tally = (arr, fn, n = 8) => {
    const m = new Map();
    for (const e of arr) { const k = fn(e); m.set(k, (m.get(k) || 0) + 1); }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  };
  const topPorts = tally(day, (e) => e.dport).map(([p, c]) => ({ port: +p, count: c, name: portName(p) }));
  const topProtos = tally(hour, (e) => e.proto || '?', 5).map(([name, count]) => ({ name, count }));

  return {
    now,
    kpi: {
      blocked5m: fiveMin.length,
      blocked1h: hour.length,
      blocked24h: day.length,
      uniqueIps1h: bySrc.size,
      tryhard: sources.filter((s) => s.level === 'tryhard').length,
      suspect: sources.filter((s) => s.level === 'suspect').length,
      idsAlerts1h: store.ids.filter((a) => now - a.ts < 3600e3).length,
    },
    timeline,
    sources: sources.slice(0, 50),
    topPorts,
    topProtos,
    recent: store.events.slice(-60).reverse(),
    ids: store.ids.slice(0, 30),
    ...extra,
  };
}

/** Parse la sortie texte de `pkg audit`. */
export function parseAudit(text) {
  const out = [];
  let cur = null;
  for (const raw of String(text).split('\n')) {
    const line = raw.trim();
    const m = line.match(/^(\S+) is vulnerable:?$/);
    if (m) { cur = { pkg: m[1], issues: [], cves: [], links: [] }; out.push(cur); continue; }
    if (!cur || !line) continue;
    if (/^CVE:/i.test(line)) cur.cves.push(line.replace(/^CVE:\s*/i, ''));
    else if (/^WWW:/i.test(line)) cur.links.push(line.replace(/^WWW:\s*/i, ''));
    else if (!/^\d+ problem/.test(line)) cur.issues.push(line);
  }
  return out;
}
