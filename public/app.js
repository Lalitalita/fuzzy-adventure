const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const time = (t) => new Date(t).toLocaleTimeString('fr-FR');
const ago = (t) => { const s = Math.round((Date.now() - t) / 1000); return s < 60 ? `${s}s` : s < 3600 ? `${Math.round(s / 60)}min` : `${Math.round(s / 3600)}h`; };
const LABEL = { tryhard: 'TRYHARD', suspect: 'SUSPECT', bruit: 'BRUIT' };
const COLOR = { tryhard: 'var(--red)', suspect: 'var(--org)', bruit: 'var(--mut)' };
const open = new Set();
let last, auditStarted = false;

function render(d) {
  last = d;
  $('#conn').textContent = d.status.ok ? 'OPNsense OK' : 'Erreur API';
  $('#conn').className = 'pill ' + (d.status.ok ? 'ok' : 'ko');
  $('#meta').textContent = [d.mock && 'MODE DÉMO', d.status.error, d.firmware?.product_version && `v${d.firmware.product_version}`].filter(Boolean).join(' · ');

  const k = d.kpi;
  const tiles = [['Blocages 5 min', k.blocked5m], ['Blocages 1 h', k.blocked1h], ['Blocages 24 h', k.blocked24h], ['IP uniques (1h)', k.uniqueIps1h],
    ['Tryhard', k.tryhard, 'var(--red)'], ['Suspects', k.suspect, 'var(--org)'], ['Alertes IDS (1h)', k.idsAlerts1h]];
  $('#kpis').innerHTML = tiles.map(([l, v, c]) => `<div class="kpi"><b style="color:${c || 'inherit'}">${v}</b><span>${l}</span></div>`).join('');

  // timeline
  const max = Math.max(1, ...d.timeline.map((p) => p.count)), w = 600 / d.timeline.length;
  $('#timeline').innerHTML = d.timeline.map((p, i) => {
    const h = (p.count / max) * 105;
    return `<rect x="${i * w + 1}" y="${115 - h}" width="${w - 2}" height="${h}" fill="var(--blu)" opacity=".85"><title>${time(p.t)} : ${p.count}</title></rect>`;
  }).join('') + `<text x="2" y="10" fill="#8b949e" font-size="9">max ${max}/min</text>`;

  const pm = Math.max(1, ...d.topPorts.map((p) => p.count));
  $('#ports').innerHTML = d.topPorts.map((p) => `<div class="row"><span class="mono">${p.port}${p.name ? ' · ' + p.name : ''}</span><span style="flex:1;align-self:center"><div class="bar"><i style="width:${p.count / pm * 100}%;background:var(--blu)"></i></div></span><b>${p.count}</b></div>`).join('');

  $('#sources tbody').innerHTML = d.sources.map((s) => {
    const rows = `<tr class="src" data-ip="${esc(s.ip)}"><td class="mono">${esc(s.ip)}</td><td><span class="badge ${s.level}">${LABEL[s.level]}</span></td>
      <td><div class="bar"><i style="width:${s.score}%;background:${COLOR[s.level]}"></i></div>${s.score}</td><td>${s.count}</td><td>${s.ports}</td><td>${s.targets}</td>
      <td class="mono">${s.topPorts.map((p) => p.port + (p.name ? '/' + p.name : '') + '×' + p.count).join(' ')}</td><td>${ago(s.last)}</td></tr>`;
    return rows + (open.has(s.ip) ? `<tr class="detail"><td colspan="8">${s.why.map((w) => '• ' + esc(w)).join('<br>')}<br><a href="https://www.abuseipdb.com/check/${encodeURIComponent(s.ip)}" target="_blank" rel="noopener" style="color:var(--blu)">AbuseIPDB ↗</a></td></tr>` : '');
  }).join('') || '<tr><td colspan="8" class="muted">Aucun blocage récent</td></tr>';

  $('#recent tbody').innerHTML = d.recent.map((e) => `<tr><td>${time(e.ts)}</td><td class="mono">${esc(e.src)}</td><td class="mono">${esc(e.dst)}:${e.dport}</td><td>${esc(e.proto)}</td></tr>`).join('');
  $('#ids tbody').innerHTML = d.ids.map((a) => `<tr><td>${time(a.ts)}</td><td class="mono">${esc(a.src)}</td><td>${esc(a.sig)}</td><td>${a.severity}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">Aucune alerte (Suricata activé ?)</td></tr>';

  const f = d.firmware, v = d.vulns;
  $('#fw').textContent = f ? `${f.status_msg || ''}${f.needs_reboot === '1' ? ' · ⚠ redémarrage requis' : ''}${f.upgrade_packages?.length ? ` · ${f.upgrade_packages.length} paquet(s) à mettre à jour` : ''}` : '';
  $('#audit').disabled = v.running;
  $('#audit').textContent = v.running ? 'Audit en cours…' : "Lancer l'audit";
  $('#vulns').innerHTML = (v.error ? `<div class="muted">Erreur : ${esc(v.error)}</div>` : '') +
    (v.lastRun && !v.items.length ? '<div class="muted">✅ Aucune vulnérabilité connue dans les paquets installés.</div>' : '') +
    v.items.map((i) => `<div class="vuln"><b>${esc(i.pkg)}</b> ${i.cves.map((c) => `<span class="badge suspect">${esc(c)}</span>`).join(' ')}<br><span class="muted">${esc(i.issues.join(' — '))}</span>
      ${i.links.map((l) => /^https?:\/\//.test(l) ? `<br><a href="${esc(l)}" target="_blank" rel="noopener">${esc(l)}</a>` : '').join('')}</div>`).join('') +
    (v.lastRun ? `<div class="muted" style="margin-top:6px">Dernier audit : ${time(v.lastRun)}</div>` : '');
}

$('#sources').addEventListener('click', (e) => {
  const tr = e.target.closest('tr.src'); if (!tr) return;
  open.has(tr.dataset.ip) ? open.delete(tr.dataset.ip) : open.add(tr.dataset.ip);
  render(last);
});
$('#audit').addEventListener('click', () => fetch('/api/audit', { method: 'POST' }));

const es = new EventSource('/api/stream');
es.onmessage = (m) => render(JSON.parse(m.data));
es.onerror = () => { $('#conn').textContent = 'déconnecté'; $('#conn').className = 'pill ko'; };
