import https from 'node:https';
import http from 'node:http';

export class OpnsenseClient {
  constructor({ url, key, secret, verifyTls }) {
    this.base = new URL(url);
    this.auth = 'Basic ' + Buffer.from(`${key}:${secret}`).toString('base64');
    this.agent = this.base.protocol === 'https:'
      ? new https.Agent({ rejectUnauthorized: verifyTls, keepAlive: true })
      : undefined;
  }

  request(method, path, body) {
    const lib = this.base.protocol === 'https:' ? https : http;
    const payload = body === undefined ? undefined : JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = lib.request(
        new URL(path, this.base),
        {
          method,
          agent: this.agent,
          timeout: 15000,
          headers: {
            Authorization: this.auth,
            Accept: 'application/json',
            ...(payload && { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }),
          },
        },
        (res) => {
          let data = '';
          res.on('data', (c) => (data += c));
          res.on('end', () => {
            if (res.statusCode >= 400) return reject(new Error(`OPNsense ${method} ${path} -> HTTP ${res.statusCode}`));
            try { resolve(JSON.parse(data)); } catch { reject(new Error(`Réponse non-JSON sur ${path}`)); }
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error(`Timeout sur ${path}`)));
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  get(path) { return this.request('GET', path); }
  post(path, body = {}) { return this.request('POST', path, body); }

  async getFirewallLog(limit) {
    const rows = await this.get(`/api/diagnostics/firewall/log?limit=${limit}`);
    return Array.isArray(rows) ? rows : [];
  }

  async getIdsAlerts(rowCount = 200) {
    const r = await this.post('/api/ids/service/queryAlerts', { current: 1, rowCount, searchPhrase: '' });
    return r.rows || [];
  }

  async getSystem() {
    const [res, traffic] = await Promise.allSettled([
      this.get('/api/diagnostics/system/systemResources'),
      this.get('/api/diagnostics/traffic/interface'),
    ]);
    return {
      resources: res.status === 'fulfilled' ? res.value : null,
      traffic: traffic.status === 'fulfilled' ? traffic.value : null,
    };
  }

  getFirmwareStatus() { return this.get('/api/core/firmware/status'); }

  /** Lance `pkg audit` et attend la fin (max ~2 min). Retourne le texte brut. */
  async runAudit() {
    await this.post('/api/core/firmware/audit');
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      const s = await this.get('/api/core/firmware/upgradestatus');
      if (s.status && s.status !== 'running') return s.log || '';
    }
    throw new Error('Audit trop long');
  }
}
