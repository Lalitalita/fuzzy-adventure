// Faux OPNsense pour tester le dashboard sans firewall (MOCK=1).
const rnd = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pick = (arr) => arr[rnd(0, arr.length - 1)];
const ip = () => `${pick([45, 80, 103, 141, 185, 193, 5, 89])}.${rnd(1, 254)}.${rnd(1, 254)}.${rnd(1, 254)}`;

const NOISE = Array.from({ length: 40 }, ip);
const TRYHARD = ip();
const SCANNER = ip();
const BRUTE = ip();

export class MockClient {
  async getFirewallLog() {
    const rows = [];
    const now = Date.now();
    const mk = (src, dport, extra = {}) => rows.push({
      __timestamp__: new Date(now - rnd(0, 4000)).toISOString(),
      action: 'block', interface: 'wan', dir: 'in', protoname: 'tcp',
      src, srcport: String(rnd(1024, 65535)), dst: `192.168.10.${rnd(2, 40)}`, dstport: String(dport), ...extra,
    });
    for (let i = 0; i < rnd(2, 8); i++) mk(pick(NOISE), pick([22, 23, 80, 443, 3389, 5060, 8080, 37215]));
    if (Math.random() < 0.7) for (let i = 0; i < rnd(10, 30); i++) mk(TRYHARD, rnd(1, 10000));
    if (Math.random() < 0.5) for (let i = 0; i < rnd(3, 10); i++) mk(SCANNER, pick([80, 443, 8080, 8443]), { dst: `192.168.10.${rnd(2, 200)}` });
    if (Math.random() < 0.6) for (let i = 0; i < rnd(2, 6); i++) mk(BRUTE, 22);
    return rows;
  }
  async getIdsAlerts() {
    return Math.random() < 0.5 ? [{
      timestamp: new Date().toISOString(), src_ip: TRYHARD, dest_ip: '192.168.10.5', dest_port: 22,
      alert: 'ET SCAN Potential SSH Scan', alert_category: 'Attempted Information Leak', alert_severity: 2, alert_action: 'blocked',
    }] : [];
  }
  async getSystem() {
    return {
      resources: { cpu: { used: rnd(3, 40) }, memory: { total: 8e9, used: rnd(2e9, 5e9) } },
      traffic: { interfaces: { wan: { 'bytes received': rnd(1e9, 2e9), 'bytes transmitted': rnd(1e8, 5e8), name: 'wan' } } },
    };
  }
  async getFirmwareStatus() {
    return { product_version: '25.1.5 (mock)', needs_reboot: '0', status: 'update', status_msg: '2 mises à jour disponibles', upgrade_packages: [{ name: 'openssl' }, { name: 'curl' }], last_check: new Date().toString() };
  }
  async runAudit() {
    return `openssl-3.0.13 is vulnerable:\n  OpenSSL -- Denial of service via crafted certificate\n  CVE: CVE-2024-0727\n  WWW: https://vuxml.freebsd.org/freebsd/mock1.html\n\ncurl-8.5.0 is vulnerable:\n  curl -- HSTS bypass\n  CVE: CVE-2024-2004\n  WWW: https://vuxml.freebsd.org/freebsd/mock2.html\n\n2 problem(s) in 2 installed package(s) found.`;
  }
}
