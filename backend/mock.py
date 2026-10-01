"""Faux OPNsense pour tester le dashboard sans firewall (MOCK=1)."""
import random
from datetime import datetime, timedelta, timezone

rnd = random.randint


def _ip() -> str:
    return f"{random.choice([45, 80, 103, 141, 185, 193, 5, 89])}.{rnd(1, 254)}.{rnd(1, 254)}.{rnd(1, 254)}"


NOISE = [_ip() for _ in range(40)]
TRYHARD, SCANNER, BRUTE = _ip(), _ip(), _ip()


class MockClient:
    async def get_firewall_log(self, limit: int = 0):
        rows, now = [], datetime.now(timezone.utc)

        def mk(src, dport, **extra):
            rows.append({
                "__timestamp__": (now - timedelta(milliseconds=rnd(0, 4000))).isoformat(),
                "action": "block", "interface": "wan", "dir": "in", "protoname": "tcp",
                "src": src, "srcport": str(rnd(1024, 65535)), "dst": f"192.168.10.{rnd(2, 40)}",
                "dstport": str(dport), **extra,
            })

        for _ in range(rnd(2, 8)):
            mk(random.choice(NOISE), random.choice([22, 23, 80, 443, 3389, 5060, 8080, 37215]))
        if random.random() < 0.7:
            for _ in range(rnd(10, 30)):
                mk(TRYHARD, rnd(1, 10000))
        if random.random() < 0.5:
            for _ in range(rnd(3, 10)):
                mk(SCANNER, random.choice([80, 443, 8080, 8443]), dst=f"192.168.10.{rnd(2, 200)}")
        if random.random() < 0.6:
            for _ in range(rnd(2, 6)):
                mk(BRUTE, 22)
        return rows

    async def get_ids_alerts(self, row_count: int = 0):
        if random.random() < 0.5:
            return [{
                "timestamp": datetime.now(timezone.utc).isoformat(), "src_ip": TRYHARD, "dest_ip": "192.168.10.5",
                "dest_port": 22, "alert": "ET SCAN Potential SSH Scan",
                "alert_category": "Attempted Information Leak", "alert_severity": 2, "alert_action": "blocked",
            }]
        return []

    async def get_system(self):
        return {"resources": {"cpu": {"used": rnd(3, 40)}}, "traffic": {}}

    async def get_firmware_status(self):
        return {"product_version": "25.1.5 (mock)", "needs_reboot": "0", "status_msg": "2 mises à jour disponibles",
                "upgrade_packages": [{"name": "openssl"}, {"name": "curl"}]}

    async def run_audit(self):
        return (
            "openssl-3.0.13 is vulnerable:\n  OpenSSL -- Denial of service via crafted certificate\n"
            "  CVE: CVE-2024-0727\n  WWW: https://vuxml.freebsd.org/freebsd/mock1.html\n\n"
            "curl-8.5.0 is vulnerable:\n  curl -- HSTS bypass\n  CVE: CVE-2024-2004\n"
            "  WWW: https://vuxml.freebsd.org/freebsd/mock2.html\n\n2 problem(s) in 2 installed package(s) found."
        )
