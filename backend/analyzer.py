"""Normalisation des logs + scoring "tryhard" par IP source."""
import bisect
import re
import time
from collections import Counter, defaultdict
from datetime import datetime

SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 135: "RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}


def port_name(p) -> str | None:
    return SENSITIVE_PORTS.get(int(p))


def _ts_ms(v) -> int:
    try:
        return int(datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp() * 1000)
    except ValueError:
        return 0


def _int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def normalize(row: dict) -> dict | None:
    ts = _ts_ms(row.get("__timestamp__") or row.get("timestamp") or "")
    if not ts or not row.get("src"):
        return None
    return {
        "ts": ts,
        "action": row.get("action"),
        "iface": row.get("interface") or row.get("ifname") or "",
        "proto": (row.get("protoname") or row.get("proto") or "").lower(),
        "src": row["src"],
        "sport": _int(row.get("srcport")),
        "dst": row.get("dst"),
        "dport": _int(row.get("dstport")),
    }


def _key(e: dict) -> tuple:
    return (e["ts"], e["src"], e["sport"], e["dst"], e["dport"], e["proto"])


class Store:
    def __init__(self, wan=(), ignore=(), retention_ms=24 * 3600_000, max_events=100_000):
        self.events: list[dict] = []
        self.seen: set[tuple] = set()
        self.wan, self.ignore = list(wan), list(ignore)
        self.retention_ms, self.max = retention_ms, max_events
        self.ids: list[dict] = []

    def ingest(self, rows: list[dict]) -> int:
        added = 0
        for row in rows:
            e = normalize(row)
            if not e or e["action"] != "block":
                continue
            if self.wan and e["iface"] not in self.wan:
                continue
            if any(e["src"].startswith(p) for p in self.ignore):
                continue
            k = _key(e)
            if k in self.seen:
                continue
            self.seen.add(k)
            self.events.append(e)
            added += 1
        if added:
            self.events.sort(key=lambda e: e["ts"])
            self._prune()
        return added

    def _prune(self):
        cut = time.time() * 1000 - self.retention_ms
        i = 0
        while i < len(self.events) and self.events[i]["ts"] < cut:
            i += 1
        i = max(i, len(self.events) - self.max)
        for e in self.events[:i]:
            self.seen.discard(_key(e))
        del self.events[:i]

    def set_ids(self, rows: list[dict]):
        self.ids = [{
            "ts": _ts_ms(r.get("timestamp")) or int(time.time() * 1000),
            "src": r.get("src_ip"), "dst": r.get("dest_ip"), "dport": _int(r.get("dest_port")),
            "sig": r.get("alert") or r.get("alert_signature") or "",
            "severity": _int(r.get("alert_severity")) or 3,
        } for r in rows if r.get("src_ip")]

    def since(self, ms: int) -> list[dict]:
        cut = time.time() * 1000 - ms
        i = bisect.bisect_left([e["ts"] for e in self.events], cut)
        return self.events[i:]


def score_source(s: dict) -> dict:
    """Score 0-100 + raisons explicites. s: count, ports(set), dsts(set), first, last, ids(list)."""
    score, why = 0, []
    n_ports, n_dst = len(s["ports"]), len(s["dsts"])

    if n_ports >= 100:
        score += 45; why.append(f"Scan de ports massif ({n_ports} ports distincts)")
    elif n_ports >= 15:
        score += 35; why.append(f"Scan de ports ({n_ports} ports distincts)")
    elif n_ports >= 5:
        score += 15; why.append(f"Sonde plusieurs ports ({n_ports})")

    if n_dst >= 10:
        score += 20; why.append(f"Balayage de {n_dst} hôtes internes")
    elif n_dst >= 3:
        score += 8; why.append(f"Touche {n_dst} hôtes")

    sens = sorted(p for p in s["ports"] if p in SENSITIVE_PORTS)
    if sens:
        score += min(30, len(sens) * 10)
        why.append("Services sensibles ciblés : " + ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in sens[:6]))

    if s["count"] >= 200:
        score += 20; why.append(f"Volume élevé ({s['count']} blocages)")
    elif s["count"] >= 50:
        score += 10; why.append(f"Volume notable ({s['count']} blocages)")

    span_min = (s["last"] - s["first"]) / 60000
    if span_min >= 10 and s["count"] >= 20:
        score += 10; why.append(f"Persistant ({round(span_min)} min d'activité)")
    if s["count"] >= 30 and span_min > 0 and s["count"] / span_min >= 30:
        score += 10; why.append(f"Rafale (~{round(s['count'] / span_min)}/min)")

    if s["ids"]:
        worst = min(a["severity"] for a in s["ids"])
        score += {1: 35, 2: 25}.get(worst, 15)
        why.append(f"{len(s['ids'])} alerte(s) IDS : {s['ids'][0]['sig']}")

    score = min(100, score)
    if not why:
        why.append("Bruit de fond internet (hit isolé)")
    level = "tryhard" if score >= 55 else "suspect" if score >= 25 else "bruit"
    return {"score": score, "level": level, "why": why}


def build_snapshot(store: Store, extra: dict) -> dict:
    now = int(time.time() * 1000)
    hour, five, day = store.since(3600_000), store.since(300_000), store.events

    agg: dict[str, dict] = {}
    port_counts: dict[str, Counter] = defaultdict(Counter)
    for e in hour:
        s = agg.setdefault(e["src"], {"ip": e["src"], "count": 0, "ports": set(), "dsts": set(),
                                      "first": e["ts"], "last": e["ts"], "ids": [], "protos": set()})
        s["count"] += 1
        s["ports"].add(e["dport"]); s["dsts"].add(e["dst"]); s["protos"].add(e["proto"])
        s["last"] = max(s["last"], e["ts"])
        port_counts[e["src"]][e["dport"]] += 1
    for a in store.ids:
        if a["src"] in agg and now - a["ts"] < 3600_000:
            agg[a["src"]]["ids"].append(a)

    sources = []
    for s in agg.values():
        r = score_source(s)
        sources.append({
            "ip": s["ip"], "count": s["count"], "ports": len(s["ports"]), "targets": len(s["dsts"]),
            "first": s["first"], "last": s["last"], "protos": sorted(s["protos"]),
            "topPorts": [{"port": p, "count": c, "name": port_name(p)} for p, c in port_counts[s["ip"]].most_common(5)],
            **r,
        })
    sources.sort(key=lambda s: (-s["score"], -s["count"]))

    t0 = now // 60000 * 60000 - 59 * 60000
    timeline = [{"t": t0 + i * 60000, "count": 0} for i in range(60)]
    for e in hour:
        i = (e["ts"] - t0) // 60000
        if 0 <= i < 60:
            timeline[i]["count"] += 1

    return {
        "now": now,
        "kpi": {
            "blocked5m": len(five), "blocked1h": len(hour), "blocked24h": len(day),
            "uniqueIps1h": len(agg),
            "tryhard": sum(s["level"] == "tryhard" for s in sources),
            "suspect": sum(s["level"] == "suspect" for s in sources),
            "idsAlerts1h": sum(now - a["ts"] < 3600_000 for a in store.ids),
        },
        "timeline": timeline,
        "sources": sources[:50],
        "topPorts": [{"port": p, "count": c, "name": port_name(p)} for p, c in Counter(e["dport"] for e in day).most_common(8)],
        "recent": store.events[-60:][::-1],
        "ids": store.ids[:30],
        **extra,
    }


def parse_audit(text: str) -> list[dict]:
    out, cur = [], None
    for raw in str(text).split("\n"):
        line = raw.strip()
        m = re.match(r"^(\S+) is vulnerable:?$", line)
        if m:
            cur = {"pkg": m[1], "issues": [], "cves": [], "links": []}
            out.append(cur)
            continue
        if cur is None or not line:
            continue
        if re.match(r"(?i)^CVE:", line):
            cur["cves"].append(re.sub(r"(?i)^CVE:\s*", "", line))
        elif re.match(r"(?i)^WWW:", line):
            cur["links"].append(re.sub(r"(?i)^WWW:\s*", "", line))
        elif not re.match(r"^\d+ problem", line):
            cur["issues"].append(line)
    return out
