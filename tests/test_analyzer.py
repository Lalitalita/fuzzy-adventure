from backend.analyzer import parse_audit, score_source


def src(**o):
    return {"count": 1, "ports": {80}, "dsts": {"a"}, "first": 0, "last": 0, "ids": [], **o}


def test_isolated_hit_is_noise():
    assert score_source(src())["level"] == "bruit"


def test_port_scan_is_tryhard():
    r = score_source(src(count=120, ports=set(range(1, 61)), dsts={f"h{i}" for i in range(12)}))
    assert r["level"] == "tryhard"


def test_parse_audit():
    r = parse_audit("curl-8.5 is vulnerable:\n  curl -- bug\n  CVE: CVE-2024-1\n  WWW: https://x\n\n1 problem(s)")
    assert r[0]["cves"] == ["CVE-2024-1"] and r[0]["links"] == ["https://x"]
