import asyncio
import json

from backend.opnsense import OpnsenseClient

BODY = json.dumps([{"action": "block", "src": "1.2.3.4"}]).encode()


async def fake_server(reader, writer):
    head = (await reader.readuntil(b"\r\n\r\n")).decode()
    if head.startswith("GET /api/forbidden"):
        writer.write(b"HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
    elif "HTTP/1.0" in head.split("\r\n")[0]:
        writer.write(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + BODY)
    else:  # chunked cassé : la taille annoncée est trop courte -> footer invalide
        writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n" + BODY[:5] + b"XX" + BODY[5:] + b"\r\n0\r\n\r\n")
    await writer.drain()
    writer.close()


def test_fallback_http10_and_friendly_403():
    async def run():
        srv = await asyncio.start_server(fake_server, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        c = OpnsenseClient(f"http://127.0.0.1:{port}", "k", "s", verify_tls=False)
        rows = await c.get_firewall_log(10)
        assert rows[0]["src"] == "1.2.3.4" and c.http10
        try:
            await c._get("/api/forbidden")
        except Exception as e:
            assert "403" in str(e)
        else:
            raise AssertionError
        c2 = OpnsenseClient(f"http://127.0.0.1:{port}", "k", "s")
        try:
            await c2._get("/api/core/firmware/forbidden")
        except Exception:
            pass
        srv.close()

    asyncio.run(run())
