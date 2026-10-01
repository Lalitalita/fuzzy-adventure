import asyncio
import base64
import http.client
import json
import ssl
from urllib.parse import urlsplit

import httpx

# Droit OPNsense nécessaire par préfixe d'endpoint (pour des messages d'erreur clairs sur un 403).
PRIVILEGES = {
    "/api/core/firmware": "System: Firmware",
    "/api/ids": "Services: Intrusion Detection: Log File",
    "/api/diagnostics/firewall/log": "Diagnostics: Log: Firewall: General (ou Live View)",
    "/api/diagnostics/system": "Diagnostics: System Activity",
    "/api/diagnostics/traffic": "Diagnostics: Traffic",
}


class OpnError(Exception):
    pass


def _friendly(path: str, status: int) -> OpnError:
    path = path.split("?")[0]
    if status in (401, 403):
        priv = next((p for prefix, p in PRIVILEGES.items() if path.startswith(prefix)), "?")
        why = "clé API invalide" if status == 401 else f"droit manquant sur l'utilisateur API : « {priv} »"
        return OpnError(f"HTTP {status} sur {path} — {why}")
    return OpnError(f"HTTP {status} sur {path}")


class _Http10Connection(http.client.HTTPSConnection):
    # En HTTP/1.0 le serveur n'utilise pas le chunked encoding (contourne les réponses chunked mal formées).
    _http_vsn = 10
    _http_vsn_str = "HTTP/1.0"


class OpnsenseClient:
    def __init__(self, url: str, key: str, secret: str, verify_tls: bool = True):
        self.url, self.verify_tls = urlsplit(url), verify_tls
        self.auth_header = "Basic " + base64.b64encode(f"{key}:{secret}".encode()).decode()
        self.http = httpx.AsyncClient(base_url=url, auth=(key, secret), verify=verify_tls, timeout=15)
        self.http10 = False  # passe à True après une réponse chunked invalide

    def _request_http10(self, method: str, path: str, body: dict | None):
        ctx = ssl.create_default_context()
        if not self.verify_tls:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        if self.url.scheme == "https":
            conn = _Http10Connection(self.url.hostname, self.url.port or 443, timeout=15, context=ctx)
        else:
            conn = http.client.HTTPConnection(self.url.hostname, self.url.port or 80, timeout=15)
            conn._http_vsn, conn._http_vsn_str = 10, "HTTP/1.0"
        try:
            payload = json.dumps(body or {}) if method == "POST" else None
            headers = {"Authorization": self.auth_header, "Accept": "application/json"}
            if payload:
                headers["Content-Type"] = "application/json"
            conn.request(method, path, payload, headers)
            r = conn.getresponse()
            data = r.read()
            return r.status, data
        finally:
            conn.close()

    async def _request(self, method: str, path: str, body: dict | None = None):
        if not self.http10:
            try:
                r = await self.http.request(method, path, json=body if method == "POST" else None)
                status, data = r.status_code, r.content
            except (httpx.RemoteProtocolError, httpx.ReadError):
                self.http10 = True
        if self.http10:
            status, data = await asyncio.to_thread(self._request_http10, method, path, body)
        if status >= 400:
            raise _friendly(path, status)
        try:
            return json.loads(data)
        except ValueError:
            raise OpnError(f"Réponse non-JSON sur {path.split('?')[0]}")

    async def _get(self, path: str):
        return await self._request("GET", path)

    async def _post(self, path: str, body: dict | None = None):
        return await self._request("POST", path, body or {})

    async def get_firewall_log(self, limit: int) -> list[dict]:
        rows = await self._get(f"/api/diagnostics/firewall/log?limit={limit}")
        return rows if isinstance(rows, list) else []

    async def get_ids_alerts(self, row_count: int = 200) -> list[dict]:
        r = await self._post("/api/ids/service/queryAlerts", {"current": 1, "rowCount": row_count, "searchPhrase": ""})
        return r.get("rows", [])

    async def get_system(self) -> dict:
        res, traffic = await asyncio.gather(
            self._get("/api/diagnostics/system/systemResources"),
            self._get("/api/diagnostics/traffic/interface"),
            return_exceptions=True,
        )
        return {
            "resources": None if isinstance(res, Exception) else res,
            "traffic": None if isinstance(traffic, Exception) else traffic,
        }

    async def get_firmware_status(self) -> dict:
        return await self._get("/api/core/firmware/status")

    async def run_audit(self) -> str:
        """Lance `pkg audit` et attend la fin (max ~2 min). Retourne le texte brut."""
        await self._post("/api/core/firmware/audit")
        for _ in range(60):
            await asyncio.sleep(2)
            s = await self._get("/api/core/firmware/upgradestatus")
            if s.get("status") and s["status"] != "running":
                return s.get("log", "")
        raise TimeoutError("Audit trop long")
