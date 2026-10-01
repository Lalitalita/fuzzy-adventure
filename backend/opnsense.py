import asyncio

import httpx


class OpnsenseClient:
    def __init__(self, url: str, key: str, secret: str, verify_tls: bool = True):
        self.http = httpx.AsyncClient(base_url=url, auth=(key, secret), verify=verify_tls, timeout=15)

    async def _get(self, path: str):
        r = await self.http.get(path)
        r.raise_for_status()
        return r.json()

    async def _post(self, path: str, body: dict | None = None):
        r = await self.http.post(path, json=body or {})
        r.raise_for_status()
        return r.json()

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
