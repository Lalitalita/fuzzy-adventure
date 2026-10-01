# OPNsense SOC Dashboard

Dashboard temps réel (backend Python/FastAPI + frontend vanilla JS) alimenté par l'API OPNsense.

- Blocages firewall en direct (timeline, top ports, flux)
- Score **tryhard / suspect / bruit** par IP source avec les raisons détaillées (scan de ports, balayage d'hôtes, services sensibles, rafales, persistance, alertes IDS)
- Alertes Suricata (si IDS activé)
- Vulnérabilités : `pkg audit` + état des mises à jour firmware

## Lancer

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # renseigne OPN_URL, OPN_API_KEY, OPN_API_SECRET
python -m backend.main
```
Puis http://127.0.0.1:3000. Test sans firewall : `MOCK=1 python -m backend.main` (données factices). Tests : `pytest`.

## Clé API OPNsense
System > Access > Users > (ton user) > API keys. Droits à donner : *Diagnostics: Firewall log*, *Diagnostics: System/Traffic*, *Intrusion Detection*, *System: Firmware* (ou un user dédié lecture seule + audit firmware).

## Notes
- Endpoints utilisés : `/api/diagnostics/firewall/log`, `/api/ids/service/queryAlerts`, `/api/diagnostics/system/systemResources`, `/api/diagnostics/traffic/interface`, `/api/core/firmware/status|audit|upgradestatus`.
- Les logs firewall doivent être activés sur tes règles de blocage (Log). Mets `WAN_INTERFACES=wan` pour ne voir que l'entrant.
- L'historique est gardé en mémoire (24 h) : il repart de zéro au redémarrage.
- Le serveur écoute en local par défaut ; si tu l'exposes, mets `DASH_USER`/`DASH_PASS` (et idéalement un reverse proxy HTTPS).
- Scoring : voir `score_source()` dans `backend/analyzer.py`, seuils faciles à ajuster.
