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
System > Access > Users > (ton user) > API keys. Droits (System > Access > Groups > Privileges) par fonctionnalité :

| Fonction | Droit OPNsense |
|---|---|
| Logs firewall (indispensable) | `Diagnostics: Log: Firewall: General` |
| Vulnérabilités / firmware | `System: Firmware` |
| Alertes IDS | `Services: Intrusion Detection: Log File` |
| Ressources / trafic | `Diagnostics: System Activity`, `Diagnostics: Traffic` |

Sans un droit, la fonction concernée affiche un ⚠ avec le droit manquant ; le reste du dashboard continue de marcher.

## Notes
- Si OPNsense renvoie une réponse chunked mal formée, le client bascule automatiquement en HTTP/1.0.
- Endpoints utilisés : `/api/diagnostics/firewall/log`, `/api/ids/service/queryAlerts`, `/api/diagnostics/system/systemResources`, `/api/diagnostics/traffic/interface`, `/api/core/firmware/status|audit|upgradestatus`.
- Les logs firewall doivent être activés sur tes règles de blocage (Log). Mets `WAN_INTERFACES=wan` pour ne voir que l'entrant.
- L'historique est gardé en mémoire (24 h) : il repart de zéro au redémarrage.
- Le serveur écoute en local par défaut ; si tu l'exposes, mets `DASH_USER`/`DASH_PASS` (et idéalement un reverse proxy HTTPS).
- Scoring : voir `score_source()` dans `backend/analyzer.py`, seuils faciles à ajuster.
