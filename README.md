# OPNsense SOC Dashboard

Dashboard temps réel (backend Node + frontend vanilla, **zéro dépendance npm**) alimenté par l'API OPNsense.

- Blocages firewall en direct (timeline, top ports, flux)
- Score **tryhard / suspect / bruit** par IP source avec les raisons détaillées (scan de ports, balayage d'hôtes, services sensibles, rafales, persistance, alertes IDS)
- Alertes Suricata (si IDS activé)
- Vulnérabilités : `pkg audit` + état des mises à jour firmware

## Lancer

```bash
cp .env.example .env   # renseigne OPN_URL, OPN_API_KEY, OPN_API_SECRET
npm start              # Node >= 20.6
```
Puis http://127.0.0.1:3000. Test sans firewall : `npm run dev` (données factices).

## Clé API OPNsense
System > Access > Users > (ton user) > API keys. Droits à donner : *Diagnostics: Firewall log*, *Diagnostics: System/Traffic*, *Intrusion Detection*, *System: Firmware* (ou un user dédié lecture seule + audit firmware).

## Notes
- Endpoints utilisés : `/api/diagnostics/firewall/log`, `/api/ids/service/queryAlerts`, `/api/diagnostics/system/systemResources`, `/api/diagnostics/traffic/interface`, `/api/core/firmware/status|audit|upgradestatus`.
- Les logs firewall doivent être activés sur tes règles de blocage (Log). Mets `WAN_INTERFACES=wan` pour ne voir que l'entrant.
- L'historique est gardé en mémoire (24 h) : il repart de zéro au redémarrage.
- Le serveur écoute en local par défaut ; si tu l'exposes, mets `DASH_USER`/`DASH_PASS` (et idéalement un reverse proxy HTTPS).
- Scoring : voir `scoreSource()` dans `server/analyzer.js`, seuils faciles à ajuster.
