# netsec-incident-triage

Synthetic **network security monitoring, alert triage, and incident escalation** pipeline for portfolio / co-op applications. No live ServiceNow, production SIEM, or host firewall changes.

## Quick start

```bash
cd netsec-incident-triage
python3 -m pip install -r requirements.txt
python3 run_pipeline.py
```

Outputs:

- `output/escalations/*_servicenow.json` — Table API-shaped mock payloads
- `output/escalations/*_brief.md` — stakeholder notification drafts
- `output/powerbi/*.csv` — Power BI import tables

## Tests

```bash
python3 data/generate_telemetry.py
pytest tests -q
```

## Containment (dry-run)

```powershell
./scripts/Invoke-HostContainment.ps1 -HostAddress 10.10.20.5 -WhatIf
```

See `docs/architecture.md` and `docs/incident_playbook.md`.