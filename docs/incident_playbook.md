# Incident playbook (synthetic)

## Detection

1. Run `python run_pipeline.py` or scheduled ingest of `data/raw_events.jsonl`.
2. Review active (non-suppressed) alerts in triage output.

## Containment

1. Read diagnostics on the incident record.
2. Run `Invoke-HostContainment.ps1 -HostAddress <ip> -WhatIf` and paste output into the change ticket.
3. **Do not** apply live rules without SOC Tier 2 + change approval.

## Escalation

1. `output/escalations/<INC>_servicenow.json` — Table API-shaped mock payload for SOC Tier 2 queue.
2. `<INC>_brief.md` — management / service-owner notification draft.

## Notification

Edit the brief for audience; remove internal MITRE detail for external parties.

## Post-incident

Import `output/powerbi/*.csv` into Power BI for MTTD proxy, VLAN heat map, and false-positive rate.