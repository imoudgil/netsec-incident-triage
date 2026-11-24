# Architecture — netsec-incident-triage

Synthetic SOC lab. No live ServiceNow, SIEM, or production hosts.

## Topology (config/network_zones.yaml)

- **VLAN 10** — Corporate LAN `10.10.10.0/24`
- **VLAN 20** — Core Servers / AD `10.10.20.0/24`
- **VLAN 50** — IoT / field `10.10.50.0/24` (must not initiate to VLAN 20)
- **External** — M365 / Azure sign-ins

## Incident lifecycle

```text
raw_events.jsonl
  -> ingest.py
  -> detector.py (rules + ipaddress CIDR)
  -> triage.py (dedupe, P1–P4, diagnostics)
  -> escalator.py (ServiceNow JSON mock + brief.md)
  -> reporting.py (Power BI CSVs)
```

## Containment

`scripts/Invoke-HostContainment.ps1` defaults to **-WhatIf**. Live firewall changes require a change ticket.