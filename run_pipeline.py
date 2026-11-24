#!/usr/bin/env python3
"""End-to-end: ingest -> detect -> triage -> escalate -> report."""

from pathlib import Path

from src.detector import detect
from src.escalator import write_escalation
from src.ingest import load_events
from src.reporting import export_power_bi_tables
from src.triage import triage_alerts
from src.zones import load_rules, load_zones

ROOT = Path(__file__).resolve().parent


def main():
    events_path = ROOT / "data" / "raw_events.jsonl"
    if not events_path.exists():
        import subprocess
        import sys

        subprocess.check_call([sys.executable, str(ROOT / "data" / "generate_telemetry.py")])

    zones, allowlisted = load_zones(ROOT / "config" / "network_zones.yaml")
    rules = load_rules(ROOT / "config" / "detection_rules.yaml")
    events = load_events(events_path)
    alerts = detect(events, zones, allowlisted, rules)
    incidents = triage_alerts(alerts)

    out_esc = ROOT / "output" / "escalations"
    for inc in incidents:
        write_escalation(inc, out_esc)

    export_power_bi_tables(incidents, ROOT / "output" / "powerbi")
    print(f"Events: {len(events)} | Alerts: {len(alerts)} | Incidents: {len(incidents)}")
    print(f"Outputs: {ROOT / 'output'}")


if __name__ == "__main__":
    main()