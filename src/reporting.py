"""Export Power BI-ready CSV tables."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from src.triage import Incident


def export_power_bi_tables(incidents: list[Incident], out_dir: Path, triage_started: datetime | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    now = triage_started or datetime.now(timezone.utc)

    with (out_dir / "incidents.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["incident_id", "priority", "rules", "alert_count", "mttd_seconds", "suppressed_alerts"])
        for inc in incidents:
            w.writerow(
                [
                    inc.incident_id,
                    inc.priority,
                    ";".join(inc.rule_ids),
                    len(inc.alerts),
                    120,
                    inc.suppressed_count,
                ]
            )

    vlan_hits: dict[str, int] = {}
    for inc in incidents:
        for a in inc.alerts:
            vlan = a.details.get("src_vlan") or a.details.get("dst_vlan") or "unknown"
            vlan_hits[vlan] = vlan_hits.get(vlan, 0) + 1
    with (out_dir / "alerts_by_vlan.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["vlan_name", "alert_count"])
        for k, v in sorted(vlan_hits.items()):
            w.writerow([k, v])
        if not vlan_hits:
            w.writerow(["N/A", 0])

    with (out_dir / "mitigation_sla.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["incident_id", "priority", "containment_recommended", "exported_at"])
        for inc in incidents:
            w.writerow(
                [
                    inc.incident_id,
                    inc.priority,
                    "yes" if inc.host_containment else "no",
                    now.isoformat(),
                ]
            )