"""Deduplicate alerts into incidents; assign P1-P4; attach diagnostics."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.detector import Alert


PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


@dataclass
class Incident:
    incident_id: str
    priority: str
    rule_ids: list[str]
    summary: str
    mitre: list[str]
    alerts: list[Alert]
    suppressed_count: int = 0
    diagnostics: dict[str, Any] = field(default_factory=dict)
    host_containment: str | None = None


def _bucket_key(alert: Alert) -> str:
    parts = [alert.rule_id, alert.src_ip or "", alert.dst_ip or "", alert.user or ""]
    return "|".join(parts)


def triage_alerts(alerts: list[Alert]) -> list[Incident]:
    active = [a for a in alerts if not a.suppressed]
    suppressed = len(alerts) - len(active)
    buckets: dict[str, list[Alert]] = {}
    for a in active:
        buckets.setdefault(_bucket_key(a), []).append(a)

    incidents: list[Incident] = []
    for idx, (key, group) in enumerate(sorted(buckets.items()), start=1):
        best = min(PRIORITY_ORDER.get(a.severity_hint, 9) for a in group)
        rev = {v: k for k, v in PRIORITY_ORDER.items()}
        pri = rev.get(best, "P3")
        if any(a.rule_id == "brute_force" for a in group):
            pri = "P1"
        elif any(a.rule_id == "cross_vlan_iot_to_server" for a in group) and pri not in ("P1", "P2"):
            pri = "P2"

        summary = group[0].summary
        if len(group) > 1:
            summary = f"{summary} (+{len(group) - 1} correlated alert(s))"

        host = group[0].dst_ip or group[0].src_ip
        containment = None
        if host and host.startswith("10."):
            containment = f"Invoke-HostContainment.ps1 -HostAddress {host} -WhatIf"

        incidents.append(
            Incident(
                incident_id=f"INC-2026-{idx:04d}",
                priority=pri,
                rule_ids=sorted({a.rule_id for a in group}),
                summary=summary,
                mitre=sorted({a.mitre for a in group}),
                alerts=group,
                suppressed_count=suppressed if idx == 1 else 0,
                diagnostics={
                    "alert_count": len(group),
                    "rules": [a.rule_id for a in group],
                    "details": [a.details for a in group],
                },
                host_containment=containment,
            )
        )
    return incidents