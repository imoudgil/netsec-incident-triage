"""ServiceNow-compatible incident JSON + management notification brief."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.triage import Incident

IMPACT_MAP = {"P1": "1", "P2": "2", "P3": "3", "P4": "3"}
URGENCY_MAP = {"P1": "1", "P2": "2", "P3": "2", "P4": "3"}


def servicenow_payload(incident: Incident) -> dict[str, Any]:
    work_notes = [
        f"MITRE: {', '.join(incident.mitre)}",
        f"Rules: {', '.join(incident.rule_ids)}",
        f"Diagnostics: {json.dumps(incident.diagnostics, default=str)[:3500]}",
    ]
    if incident.host_containment:
        work_notes.append(f"Recommended containment (dry-run): {incident.host_containment}")

    return {
        "short_description": f"[SOC] {incident.summary}"[:160],
        "impact": IMPACT_MAP.get(incident.priority, "3"),
        "urgency": URGENCY_MAP.get(incident.priority, "3"),
        "category": "Security",
        "assignment_group": "SOC Tier 2",
        "work_notes": "\n".join(work_notes),
        "u_priority": incident.priority,
        "correlation_id": incident.incident_id,
    }


def management_brief(incident: Incident) -> str:
    lines = [
        f"# Security Incident Brief — {incident.incident_id}",
        "",
        f"**Priority:** {incident.priority}",
        "",
        "## What happened",
        incident.summary,
        "",
        "## Business impact",
        "Potential unauthorized access or policy violation on production VLAN assets. "
        "Confirm with SOC Tier 2 before customer-facing impact statements.",
        "",
        "## Containment status",
        (incident.host_containment or "No automated host isolation recommended pending analyst review."),
        "",
        "## Next actions",
        "- Validate alerts against SIEM correlation",
        "- Obtain change ticket before live firewall or host isolation",
        "- Notify service owner for affected server VLAN hosts",
        "",
    ]
    return "\n".join(lines)


def write_escalation(incident: Incident, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    sn_path = out_dir / f"{incident.incident_id}_servicenow.json"
    md_path = out_dir / f"{incident.incident_id}_brief.md"
    payload = servicenow_payload(incident)
    sn_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(management_brief(incident), encoding="utf-8")
    return sn_path, md_path