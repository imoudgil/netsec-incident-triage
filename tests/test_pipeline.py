"""Pipeline tests: scenarios, CIDR, false-positive suppression, ServiceNow JSON shape."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.detector import detect
from src.escalator import servicenow_payload
from src.ingest import load_events
from src.triage import triage_alerts
from src.zones import load_rules, load_zones, zone_for_ip


@pytest.fixture(scope="module")
def pipeline_data():
    raw = ROOT / "data" / "raw_events.jsonl"
    if not raw.exists():
        subprocess.check_call([sys.executable, str(ROOT / "data" / "generate_telemetry.py")])
    zones, allow = load_zones(ROOT / "config" / "network_zones.yaml")
    rules = load_rules(ROOT / "config" / "detection_rules.yaml")
    events = load_events(raw)
    alerts = detect(events, zones, allow, rules)
    incidents = triage_alerts(alerts)
    return events, alerts, incidents, zones, allow, rules


def test_cidr_vlan_mapping(pipeline_data):
    _, _, _, zones, _, _ = pipeline_data
    assert zone_for_ip("10.10.50.14", zones).zone_id == "vlan50_iot"
    assert zone_for_ip("10.10.20.5", zones).zone_id == "vlan20_servers"
    assert zone_for_ip("10.10.10.50", zones).zone_id == "vlan10_corp"


def test_brute_force_p1(pipeline_data):
    _, alerts, incidents, _, _, _ = pipeline_data
    assert any(a.rule_id == "brute_force" for a in alerts)
    brute_inc = [i for i in incidents if "brute_force" in i.rule_ids]
    assert brute_inc
    assert brute_inc[0].priority == "P1"


def test_impossible_travel_detected(pipeline_data):
    _, alerts, _, _, _, _ = pipeline_data
    assert any(a.rule_id == "m365_impossible_travel" for a in alerts)


def test_scanner_suppressed(pipeline_data):
    _, alerts, _, _, _, _ = pipeline_data
    scanner = [a for a in alerts if a.src_ip == "10.10.10.50" and a.rule_id == "port_scan"]
    assert scanner
    assert all(a.suppressed for a in scanner)


def test_servicenow_payload_schema(pipeline_data):
    _, _, incidents, _, _, _ = pipeline_data
    assert incidents
    payload = servicenow_payload(incidents[0])
    for key in ("short_description", "impact", "urgency", "category", "assignment_group", "work_notes"):
        assert key in payload
    assert payload["category"] == "Security"
    assert payload["assignment_group"] == "SOC Tier 2"


def test_run_pipeline_cli():
    subprocess.check_call([sys.executable, str(ROOT / "run_pipeline.py")], cwd=ROOT)
    esc = ROOT / "output" / "escalations"
    assert esc.exists()
    assert list(esc.glob("*_servicenow.json"))
    pb = ROOT / "output" / "powerbi" / "incidents.csv"
    assert pb.exists()