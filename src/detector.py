"""Rule-based detection: VLAN boundaries, port scans, brute force, impossible travel."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from src.zones import Zone, zone_for_ip


@dataclass
class Alert:
    rule_id: str
    mitre: str
    summary: str
    severity_hint: str
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    suppressed: bool = False


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def detect(
    events: list[dict[str, Any]],
    zones: list[Zone],
    allowlisted: set[str],
    rules_cfg: dict[str, Any],
) -> list[Alert]:
    alerts: list[Alert] = []
    rules = rules_cfg.get("rules", {})
    suppression = rules_cfg.get("suppression", {})

    # Port scan aggregation
    scan_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    scan_times: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    # Brute force
    fail_counts: dict[tuple[str, str], int] = defaultdict(int)
    success_after_fail: dict[tuple[str, str], bool] = defaultdict(bool)

    # M365 sign-ins per user
    signins: dict[str, list[dict]] = defaultdict(list)

    for ev in events:
        if ev.get("source") == "netflow":
            src_ip = ev.get("src_ip", "")
            dst_ip = ev.get("dst_ip", "")
            src_z = zone_for_ip(src_ip, zones)
            dst_z = zone_for_ip(dst_ip, zones)

            if src_z and dst_z and src_z.zone_id == "vlan50_iot" and dst_z.zone_id == "vlan20_servers":
                alert = Alert(
                    rule_id="cross_vlan_iot_to_server",
                    mitre=rules["cross_vlan_iot_to_server"]["mitre"],
                    summary=f"IoT host {src_ip} connected to server {dst_ip}:{ev.get('dst_port')}",
                    severity_hint=rules["cross_vlan_iot_to_server"]["severity_base"],
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    details={"src_vlan": src_z.name, "dst_vlan": dst_z.name, "port": ev.get("dst_port")},
                )
                if src_ip in allowlisted and suppression.get("downgrade_if_allowlisted_source"):
                    alert.suppressed = True
                alerts.append(alert)

            key = (src_ip, dst_ip)
            port = ev.get("dst_port")
            if port is not None:
                scan_ports[key].add(int(port))
                scan_times[key].append(_parse_ts(ev["ts"]))

        elif ev.get("source") == "windows_security":
            src_ip = ev.get("src_ip", "")
            host = ev.get("host", "")
            key = (src_ip, host)
            if ev.get("event_id") == 4625:
                fail_counts[key] += 1
            elif ev.get("event_id") == 4624 and fail_counts[key] >= rules["brute_force"]["min_failures"]:
                success_after_fail[key] = True

        elif ev.get("source") == "linux_auth" and "Failed password" in ev.get("message", ""):
            fail_counts[(ev.get("src_ip", ""), ev.get("host", ""))] += 1

        elif ev.get("source") == "azure_signin":
            signins[ev["user"]].append(ev)

    # Port scan alerts
    rule = rules.get("port_scan", {})
    min_ports = rule.get("min_distinct_ports", 3)
    for key, ports in scan_ports.items():
        if len(ports) >= min_ports:
            src_ip, dst_ip = key
            alert = Alert(
                rule_id="port_scan",
                mitre=rule["mitre"],
                summary=f"Port scan from {src_ip} to {dst_ip} ({len(ports)} ports)",
                severity_hint=rule["severity_base"],
                src_ip=src_ip,
                dst_ip=dst_ip,
                details={"ports": sorted(ports)},
            )
            if src_ip in allowlisted:
                allowed = set(suppression.get("allowlisted_scanner_ports", []))
                if ports.issubset(allowed):
                    alert.suppressed = True
            alerts.append(alert)

    # Brute force alerts
    bf = rules["brute_force"]
    for key, ok in success_after_fail.items():
        if ok:
            src_ip, host = key
            alerts.append(
                Alert(
                    rule_id="brute_force",
                    mitre=bf["mitre"],
                    summary=f"Brute-force pattern then successful logon from {src_ip} to {host}",
                    severity_hint=bf["severity_base"],
                    src_ip=src_ip,
                    dst_ip=host,
                    details={"failures": fail_counts[key]},
                )
            )

    # Impossible travel
    it_rule = rules["m365_impossible_travel"]
    max_mins = it_rule["max_minutes_between"]
    for user, rows in signins.items():
        if len(rows) < 2:
            continue
        rows = sorted(rows, key=lambda r: r["ts"])
        for i in range(len(rows) - 1):
            t0 = _parse_ts(rows[i]["ts"])
            t1 = _parse_ts(rows[i + 1]["ts"])
            if (t1 - t0).total_seconds() <= max_mins * 60:
                if rows[i].get("country") != rows[i + 1].get("country"):
                    alerts.append(
                        Alert(
                            rule_id="m365_impossible_travel",
                            mitre=it_rule["mitre"],
                            summary=f"Impossible travel for {user}: {rows[i]['city']} -> {rows[i+1]['city']}",
                            severity_hint=it_rule["severity_base"],
                            user=user,
                            details={
                                "ip_a": rows[i]["ip"],
                                "ip_b": rows[i + 1]["ip"],
                                "minutes_apart": int((t1 - t0).total_seconds() / 60),
                            },
                        )
                    )
                    break

    return alerts