"""Load network zones and resolve IPs to VLAN metadata."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Zone:
    zone_id: str
    name: str
    vlan: int | None
    cidr: str
    criticality: str


def load_zones(config_path: Path) -> tuple[list[Zone], set[str]]:
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    zones: list[Zone] = []
    allowlisted: set[str] = set()
    for z in raw.get("zones", []):
        if z.get("public_only"):
            continue
        zones.append(
            Zone(
                zone_id=z["id"],
                name=z["name"],
                vlan=z.get("vlan"),
                cidr=z["cidr"],
                criticality=z.get("criticality", "medium"),
            )
        )
    for entry in raw.get("allowlisted_sources", []):
        allowlisted.add(entry["ip"])
    return zones, allowlisted


def zone_for_ip(ip_str: str, zones: list[Zone]) -> Zone | None:
    if not ip_str or ip_str.count(".") != 3:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for z in zones:
        net = ipaddress.ip_network(z.cidr, strict=False)
        if ip in net:
            return z
    return None


def load_rules(rules_path: Path) -> dict[str, Any]:
    return yaml.safe_load(rules_path.read_text(encoding="utf-8"))