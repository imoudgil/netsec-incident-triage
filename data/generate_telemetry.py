#!/usr/bin/env python3
"""Deterministic multi-source telemetry generator (normal + attack scenarios)."""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_OUT = BASE_DIR / "data" / "raw_events.jsonl"

SEED = 20260107


def _ts(base: datetime, offset_sec: int) -> str:
    return (base + timedelta(seconds=offset_sec)).replace(tzinfo=timezone.utc).isoformat()


def generate_events() -> list[dict]:
    rng = random.Random(SEED)
    base = datetime(2026, 1, 7, 14, 0, 0)
    events: list[dict] = []

    # Baseline noise
    for i in range(120):
        events.append(
            {
                "source": "netflow",
                "ts": _ts(base, i * 30),
                "src_ip": f"10.10.10.{10 + (i % 40)}",
                "dst_ip": "10.10.20.5",
                "dst_port": rng.choice([443, 445, 53]),
                "bytes": rng.randint(500, 5000),
                "proto": "tcp",
            }
        )

    # Attack 1: IoT lateral / VLAN violation — scan from 10.10.50.14 -> 10.10.20.5
    for port in [22, 445, 3389, 135]:
        events.append(
            {
                "source": "netflow",
                "ts": _ts(base, 600 + port),
                "src_ip": "10.10.50.14",
                "dst_ip": "10.10.20.5",
                "dst_port": port,
                "bytes": 64,
                "proto": "tcp",
                "scenario": "iot_vlan_violation",
            }
        )

    # Attack 2: Brute force then success (Windows + Linux)
    src = "203.0.113.44"
    for j in range(8):
        events.append(
            {
                "source": "windows_security",
                "ts": _ts(base, 900 + j * 5),
                "event_id": 4625,
                "host": "10.10.20.5",
                "src_ip": src,
                "user": "svc_backup",
                "scenario": "brute_force",
            }
        )
    events.append(
        {
            "source": "windows_security",
            "ts": _ts(base, 950),
            "event_id": 4624,
            "host": "10.10.20.5",
            "src_ip": src,
            "user": "svc_backup",
            "scenario": "brute_force",
        }
    )
    events.append(
        {
            "source": "linux_auth",
            "ts": _ts(base, 960),
            "message": "Failed password for invalid user admin",
            "host": "10.10.20.12",
            "src_ip": "198.51.100.77",
            "scenario": "brute_force",
        }
    )

    # Attack 3: M365 impossible travel
    events.append(
        {
            "source": "azure_signin",
            "ts": _ts(base, 1200),
            "user": "j.smith@corp.example",
            "ip": "24.66.1.1",
            "city": "Edmonton",
            "country": "CA",
            "status": "success",
            "scenario": "impossible_travel",
        }
    )
    events.append(
        {
            "source": "azure_signin",
            "ts": _ts(base, 1200 + 600),
            "user": "j.smith@corp.example",
            "ip": "185.220.101.5",
            "city": "Frankfurt",
            "country": "DE",
            "status": "success",
            "scenario": "impossible_travel",
        }
    )

    # False positive: allowlisted scanner
    for port in [80, 443, 22]:
        events.append(
            {
                "source": "netflow",
                "ts": _ts(base, 1500 + port),
                "src_ip": "10.10.10.50",
                "dst_ip": "10.10.20.5",
                "dst_port": port,
                "bytes": 128,
                "proto": "tcp",
                "scenario": "scanner_noise",
            }
        )

    events.sort(key=lambda e: e["ts"])
    return events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    events = generate_events()
    with args.output.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    print(f"Wrote {len(events)} events to {args.output}")


if __name__ == "__main__":
    main()