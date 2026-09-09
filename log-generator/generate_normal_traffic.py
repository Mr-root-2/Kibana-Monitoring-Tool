#!/usr/bin/env python3
"""
Phase 3 - Normal traffic baseline generator.

Produces a believable, noisy-but-stable baseline across all three sources:
varying request rates per minute, many distinct source IPs, normal response
codes, multiple endpoints, normal latency. Run this continuously (or for a
fixed duration) BEFORE testing any detection or anomaly logic - you need a
baseline to detect deviations from.

Usage:
    python generate_normal_traffic.py               # runs for 10 minutes
    python generate_normal_traffic.py --minutes 30   # runs for 30 minutes
    python generate_normal_traffic.py --forever      # runs until Ctrl+C
"""

import argparse
import random
import time

from common import (
    API_ENDPOINTS,
    INTERNAL_ASSETS,
    emit_app,
    emit_cloud,
    emit_firewall,
    random_public_ip,
)

# Target requests/minute band. Real traffic isn't flat - it wobbles.
BASE_RATE_MIN = 450
BASE_RATE_MAX = 550


def emit_one_normal_event() -> None:
    src_ip = random_public_ip()
    asset = random.choice(INTERNAL_ASSETS)
    protocol = random.choice(["TCP", "UDP"])
    byte_count = random.randint(200, 15000)

    kind = random.choice(["firewall", "cloud", "app"])

    if kind == "firewall":
        emit_firewall(src_ip, asset["ip"], asset["port"], protocol, "ALLOW", byte_count)
    elif kind == "cloud":
        emit_cloud(src_ip, asset["ip"], asset["port"], protocol, "ACCEPT", byte_count)
    else:
        status = random.choice([200, 200, 200, 200, 301, 404])
        path = random.choice(API_ENDPOINTS)
        latency = random.randint(60, 180)  # healthy latency band
        emit_app(src_ip, "GET", path, status, byte_count, latency)


def run_one_minute() -> int:
    """Emit a randomized-but-bounded number of events over ~60 seconds."""
    target_count = random.randint(BASE_RATE_MIN, BASE_RATE_MAX)
    interval = 60.0 / target_count
    for _ in range(target_count):
        emit_one_normal_event()
        time.sleep(interval)
    return target_count


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--minutes", type=int, default=10)
    parser.add_argument("--forever", action="store_true")
    args = parser.parse_args()

    print(f"Emitting normal traffic at ~{BASE_RATE_MIN}-{BASE_RATE_MAX} req/min")
    minute = 0
    try:
        while args.forever or minute < args.minutes:
            count = run_one_minute()
            minute += 1
            print(f"  minute {minute}: {count} events")
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
