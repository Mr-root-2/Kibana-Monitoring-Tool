#!/usr/bin/env python3
"""
Phase 4 - Port scan simulation.

One source IP probes many distinct destination ports on one target within
a short window. This is the signal detection-engine/rules/port_scan.py
looks for: same source.ip -> more than N distinct destination.port within
1 minute.

Usage:
    python generate_portscan.py
"""

import random
import time

from common import INTERNAL_ASSETS, emit_firewall, random_public_ip

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                9200, 9300, 27017]


def main() -> None:
    attacker_ip = random_public_ip()
    target = random.choice(INTERNAL_ASSETS)
    print(f"Simulating port scan: {attacker_ip} -> {target['ip']} "
          f"({len(COMMON_PORTS)} ports)")

    for port in COMMON_PORTS:
        emit_firewall(
            src_ip=attacker_ip,
            dst_ip=target["ip"],
            dst_port=port,
            protocol="TCP",
            action=random.choice(["ALLOW", "DENY"]),
            byte_count=random.randint(40, 100),
        )
        time.sleep(random.uniform(0.5, 2.0))  # within a 1-minute window

    print("Port scan simulation complete.")


if __name__ == "__main__":
    main()
