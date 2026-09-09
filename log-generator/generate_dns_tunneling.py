#!/usr/bin/env python3
"""
DNS tunneling attack simulation.

Simulates data exfiltration via DNS by generating firewall logs showing
many DNS queries (port 53) with unusually large byte counts from a single
internal source to an external IP. Detection signal: one source.ip sending
many connections to destination.port 53 with abnormally high network.bytes.

Usage:
    python generate_dns_tunneling.py
"""

import random
import time

from common import emit_firewall, random_public_ip

# The "compromised" internal host doing the exfiltration
COMPROMISED_HOST = "10.20.1.5"
DNS_PORT = 53
QUERY_COUNT = 60  # many DNS "queries" in rapid succession


def main() -> None:
    # Tunnel goes to a single external DNS server (attacker-controlled)
    c2_server = random_public_ip()
    print(f"Simulating DNS tunneling: {COMPROMISED_HOST} -> {c2_server}:53 "
          f"({QUERY_COUNT} queries with large payloads)")

    for _ in range(QUERY_COUNT):
        # Normal DNS queries are ~100-300 bytes. Tunneling pushes 500-3000+
        byte_count = random.randint(500, 3000)
        emit_firewall(
            src_ip=COMPROMISED_HOST,
            dst_ip=c2_server,
            dst_port=DNS_PORT,
            protocol="UDP",
            action="ALLOW",
            byte_count=byte_count,
            src_port=random.randint(1024, 65535),
        )
        time.sleep(random.uniform(0.2, 0.8))

    print("DNS tunneling simulation complete.")


if __name__ == "__main__":
    main()
