#!/usr/bin/env python3
"""
Volumetric DDoS (UDP flood) simulation.

Generates massive UDP traffic (large packets) from many IPs targeting one
destination - classic bandwidth exhaustion attack. Distinct from
application-layer DDoS because it's protocol-layer (no HTTP, just raw
network flood).

Usage:
    python generate_ddos_volumetric.py
"""

import random
import time

from common import emit_cloud, emit_firewall, random_public_ip

TARGET_IP = "10.20.1.5"
TARGET_PORT = 443
DURATION_SECONDS = 20
PACKETS_PER_TICK = 50


def main() -> None:
    print(f"Simulating volumetric UDP flood against {TARGET_IP} for {DURATION_SECONDS}s")

    end_time = time.time() + DURATION_SECONDS
    while time.time() < end_time:
        for _ in range(PACKETS_PER_TICK):
            src_ip = random_public_ip()
            # Volumetric = large packets, high total bandwidth
            byte_count = random.randint(1000, 65000)
            emit_firewall(
                src_ip=src_ip, dst_ip=TARGET_IP, dst_port=TARGET_PORT,
                protocol="UDP", action="ALLOW", byte_count=byte_count,
            )
            if random.random() < 0.3:
                emit_cloud(
                    src_ip=src_ip, dst_ip=TARGET_IP, dst_port=TARGET_PORT,
                    protocol="UDP", action="ACCEPT", byte_count=byte_count,
                )
        time.sleep(0.5)

    print("Volumetric DDoS simulation complete.")


if __name__ == "__main__":
    main()
