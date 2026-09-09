#!/usr/bin/env python3
"""
Protocol-layer DDoS (SYN flood) simulation.

Many source IPs send small TCP SYN packets (low bytes, high count) to
exhaust connection tables. Distinct from volumetric (large packets) and
application-layer (HTTP requests).

Usage:
    python generate_ddos_syn_flood.py
"""

import random
import time

from common import emit_firewall, random_public_ip

TARGET_IP = "10.20.1.5"
TARGET_PORT = 443
DURATION_SECONDS = 20
PACKETS_PER_TICK = 80


def main() -> None:
    print(f"Simulating SYN flood against {TARGET_IP}:{TARGET_PORT} for {DURATION_SECONDS}s")

    end_time = time.time() + DURATION_SECONDS
    while time.time() < end_time:
        for _ in range(PACKETS_PER_TICK):
            src_ip = random_public_ip()
            # SYN flood = tiny packets, massive count
            byte_count = random.randint(40, 80)
            emit_firewall(
                src_ip=src_ip, dst_ip=TARGET_IP, dst_port=TARGET_PORT,
                protocol="TCP", action="ALLOW", byte_count=byte_count,
            )
        time.sleep(0.5)

    print("SYN flood simulation complete.")


if __name__ == "__main__":
    main()
