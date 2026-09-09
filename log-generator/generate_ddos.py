#!/usr/bin/env python3
"""
Phase 5 - DDoS burst simulation.

Simulates an application-layer DDoS with the multiple correlated signals a
good detection should look for, not just a raw request count:

  - Request rate far above the Phase 3 baseline (~500/min -> tens of
    thousands/min)
  - High cardinality of distinct source IPs (many attackers, not one)
  - Traffic concentrated on a single target endpoint
  - Increased application latency as the target struggles
  - Increased rate of 5xx responses as the target starts failing

Usage:
    python generate_ddos.py                 # 30s burst against /api/checkout
    python generate_ddos.py --duration 60
"""

import argparse
import random
import time

from common import emit_app, emit_cloud, emit_firewall, random_public_ip

TARGET_PATH = "/api/checkout"
TARGET_IP = "10.20.1.5"
TARGET_PORT = 443


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=30, help="seconds")
    parser.add_argument("--requests-per-tick", type=int, default=60)
    args = parser.parse_args()

    print(f"Simulating DDoS burst against {TARGET_PATH} ({TARGET_IP}) "
          f"for {args.duration}s")

    end_time = time.time() + args.duration
    tick = 0
    while time.time() < end_time:
        tick += 1
        # Latency and error rate degrade as the burst continues, simulating
        # the target actually struggling under load - this is part of the
        # signal, not just raw volume.
        progress = min(1.0, tick / 20)
        latency = int(100 + progress * 3900)       # 100ms -> ~4000ms
        error_chance = 0.02 + progress * 0.5        # rising 5xx rate

        for _ in range(args.requests_per_tick):
            src_ip = random_public_ip()  # new distinct IP almost every request
            byte_count = random.randint(40, 300)

            status = 503 if random.random() < error_chance else 200

            emit_app(
                client_ip=src_ip,
                method="GET",
                path=TARGET_PATH,
                status=status,
                response_bytes=byte_count,
                latency_ms=latency,
            )
            emit_firewall(
                src_ip=src_ip, dst_ip=TARGET_IP, dst_port=TARGET_PORT,
                protocol="TCP", action="ALLOW", byte_count=byte_count,
            )
            if random.random() < 0.3:
                emit_cloud(
                    src_ip=src_ip, dst_ip=TARGET_IP, dst_port=TARGET_PORT,
                    protocol="TCP", action="ACCEPT", byte_count=byte_count,
                )

        time.sleep(0.5)

    print("DDoS burst simulation complete.")


if __name__ == "__main__":
    main()
