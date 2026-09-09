#!/usr/bin/env python3
"""
Phase 4 - Brute force login simulation.

One source IP produces many failed login attempts against one application
endpoint within a short window. Detection signal: same source.ip -> more
than N failed logins (401) within 5 minutes.

Usage:
    python generate_bruteforce.py
"""

import random
import time

from common import emit_app, random_public_ip

LOGIN_PATH = "/login"
ATTEMPT_COUNT = 35  # comfortably above the >20-in-5-minutes threshold


def main() -> None:
    attacker_ip = random_public_ip()
    print(f"Simulating brute force login: {attacker_ip} -> {LOGIN_PATH} "
          f"({ATTEMPT_COUNT} attempts)")

    for i in range(ATTEMPT_COUNT):
        # Mostly failed (401), the occasional lucky-looking 200 to make it
        # slightly less obviously synthetic.
        status = 401 if random.random() > 0.05 else 200
        emit_app(
            client_ip=attacker_ip,
            method="POST",
            path=LOGIN_PATH,
            status=status,
            response_bytes=random.randint(80, 300),
            latency_ms=random.randint(50, 150),
        )
        time.sleep(random.uniform(2, 6))  # spread across ~2-3 minutes

    print("Brute force simulation complete.")


if __name__ == "__main__":
    main()
