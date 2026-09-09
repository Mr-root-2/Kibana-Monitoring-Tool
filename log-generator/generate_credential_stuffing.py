#!/usr/bin/env python3
"""
Credential stuffing attack simulation.

Unlike brute force (one IP, many attempts), credential stuffing uses
MANY different source IPs each making a small number of login attempts
with leaked username/password combos. Detection signal: many distinct
source IPs hitting /login with high failure rate in a short window,
but each individual IP has only 1-3 attempts (below brute force threshold).

Usage:
    python generate_credential_stuffing.py
"""

import random
import time

from common import emit_app, random_public_ip

LOGIN_PATH = "/login"
ATTACKER_COUNT = 50  # many distinct IPs (botnet)
ATTEMPTS_PER_IP = random.randint(1, 3)


def main() -> None:
    print(f"Simulating credential stuffing: {ATTACKER_COUNT} distinct IPs, "
          f"1-3 attempts each")

    for i in range(ATTACKER_COUNT):
        src_ip = random_public_ip()
        attempts = random.randint(1, 3)
        for _ in range(attempts):
            # Most fail (stolen credentials often expired/changed)
            status = 401 if random.random() > 0.03 else 200
            emit_app(
                client_ip=src_ip,
                method="POST",
                path=LOGIN_PATH,
                status=status,
                response_bytes=random.randint(80, 300),
                latency_ms=random.randint(50, 200),
            )
            time.sleep(random.uniform(0.1, 0.5))

    print("Credential stuffing simulation complete.")


if __name__ == "__main__":
    main()
