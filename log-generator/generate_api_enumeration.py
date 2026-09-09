#!/usr/bin/env python3
"""
Phase 4 - API enumeration simulation.

One source IP probes many distinct endpoints (including guessed/nonexistent
ones), generating a high rate of 401/403/404 responses. Detection signal:
same source.ip -> many unique url.path values + high error-response ratio
within a short window.

Usage:
    python generate_api_enumeration.py
"""

import random
import time

from common import emit_app, random_public_ip

GUESSED_PATHS = [
    "/api/users", "/api/users/1", "/api/users/2", "/api/admin",
    "/api/config", "/api/v1/orders", "/api/v2/orders", "/api/internal",
    "/api/debug", "/api/backup", "/.env", "/.git/config",
    "/api/orders/export", "/api/keys", "/api/tokens", "/wp-admin",
    "/admin", "/api/health/debug", "/api/users/export", "/api/reports",
    "/api/v1/users/me", "/api/settings", "/api/logs", "/api/metrics",
    "/api/session", "/api/payments", "/api/payments/refund",
]


def main() -> None:
    attacker_ip = random_public_ip()
    print(f"Simulating API enumeration: {attacker_ip} "
          f"({len(GUESSED_PATHS)} endpoints)")

    for path in GUESSED_PATHS:
        status = random.choices([403, 404, 401, 200], weights=[3, 5, 2, 1])[0]
        emit_app(
            client_ip=attacker_ip,
            method=random.choice(["GET", "POST"]),
            path=path,
            status=status,
            response_bytes=random.randint(50, 200),
            latency_ms=random.randint(40, 120),
        )
        time.sleep(random.uniform(0.3, 1.5))

    print("API enumeration simulation complete.")


if __name__ == "__main__":
    main()
