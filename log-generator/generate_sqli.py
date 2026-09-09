#!/usr/bin/env python3
"""
SQL Injection attack simulation.

Generates application-layer requests containing common SQL injection
payloads in the URL path or query parameters. Detection signal: requests
from the same source IP containing SQLi patterns in url.path.

Usage:
    python generate_sqli.py
"""

import random
import time

from common import emit_app, random_public_ip

SQLI_PAYLOADS = [
    "/api/users?id=1' OR '1'='1",
    "/api/users?id=1; DROP TABLE users--",
    "/api/orders?id=1 UNION SELECT * FROM passwords--",
    "/api/products?search=' OR 1=1--",
    "/login?user=admin'--&pass=x",
    "/api/users?id=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "/api/search?q='; EXEC xp_cmdshell('net user')--",
    "/api/products?category=1' WAITFOR DELAY '0:0:5'--",
    "/api/users?sort=name; INSERT INTO admin VALUES('hacker','pass')--",
    "/api/orders?filter=status%3D'pending' OR '1'%3D'1",
    "/api/users/1' HAVING 1=1--",
    "/api/checkout?promo=' UNION SELECT credit_card FROM payments--",
    "/api/search?q=test' AND SUBSTRING(@@version,1,1)='5",
    "/api/login' OR SLEEP(5)--",
    "/api/users?id=-1 UNION ALL SELECT username,password FROM admin_users--",
    "/api/products?id=1;SELECT LOAD_FILE('/etc/passwd')--",
]


def main() -> None:
    attacker_ip = random_public_ip()
    print(f"Simulating SQL injection: {attacker_ip} ({len(SQLI_PAYLOADS)} payloads)")

    for payload in SQLI_PAYLOADS:
        # SQLi usually gets mixed responses: some 200 (successful injection),
        # some 500 (syntax error in injected SQL), some 403 (WAF block)
        status = random.choices([200, 500, 403], weights=[3, 5, 2])[0]
        emit_app(
            client_ip=attacker_ip,
            method="GET",
            path=payload,
            status=status,
            response_bytes=random.randint(100, 2000),
            latency_ms=random.randint(80, 5000),  # some payloads cause slow queries
        )
        time.sleep(random.uniform(0.5, 2.0))

    print("SQL injection simulation complete.")


if __name__ == "__main__":
    main()
