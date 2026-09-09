"""
Shared helpers for the log generator scripts. Each generate_*.py script
writes raw, source-specific JSON lines that Data Prepper then normalizes.
"""

import ipaddress
import json
import random
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

FIREWALL_LOG = OUTPUT_DIR / "firewall.log"
CLOUD_LOG = OUTPUT_DIR / "cloud.log"
APP_LOG = OUTPUT_DIR / "app.log"

# "Protected" internal assets - the things traffic is sent to/attacks target.
INTERNAL_ASSETS = [
    {"ip": "10.20.1.5", "port": 443, "name": "web-frontend"},
    {"ip": "10.20.1.6", "port": 22, "name": "bastion-host"},
    {"ip": "10.20.2.5", "port": 5432, "name": "prod-db"},
    {"ip": "10.20.2.6", "port": 3306, "name": "legacy-mysql"},
]

API_ENDPOINTS = [
    "/", "/login", "/api/orders", "/api/checkout", "/api/users",
    "/api/products", "/health", "/static/app.js",
]


def random_public_ip() -> str:
    while True:
        ip = ipaddress.IPv4Address(random.randint(1, 2**32 - 1))
        if ip.is_global and not ip.is_multicast:
            return str(ip)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def write_line(path: Path, record: dict) -> None:
    with path.open("a") as f:
        f.write(json.dumps(record) + "\n")


def emit_firewall(src_ip: str, dst_ip: str, dst_port: int, protocol: str,
                   action: str, byte_count: int, src_port: int | None = None) -> None:
    write_line(FIREWALL_LOG, {
        "timestamp": now_iso(),
        "src_ip": src_ip,
        "src_port": src_port or random.randint(1024, 65535),
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "action": action,
        "bytes": byte_count,
    })


def emit_cloud(src_ip: str, dst_ip: str, dst_port: int, protocol: str,
               action: str, byte_count: int, src_port: int | None = None) -> None:
    write_line(CLOUD_LOG, {
        "eventTime": now_iso(),
        "sourceIPAddress": src_ip,
        "sourcePort": src_port or random.randint(1024, 65535),
        "destinationIPAddress": dst_ip,
        "destinationPort": dst_port,
        "protocolName": protocol,
        "bytesTransferred": byte_count,
        "actionTaken": action,
    })


def emit_app(client_ip: str, method: str, path: str, status: int,
             response_bytes: int, latency_ms: int) -> None:
    write_line(APP_LOG, {
        "time": now_iso(),
        "client_ip": client_ip,
        "method": method,
        "path": path,
        "status": status,
        "response_bytes": response_bytes,
        "latency_ms": latency_ms,
    })
