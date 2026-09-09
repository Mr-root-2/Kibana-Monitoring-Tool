"""
Detection: SQL Injection.

Signal: requests containing known SQLi patterns in url.path from the same
source.ip. Matches common SQLi keywords/syntax: UNION, SELECT, DROP,
OR '1'='1, --, WAITFOR, xp_cmdshell, SLEEP, information_schema, etc.

Uses OpenSearch query_string with wildcards against url.path since it's
stored as keyword (exact match), so we search for substrings via the
security-findings approach: query all recent app events and check patterns
in Python for flexibility.
"""

import re

from opensearch_client import EVENTS_INDEX_PATTERN, get_client

LOOKBACK_MINUTES = 5
MIN_SQLI_REQUESTS = 3  # at least 3 SQLi attempts from same IP

SQLI_PATTERNS = [
    r"(?i)(union\s+(all\s+)?select)",
    r"(?i)(or\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
    r"(?i)(drop\s+table)",
    r"(?i)(insert\s+into)",
    r"(?i)(xp_cmdshell)",
    r"(?i)(waitfor\s+delay)",
    r"(?i)(sleep\s*\()",
    r"(?i)(information_schema)",
    r"(?i)(load_file\s*\()",
    r"(?i)(;\s*(select|drop|insert|update|delete|exec))",
    r"--\s*$",
    r"(?i)(having\s+1\s*=\s*1)",
]

_compiled = [re.compile(p) for p in SQLI_PATTERNS]


def _is_sqli(path: str) -> bool:
    return any(p.search(path) for p in _compiled)


def detect() -> list[dict]:
    client = get_client()
    # Use docvalue_fields rather than _source: Data Prepper stores documents
    # with nested JSON (url.path -> {"url": {"path": ...}}), so reading
    # _source["url.path"] would always miss. docvalue_fields returns the
    # values keyed by the flat dotted field name regardless of _source shape.
    query = {
        "size": 5000,
        "_source": False,
        "docvalue_fields": ["source.ip", "url.path"],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_MINUTES}m"}}},
                    {"exists": {"field": "url.path"}},
                ]
            }
        }
    }
    resp = client.search(index=EVENTS_INDEX_PATTERN, body=query)

    # Group SQLi hits by source IP. docvalue_fields returns each field as a
    # list (one entry per value), so take the first element.
    sqli_by_ip: dict[str, list[str]] = {}
    for hit in resp["hits"]["hits"]:
        fields = hit.get("fields", {})
        path_values = fields.get("url.path", [])
        ip_values = fields.get("source.ip", [])
        path = path_values[0] if path_values else ""
        ip = ip_values[0] if ip_values else ""
        if ip and path and _is_sqli(path):
            sqli_by_ip.setdefault(ip, []).append(path)

    findings = []
    for ip, paths in sqli_by_ip.items():
        if len(paths) >= MIN_SQLI_REQUESTS:
            findings.append({
                "type": "sql_injection",
                "source_ip": ip,
                "sqli_request_count": len(paths),
                "sample_payloads": paths[:5],
                "window_minutes": LOOKBACK_MINUTES,
                "confidence": "high" if len(paths) >= 8 else "medium",
            })
    return findings


if __name__ == "__main__":
    for f in detect():
        print(f)
