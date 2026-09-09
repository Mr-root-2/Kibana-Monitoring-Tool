"""
Detection: DDoS subtype classifier.

Classifies a detected DDoS into one of three types based on traffic
characteristics:

  - VOLUMETRIC (bandwidth flood): high total bytes, large average packet
    size (>500 bytes), primarily UDP. NTP/DNS amplification, UDP flood.
  - PROTOCOL (connection flood): high packet count, small average packet
    size (<200 bytes), primarily TCP. SYN flood, ACK flood.
  - APPLICATION (request flood): high HTTP request count, normal packet
    size, mixed latency/5xx. HTTP flood, Slowloris.

Runs AFTER the main ddos.py rule fires — takes the same target and
window, but adds a subtype classification.
"""

from opensearch_client import EVENTS_INDEX_PATTERN, get_client

LOOKBACK_MINUTES = 5
MIN_EVENTS_TO_CLASSIFY = 100  # need enough data to make a meaningful classification


def _discover_target_ips(client) -> list[str]:
    """Find destination IPs receiving unusually high traffic in the current window.

    Returns IPs with >MIN_EVENTS_TO_CLASSIFY events, sorted by volume descending.
    This replaces the old hardcoded target_ip approach.
    """
    query = {
        "size": 0,
        "query": {
            "range": {"@timestamp": {"gte": f"now-{LOOKBACK_MINUTES}m"}}
        },
        "aggs": {
            "top_targets": {
                "terms": {"field": "destination.ip", "size": 10, "order": {"_count": "desc"}}
            }
        }
    }
    resp = client.search(index=EVENTS_INDEX_PATTERN, body=query)
    return [
        bucket["key"]
        for bucket in resp["aggregations"]["top_targets"]["buckets"]
        if bucket["doc_count"] >= MIN_EVENTS_TO_CLASSIFY
    ]


def _classify_target(client, target_ip: str) -> dict | None:
    """Classify the DDoS subtype for a single target IP."""
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_MINUTES}m"}}},
                    {"term": {"destination.ip": target_ip}},
                ]
            }
        },
        "aggs": {
            "by_protocol": {
                "terms": {"field": "network.protocol", "size": 10}
            },
            "avg_bytes": {"avg": {"field": "network.bytes"}},
            "total_bytes": {"sum": {"field": "network.bytes"}},
            "unique_sources": {"cardinality": {"field": "source.ip"}},
            "has_http": {
                "filter": {"exists": {"field": "http.request.method"}}
            },
            "avg_latency": {
                "avg": {"field": "event.duration_ms"}
            }
        }
    }
    resp = client.search(index=EVENTS_INDEX_PATTERN, body=query)
    total = resp["hits"]["total"]["value"]

    if total < MIN_EVENTS_TO_CLASSIFY:
        return None

    aggs = resp["aggregations"]
    avg_bytes = aggs["avg_bytes"]["value"] or 0
    total_bytes = aggs["total_bytes"]["value"] or 0
    unique_sources = aggs["unique_sources"]["value"]
    http_count = aggs["has_http"]["doc_count"]
    http_ratio = http_count / total if total else 0

    # Protocol breakdown
    protocols = {b["key"]: b["doc_count"] for b in aggs["by_protocol"]["buckets"]}
    tcp_count = protocols.get("TCP", 0)
    udp_count = protocols.get("UDP", 0)
    tcp_ratio = tcp_count / total if total else 0
    udp_ratio = udp_count / total if total else 0

    # Classification logic
    evidence = []
    ddos_subtype = "unknown"

    if udp_ratio > 0.6 and avg_bytes > 500:
        ddos_subtype = "volumetric"
        evidence = [
            f"UDP dominant ({udp_ratio:.0%} of traffic)",
            f"Large avg packet size ({avg_bytes:.0f} bytes)",
            f"Total bandwidth: {total_bytes / 1_000_000:.1f} MB",
            f"{unique_sources} unique source IPs",
        ]
    elif tcp_ratio > 0.6 and avg_bytes < 200 and http_ratio < 0.2:
        ddos_subtype = "protocol_syn_flood"
        evidence = [
            f"TCP dominant ({tcp_ratio:.0%} of traffic)",
            f"Small avg packet size ({avg_bytes:.0f} bytes — SYN-sized)",
            f"Low HTTP ratio ({http_ratio:.0%} — not application layer)",
            f"{unique_sources} unique source IPs",
        ]
    elif http_ratio > 0.3:
        ddos_subtype = "application_layer"
        avg_latency = aggs["avg_latency"]["value"] or 0
        evidence = [
            f"High HTTP request ratio ({http_ratio:.0%})",
            f"Avg latency: {avg_latency:.0f}ms",
            f"{unique_sources} unique source IPs",
            f"Avg bytes: {avg_bytes:.0f}",
        ]
    else:
        ddos_subtype = "mixed"
        evidence = [
            f"TCP: {tcp_ratio:.0%}, UDP: {udp_ratio:.0%}",
            f"Avg bytes: {avg_bytes:.0f}",
            f"HTTP ratio: {http_ratio:.0%}",
            f"{unique_sources} unique source IPs",
        ]

    return {
        "type": f"ddos_{ddos_subtype}",
        "target_ip": target_ip,
        "ddos_subtype": ddos_subtype,
        "total_events": total,
        "unique_source_ips": unique_sources,
        "evidence": evidence,
        "confidence": "high" if unique_sources > 200 else "medium",
    }


def classify(target_ips: list[str] | None = None) -> list[dict]:
    """Classify DDoS subtypes for target IPs.

    Args:
        target_ips: Specific IPs to classify. If None, automatically discovers
                    destination IPs with high traffic volume in the current window.
    """
    client = get_client()

    if target_ips is None:
        target_ips = _discover_target_ips(client)

    findings = []
    for ip in target_ips:
        result = _classify_target(client, ip)
        if result:
            findings.append(result)

    return findings


if __name__ == "__main__":
    for f in classify():
        print(f)
