"""
Detection: Port scan.

Signal: same source.ip accesses more than PORT_THRESHOLD distinct
destination.port values within LOOKBACK_MINUTES.

This is a two-level aggregation: bucket by source.ip, then count distinct
destination.port within each bucket (cardinality agg).
"""

from opensearch_client import EVENTS_INDEX_PATTERN, get_client

LOOKBACK_MINUTES = 5
PORT_THRESHOLD = 20


def detect() -> list[dict]:
    client = get_client()
    query = {
        "size": 0,
        "query": {
            "range": {"@timestamp": {"gte": f"now-{LOOKBACK_MINUTES}m"}}
        },
        "aggs": {
            "by_source": {
                "terms": {"field": "source.ip", "size": 1000},
                "aggs": {
                    "distinct_ports": {
                        "cardinality": {"field": "destination.port"}
                    }
                }
            }
        }
    }
    resp = client.search(index=EVENTS_INDEX_PATTERN, body=query)

    findings = []
    for bucket in resp["aggregations"]["by_source"]["buckets"]:
        distinct_ports = bucket["distinct_ports"]["value"]
        if distinct_ports > PORT_THRESHOLD:
            findings.append({
                "type": "port_scan",
                "source_ip": bucket["key"],
                "distinct_ports": distinct_ports,
                "window_minutes": LOOKBACK_MINUTES,
                "confidence": "high" if distinct_ports > PORT_THRESHOLD * 2 else "medium",
            })
    return findings


if __name__ == "__main__":
    for f in detect():
        print(f)
