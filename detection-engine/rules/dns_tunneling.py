"""
Detection: DNS Tunneling.

Signal: a single source.ip sending many connections to destination.port 53
with abnormally high average network.bytes. Normal DNS queries are
~100-300 bytes; tunneling pushes 500-3000+ bytes per "query" as data is
encoded into DNS payloads.

Threshold: more than QUERY_COUNT queries to port 53 with average bytes
above AVG_BYTES_THRESHOLD within LOOKBACK_MINUTES.
"""

from opensearch_client import EVENTS_INDEX_PATTERN, get_client

LOOKBACK_MINUTES = 5
QUERY_COUNT_THRESHOLD = 30  # at least 30 DNS "queries"
AVG_BYTES_THRESHOLD = 400   # normal DNS is ~100-300 bytes


def detect() -> list[dict]:
    client = get_client()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_MINUTES}m"}}},
                    {"term": {"destination.port": 53}},
                ]
            }
        },
        "aggs": {
            "by_source": {
                "terms": {"field": "source.ip", "size": 1000},
                "aggs": {
                    "avg_bytes": {"avg": {"field": "network.bytes"}},
                    "dst_ips": {"cardinality": {"field": "destination.ip"}},
                }
            }
        }
    }
    resp = client.search(index=EVENTS_INDEX_PATTERN, body=query)

    findings = []
    for bucket in resp["aggregations"]["by_source"]["buckets"]:
        count = bucket["doc_count"]
        avg_bytes = bucket["avg_bytes"]["value"] or 0
        dst_count = bucket["dst_ips"]["value"]

        if count >= QUERY_COUNT_THRESHOLD and avg_bytes >= AVG_BYTES_THRESHOLD:
            findings.append({
                "type": "dns_tunneling",
                "source_ip": bucket["key"],
                "query_count": count,
                "avg_bytes_per_query": round(avg_bytes, 1),
                "destination_ip_count": dst_count,
                "window_minutes": LOOKBACK_MINUTES,
                "confidence": "high" if avg_bytes > 800 else "medium",
            })
    return findings


if __name__ == "__main__":
    for f in detect():
        print(f)
