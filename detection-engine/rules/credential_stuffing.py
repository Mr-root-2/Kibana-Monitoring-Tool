"""
Detection: Credential Stuffing.

Distinct from brute force: brute force = one IP, many attempts.
Credential stuffing = MANY distinct IPs, each with few attempts (1-3),
but a high collective failure rate on /login in a short window.

Signal: more than UNIQUE_IP_THRESHOLD distinct source IPs hitting /login
with >FAILURE_RATE_THRESHOLD failure rate within LOOKBACK_MINUTES, where
each individual IP has fewer than BRUTE_FORCE_CUTOFF attempts (otherwise
it's just brute force).
"""

from opensearch_client import EVENTS_INDEX_PATTERN, get_client

LOOKBACK_MINUTES = 5
UNIQUE_IP_THRESHOLD = 20  # at least 20 distinct IPs participating
FAILURE_RATE_THRESHOLD = 0.8  # 80% of login attempts fail
BRUTE_FORCE_CUTOFF = 5  # exclude IPs with >5 attempts (those are brute force)
LOGIN_PATH = "/login"


def detect() -> list[dict]:
    client = get_client()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_MINUTES}m"}}},
                    {"term": {"url.path": LOGIN_PATH}},
                    {"term": {"http.request.method": "POST"}},
                ]
            }
        },
        "aggs": {
            "by_source": {
                "terms": {"field": "source.ip", "size": 5000},
                "aggs": {
                    "failures": {
                        "filter": {"term": {"http.response.status_code": 401}}
                    }
                }
            }
        }
    }
    resp = client.search(index=EVENTS_INDEX_PATTERN, body=query)

    # Filter to only IPs with few attempts (not brute force)
    stuffing_ips = []
    total_attempts = 0
    total_failures = 0
    for bucket in resp["aggregations"]["by_source"]["buckets"]:
        if bucket["doc_count"] <= BRUTE_FORCE_CUTOFF:
            stuffing_ips.append(bucket["key"])
            total_attempts += bucket["doc_count"]
            total_failures += bucket["failures"]["doc_count"]

    if len(stuffing_ips) < UNIQUE_IP_THRESHOLD:
        return []

    failure_rate = total_failures / total_attempts if total_attempts else 0
    if failure_rate < FAILURE_RATE_THRESHOLD:
        return []

    return [{
        "type": "credential_stuffing",
        "target_path": LOGIN_PATH,
        "unique_source_ips": len(stuffing_ips),
        "total_attempts": total_attempts,
        "failure_rate": round(failure_rate, 2),
        "window_minutes": LOOKBACK_MINUTES,
        "confidence": "high" if len(stuffing_ips) >= 40 else "medium",
    }]


if __name__ == "__main__":
    for f in detect():
        print(f)
