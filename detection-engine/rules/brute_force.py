"""
Detection: Brute force login.

Signal: same source.ip produces more than FAILED_LOGIN_THRESHOLD failed
logins (http.response.status_code == 401) against url.path == "/login"
within LOOKBACK_MINUTES.
"""

from opensearch_client import EVENTS_INDEX_PATTERN, get_client

LOOKBACK_MINUTES = 5
FAILED_LOGIN_THRESHOLD = 20
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
                    {"term": {"http.response.status_code": 401}},
                ]
            }
        },
        "aggs": {
            "by_source": {
                "terms": {"field": "source.ip", "size": 1000},
            }
        }
    }
    resp = client.search(index=EVENTS_INDEX_PATTERN, body=query)

    findings = []
    for bucket in resp["aggregations"]["by_source"]["buckets"]:
        failed_count = bucket["doc_count"]
        if failed_count > FAILED_LOGIN_THRESHOLD:
            findings.append({
                "type": "brute_force",
                "source_ip": bucket["key"],
                "failed_login_count": failed_count,
                "window_minutes": LOOKBACK_MINUTES,
                "confidence": "high" if failed_count > FAILED_LOGIN_THRESHOLD * 2 else "medium",
            })
    return findings


if __name__ == "__main__":
    for f in detect():
        print(f)
