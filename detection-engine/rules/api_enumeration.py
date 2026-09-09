"""
Detection: API enumeration.

Signal: same source.ip accesses many distinct url.path values AND generates
a high proportion of 401/403/404 responses, within LOOKBACK_MINUTES.
Distinguishes this from brute force (one endpoint, many attempts) by
requiring high path cardinality instead.
"""

from opensearch_client import EVENTS_INDEX_PATTERN, get_client

LOOKBACK_MINUTES = 5
DISTINCT_PATH_THRESHOLD = 10
ERROR_RATIO_THRESHOLD = 0.6
ERROR_STATUS_CODES = [401, 403, 404]


def detect() -> list[dict]:
    client = get_client()
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{LOOKBACK_MINUTES}m"}}},
                    {"exists": {"field": "url.path"}},
                ]
            }
        },
        "aggs": {
            "by_source": {
                "terms": {"field": "source.ip", "size": 1000},
                "aggs": {
                    "distinct_paths": {"cardinality": {"field": "url.path"}},
                    "error_responses": {
                        "filter": {
                            "terms": {"http.response.status_code": ERROR_STATUS_CODES}
                        }
                    }
                }
            }
        }
    }
    resp = client.search(index=EVENTS_INDEX_PATTERN, body=query)

    findings = []
    for bucket in resp["aggregations"]["by_source"]["buckets"]:
        total = bucket["doc_count"]
        distinct_paths = bucket["distinct_paths"]["value"]
        error_count = bucket["error_responses"]["doc_count"]
        error_ratio = error_count / total if total else 0

        if distinct_paths > DISTINCT_PATH_THRESHOLD and error_ratio > ERROR_RATIO_THRESHOLD:
            findings.append({
                "type": "api_enumeration",
                "source_ip": bucket["key"],
                "distinct_paths": distinct_paths,
                "error_ratio": round(error_ratio, 2),
                "window_minutes": LOOKBACK_MINUTES,
                "confidence": "high" if distinct_paths > DISTINCT_PATH_THRESHOLD * 1.5 else "medium",
            })
    return findings


if __name__ == "__main__":
    for f in detect():
        print(f)
