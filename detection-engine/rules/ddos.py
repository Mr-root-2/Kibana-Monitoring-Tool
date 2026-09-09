"""
Detection: DDoS (application-layer volumetric).

Deliberately NOT a single "requests > N" threshold. Combines multiple
signals against a per-target url.path, comparing the current short window
to a longer baseline window:

  - Traffic rate spike       (current req/min vs baseline req/min)
  - Source IP cardinality    (many distinct attackers, not one)
  - Target concentration     (traffic aimed at one endpoint)
  - Latency increase         (event.duration_ms average, current vs baseline)
  - 5xx error rate increase  (current vs baseline)

A finding only fires when enough of these signals agree - see EVIDENCE
scoring below. This mirrors the "possible application layer DDoS" incident
shape from docs/DETECTION_USE_CASES.md.

Operational note: this detector should run on a regular schedule (e.g. every
1-2 minutes via cron) so CURRENT_WINDOW_MINUTES stays tight relative to real
time. If run ad hoc with a large gap since the traffic was generated, widen
CURRENT_WINDOW_MINUTES/BASELINE_WINDOW_MINUTES to cover that gap, or nothing
will be found (target-path discovery depends on data existing within
CURRENT_WINDOW_MINUTES of "now").
"""

from opensearch_client import EVENTS_INDEX_PATTERN, get_client

CURRENT_WINDOW_MINUTES = 5
BASELINE_WINDOW_MINUTES = 30

RATE_SPIKE_MULTIPLIER = 10       # current rate vs baseline rate
MIN_UNIQUE_SOURCE_IPS = 200      # cardinality threshold in current window
LATENCY_INCREASE_MULTIPLIER = 3  # current avg latency vs baseline avg latency
ERROR_RATE_INCREASE_ABS = 0.1    # +10 percentage points 5xx rate vs baseline


def _stats_for_window(client, path: str, minutes_ago_start: int, minutes_ago_end: int) -> dict:
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"url.path": path}},
                    {"range": {"@timestamp": {
                        "gte": f"now-{minutes_ago_start}m",
                        "lt": f"now-{minutes_ago_end}m" if minutes_ago_end else "now",
                    }}},
                ]
            }
        },
        "aggs": {
            "unique_sources": {"cardinality": {"field": "source.ip"}},
            "avg_latency": {"avg": {"field": "event.duration_ms"}},
            "server_errors": {
                "filter": {"range": {"http.response.status_code": {"gte": 500}}}
            }
        }
    }
    resp = client.search(index=EVENTS_INDEX_PATTERN, body=query)
    total = resp["hits"]["total"]["value"]
    aggs = resp["aggregations"]
    window_len = minutes_ago_start - minutes_ago_end
    return {
        "total": total,
        "rate_per_min": total / window_len if window_len else 0,
        "unique_sources": aggs["unique_sources"]["value"],
        "avg_latency_ms": aggs["avg_latency"]["value"] or 0,
        "error_rate": (aggs["server_errors"]["doc_count"] / total) if total else 0,
    }


def _distinct_target_paths(client) -> list[str]:
    query = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{CURRENT_WINDOW_MINUTES}m"}}},
        "aggs": {"paths": {"terms": {"field": "url.path", "size": 50}}},
    }
    resp = client.search(index=EVENTS_INDEX_PATTERN, body=query)
    return [b["key"] for b in resp["aggregations"]["paths"]["buckets"]]


def detect() -> list[dict]:
    return detect_with_client(get_client())


def detect_with_client(client) -> list[dict]:
    """Same logic as detect(), but takes a client so it can be unit tested
    with a mock instead of a live OpenSearch connection."""
    findings = []

    for path in _distinct_target_paths(client):
        current = _stats_for_window(client, path, CURRENT_WINDOW_MINUTES, 0)
        baseline = _stats_for_window(
            client, path,
            CURRENT_WINDOW_MINUTES + BASELINE_WINDOW_MINUTES,
            CURRENT_WINDOW_MINUTES,
        )

        if baseline["rate_per_min"] <= 0:
            continue  # no baseline to compare against yet

        evidence = []
        rate_multiplier = current["rate_per_min"] / baseline["rate_per_min"]
        if rate_multiplier >= RATE_SPIKE_MULTIPLIER:
            evidence.append(f"traffic {rate_multiplier:.0f}x above baseline")

        if current["unique_sources"] >= MIN_UNIQUE_SOURCE_IPS:
            evidence.append(f"{current['unique_sources']} unique source IPs")

        if baseline["avg_latency_ms"] > 0 and \
                current["avg_latency_ms"] >= baseline["avg_latency_ms"] * LATENCY_INCREASE_MULTIPLIER:
            evidence.append(
                f"latency {current['avg_latency_ms']:.0f}ms vs baseline "
                f"{baseline['avg_latency_ms']:.0f}ms"
            )

        if current["error_rate"] - baseline["error_rate"] >= ERROR_RATE_INCREASE_ABS:
            evidence.append(
                f"5xx rate {current['error_rate']:.0%} vs baseline "
                f"{baseline['error_rate']:.0%}"
            )

        # Require at least 3 of 4 signals to agree before calling it DDoS.
        if len(evidence) >= 3:
            findings.append({
                "type": "ddos",
                "target_path": path,
                "confidence": "high" if len(evidence) == 4 else "medium",
                "evidence": evidence,
                "current_rate_per_min": round(current["rate_per_min"], 1),
                "baseline_rate_per_min": round(baseline["rate_per_min"], 1),
                "unique_source_ips": current["unique_sources"],
            })

    return findings


if __name__ == "__main__":
    for f in detect():
        print(f)
