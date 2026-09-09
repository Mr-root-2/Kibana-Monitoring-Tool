"""
Unit test for the DDoS detection logic, using a mocked OpenSearch client so
the test is deterministic and doesn't depend on live timing/data (unlike
manual sandbox testing, where the baseline window can overlap with the
attack window if the whole test is compressed into a few minutes - see
docs/DETECTION_USE_CASES.md for that caveat).

Run:
    python3 -m pytest rules/test_ddos.py -v
"""

from unittest.mock import MagicMock

import rules.ddos as ddos


def _fake_stats_response(total, unique_sources, avg_latency, error_count):
    return {
        "hits": {"total": {"value": total}},
        "aggregations": {
            "unique_sources": {"value": unique_sources},
            "avg_latency": {"value": avg_latency},
            "server_errors": {"doc_count": error_count},
        },
    }


def test_ddos_fires_when_all_signals_present():
    client = MagicMock()

    # First call from _distinct_target_paths, then alternating
    # current/baseline calls for that one path.
    client.search.side_effect = [
        {"aggregations": {"paths": {"buckets": [{"key": "/api/checkout"}]}}},
        # current window: high rate, high cardinality, high latency, high errors
        _fake_stats_response(total=25000, unique_sources=8000, avg_latency=4000, error_count=11250),
        # baseline window: normal traffic
        _fake_stats_response(total=500, unique_sources=450, avg_latency=100, error_count=10),
    ]

    findings = ddos.detect_with_client(client)

    assert len(findings) == 1
    finding = findings[0]
    assert finding["type"] == "ddos"
    assert finding["target_path"] == "/api/checkout"
    assert finding["confidence"] == "high"
    assert len(finding["evidence"]) == 4


def test_ddos_does_not_fire_with_no_baseline():
    client = MagicMock()
    client.search.side_effect = [
        {"aggregations": {"paths": {"buckets": [{"key": "/api/checkout"}]}}},
        _fake_stats_response(total=25000, unique_sources=8000, avg_latency=4000, error_count=11250),
        _fake_stats_response(total=0, unique_sources=0, avg_latency=None, error_count=0),
    ]

    findings = ddos.detect_with_client(client)
    assert findings == []


def test_ddos_does_not_fire_with_only_one_signal():
    client = MagicMock()
    client.search.side_effect = [
        {"aggregations": {"paths": {"buckets": [{"key": "/api/checkout"}]}}},
        # Only rate is elevated; latency/errors/cardinality look normal.
        _fake_stats_response(total=6000, unique_sources=50, avg_latency=110, error_count=6),
        _fake_stats_response(total=500, unique_sources=45, avg_latency=100, error_count=5),
    ]

    findings = ddos.detect_with_client(client)
    assert findings == []


if __name__ == "__main__":
    test_ddos_fires_when_all_signals_present()
    test_ddos_does_not_fire_with_no_baseline()
    test_ddos_does_not_fire_with_only_one_signal()
    print("All tests passed.")
