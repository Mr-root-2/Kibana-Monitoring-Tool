"""
Shared OpenSearch connection for the detection engine. This intentionally
uses plain aggregation queries rather than OpenSearch's native Security
Analytics / Anomaly Detection plugins - see docs/LEARNING_PATH.md for why:
transparent, debuggable logic first, native plugins as a later enhancement.
"""

import os

from opensearchpy import OpenSearch

OPENSEARCH_HOST = os.environ.get("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.environ.get("OPENSEARCH_PORT", "9200"))
OPENSEARCH_USER = os.environ.get("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.environ.get("OPENSEARCH_PASSWORD", "Sbx-Monitor#2026!")

EVENTS_INDEX_PATTERN = "network-events-*"
FINDINGS_INDEX = "security-findings"
INCIDENTS_INDEX = "security-incidents"


def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False,
    )
