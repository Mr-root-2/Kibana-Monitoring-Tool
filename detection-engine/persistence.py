"""
Persist findings and incidents to OpenSearch so they can be visualized in
OpenSearch Dashboards (Phase 7), rather than only printed to stdout.

Writes to security-findings-YYYY.MM.dd and security-incidents-YYYY.MM.dd,
matching the index templates in opensearch/index-template-security-*.json.
"""

from datetime import datetime, timezone

from opensearch_client import FINDINGS_INDEX, INCIDENTS_INDEX, get_client


def _today_index(base_name: str) -> str:
    date_suffix = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    return f"{base_name}-{date_suffix}"


def persist_findings(client, findings: list[dict]) -> None:
    if not findings:
        return
    index = _today_index(FINDINGS_INDEX)
    now = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        doc = dict(finding)
        doc["@timestamp"] = now
        client.index(index=index, body=doc)


def persist_incidents(client, incidents: list) -> None:
    if not incidents:
        return
    index = _today_index(INCIDENTS_INDEX)
    now = datetime.now(timezone.utc).isoformat()
    for incident in incidents:
        doc = incident.to_dict()
        doc["@timestamp"] = now
        doc["finding_count"] = len(doc.pop("contributing_findings", []))
        doc["finding_types"] = doc["type"].split(" + ")
        client.index(index=index, body=doc)


def persist_all(findings: list[dict], incidents: list) -> None:
    client = get_client()
    persist_findings(client, findings)
    persist_incidents(client, incidents)
