"""
Phase 6 - Correlation / incident engine.

Combines findings from multiple rules into a single incident when they
point at the same target within the same time window, instead of
surfacing disconnected alerts. Example: a DDoS finding on /api/checkout
plus a rate spike seen in firewall/cloud data toward the same backing
IP within the same window becomes ONE incident, not two+ alerts.

This is intentionally simple (grouping by shared target), matching the
"first correlation" step in docs/LEARNING_PATH.md Phase 6. It can grow
into a rules-based correlation engine (like OpenSearch Security
Analytics' correlation rules) later.
"""

from dataclasses import dataclass, field


@dataclass
class Incident:
    incident_type: str
    target: str
    confidence: str
    evidence: list[str] = field(default_factory=list)
    contributing_findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "type": self.incident_type,
            "target": self.target,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "contributing_findings": self.contributing_findings,
        }


def _target_of(finding: dict) -> str | None:
    return (
        finding.get("target_path")
        or finding.get("target_ip")
        or finding.get("source_ip")
    )


def correlate(all_findings: list[dict]) -> list[Incident]:
    """
    Groups findings by shared target (target_path for DDoS-style findings,
    source_ip for attacker-centric findings) and merges same-target
    findings of different types into one incident.
    """
    by_target: dict[str, list[dict]] = {}
    for finding in all_findings:
        target = _target_of(finding)
        if not target:
            continue
        by_target.setdefault(target, []).append(finding)

    incidents = []
    for target, findings in by_target.items():
        types = sorted({f["type"] for f in findings})
        confidences = [f.get("confidence", "medium") for f in findings]
        overall_confidence = "high" if "high" in confidences else "medium"

        evidence = []
        for f in findings:
            if "evidence" in f:
                evidence.extend(f["evidence"])
            else:
                evidence.append(f"{f['type']} finding on {target}")

        incidents.append(Incident(
            incident_type=" + ".join(types) if len(types) > 1 else types[0],
            target=target,
            confidence=overall_confidence,
            evidence=evidence,
            contributing_findings=findings,
        ))

    return incidents


if __name__ == "__main__":
    # Small smoke test with synthetic findings.
    sample_findings = [
        {"type": "ddos", "target_path": "/api/checkout", "confidence": "high",
         "evidence": ["traffic 50x above baseline", "8000 unique source IPs"]},
        {"type": "port_scan", "source_ip": "203.0.113.9", "confidence": "medium",
         "distinct_ports": 25},
    ]
    for incident in correlate(sample_findings):
        print(incident.to_dict())
