#!/usr/bin/env python3
"""
Detection engine entry point.

Runs each detection rule once, prints findings, then runs correlation
across the findings to surface incidents. Run this repeatedly (e.g. via a
loop or cron) while the log generators are producing traffic.

Usage:
    python main.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "rules"))

from correlation.incident_engine import correlate
from persistence import persist_all
from rules import api_enumeration, brute_force, credential_stuffing, ddos, ddos_classifier, dns_tunneling, port_scan, sqli


def main() -> None:
    all_findings = []

    for module, name in [
        (port_scan, "port_scan"),
        (brute_force, "brute_force"),
        (api_enumeration, "api_enumeration"),
        (sqli, "sql_injection"),
        (credential_stuffing, "credential_stuffing"),
        (dns_tunneling, "dns_tunneling"),
        (ddos, "ddos"),
        (ddos_classifier, "ddos_classifier"),
    ]:
        if hasattr(module, "detect"):
            findings = module.detect()
        elif hasattr(module, "classify"):
            findings = module.classify()
        else:
            findings = []
        print(f"[{name}] {len(findings)} finding(s)")
        for f in findings:
            print(f"  {json.dumps(f)}")
        all_findings.extend(findings)

    print("\n--- Correlation ---")
    incidents = correlate(all_findings)
    if not incidents:
        print("No incidents (no correlated findings).")
    for incident in incidents:
        print(json.dumps(incident.to_dict(), indent=2))

    persist_all(all_findings, incidents)
    print(f"\nPersisted {len(all_findings)} finding(s) and {len(incidents)} "
          f"incident(s) to OpenSearch.")


if __name__ == "__main__":
    main()
