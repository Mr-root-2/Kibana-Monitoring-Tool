# Detection Use Cases

## Detection 1: Port Scan
- **Signal:** same `source.ip` accesses more than 20 distinct `destination.port` values within 5 minutes
  (widened from the textbook "1 minute" to account for realistic ingestion lag between the log generator writing lines and Data Prepper's tail picking them up)
- **Rule:** `detection-engine/rules/port_scan.py`
- **Generator to test:** `log-generator/generate_portscan.py`

## Detection 2: Brute Force
- **Signal:** same `source.ip` produces more than 20 failed logins (`http.response.status_code: 401` on `url.path: /login`) within 5 minutes
- **Rule:** `detection-engine/rules/brute_force.py`
- **Generator to test:** `log-generator/generate_bruteforce.py`

## Detection 3: API Enumeration
- **Signal:** same `source.ip` accesses more than 10 distinct `url.path` values AND more than 60% of responses are 401/403/404, within 5 minutes
- **Rule:** `detection-engine/rules/api_enumeration.py`
- **Generator to test:** `log-generator/generate_api_enumeration.py`

## Detection 4: DDoS (application-layer)
Not a single request-count threshold. Requires at least 3 of these 4 signals
to agree, comparing a 5-minute current window against a 30-minute baseline
on the same `url.path`:

- Traffic rate ≥10x baseline
- ≥200 unique `source.ip` values in the current window
- Average latency (`event.duration_ms`) ≥3x baseline
- 5xx error rate increase ≥10 percentage points vs baseline

- **Rule:** `detection-engine/rules/ddos.py`
- **Generator to test:** `log-generator/generate_ddos.py`
- **Unit tests (mocked, deterministic):** `detection-engine/rules/test_ddos.py`

### Operational timing note (learned the hard way)
All these rules depend on relative time windows (`now-Xm`). When testing
manually in the sandbox:
- **Data Prepper ingestion has real lag** (roughly 15-30s between a
  generator writing a line and it landing in OpenSearch) - don't run
  detection immediately after a generator finishes.
- **The baseline window needs genuinely quiet time before the baseline
  window and the attack window overlap.** If you run a 2-minute normal
  traffic burst immediately followed by an attack, and the baseline window
  is wider than that gap, the baseline stats will include the attack
  traffic itself and dilute the signal. Leave a real gap (a minute or more)
  between generating baseline traffic and triggering an attack, or widen
  the windows to match your test's actual timeline.
- For production use, these detectors should run on a fixed schedule (e.g.
  every 1-2 minutes via cron) so the "current window" stays meaningfully
  tight relative to when it runs - not run ad hoc minutes after the fact.

Example incident produced when this fires:
```json
{
  "type": "ddos",
  "target_path": "/api/checkout",
  "confidence": "high",
  "evidence": [
    "traffic 50x above baseline",
    "8000 unique source IPs",
    "latency 4000ms vs baseline 100ms",
    "5xx rate 45% vs baseline 2%"
  ],
  "current_rate_per_min": 25000,
  "baseline_rate_per_min": 500,
  "unique_source_ips": 8000
}
```

## Correlation
`detection-engine/correlation/incident_engine.py` groups findings that
share the same target (`target_path` for DDoS-style findings, `source_ip`
for attacker-centric findings) into one incident, so a DDoS finding and a
related port scan on the same target don't show up as two disconnected
alerts.

## Deferred: native OpenSearch detection plugins
Once the above rules work and their logic is understood, the natural next
step is comparing them against OpenSearch's own **Security Analytics**
(Sigma rules + correlation engine) and **Anomaly Detection** (RCF) plugins -
see the earlier discussion in this project's chat history for why ECS was
chosen specifically to make that migration path smooth. Not part of the
initial build.
