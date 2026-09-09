# Learning Path

This is the order to build and learn this project in. Don't skip ahead -
each phase's success criteria is the input the next phase depends on.

## Phase 0 — Build the sandbox
Run OpenSearch + OpenSearch Dashboards + Data Prepper locally. No detection
logic yet.

**Success criteria:** `docker compose up` brings up all three containers
healthy, and you can log into Dashboards at http://localhost:5601.

## Phase 1 — One log source (firewall only)
Generate fake firewall logs, ingest with Data Prepper, confirm normalized
events land in OpenSearch as `source.ip`, `destination.ip`, etc.

**Success criteria:** query `network-events-firewall-*` in Dashboards Dev
Tools and see real documents with the common schema fields populated.

## Phase 2 — Add multiple sources (cloud, application)
Each source has a *different* raw field naming (`src_ip` vs `sourceIPAddress`
vs `client_ip`). The point of this phase is proving normalization works
across genuinely different formats, not just relabeling one format three
times.

**Success criteria:** all three sources land in indices sharing the same
`source.ip` / `destination.ip` field names and types, so a single query
across `network-events-*` returns consistent results regardless of origin.

## Phase 3 — Generate realistic normal traffic
Before any detection logic, the generator must produce a believable
baseline: varying request rates, many distinct source IPs, normal response
codes, multiple endpoints. Without this, anomaly/threshold detections can't
be validated - there's nothing to deviate from.

**Success criteria:** plotting request count per minute in Dashboards shows
a noisy but roughly stable baseline (e.g. 450-550 req/min), not a flat line
or pure randomness.

## Phase 4 — First detection rules (simple, rule-based)
Implement before touching DDoS:
- **Port scan**: same `source.ip` hits >20 distinct `destination.port` within 1 minute
- **Brute force**: same `source.ip` produces >20 failed logins within 5 minutes
- **API enumeration**: same `source.ip` hits many distinct endpoints with a high rate of 401/403/404 responses

These are simpler to validate than DDoS because the signal is a clear
threshold on a single dimension, not a multi-factor judgment call.

## Phase 5 — DDoS detection
Only after Phase 4 works. A DDoS verdict should combine multiple signals,
not a single request-count threshold:
- Traffic rate vs baseline (e.g. 50x normal)
- Unique source IP cardinality
- Concentration on one target/endpoint
- Downstream impact: latency increase, 5xx error rate increase

## Phase 6 — Correlation
Combine signals from multiple sources/pipelines (firewall traffic spike +
application latency spike + infra metric spike, all pointing at the same
target) into a single incident, rather than three disconnected alerts.

## Phase 7 — Investigation dashboard (done)
Built via `dashboards/create_dashboard.sh` - see
`dashboards/dashboard-configuration.md` for what's in it and how to
regenerate it. Requires `detection-engine/main.py` to have persisted at
least one run's findings/incidents to OpenSearch first (see Phase 4-6 for
how findings/incidents get written - `detection-engine/persistence.py`).

Source→destination geo mapping is a known gap - needs a `geoip` Data
Prepper processor added to the ingest pipelines first.

## What to defer
Native OpenSearch plugins (Security Analytics Sigma rules, Anomaly
Detection RCF) are a good enhancement *after* the custom Python detection
engine works and you understand what each detection is actually looking
for. Reaching for them first would skip the learning and hide the logic
behind a plugin UI you don't yet have the context to configure well.
