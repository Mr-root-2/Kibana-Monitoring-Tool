# Security Monitoring Tool (OpenSearch)

A local, throwaway sandbox for learning and building a multi-source security
monitoring pipeline: log ingestion → normalization → rule-based detection →
DDoS detection → correlation → investigation dashboard.

> Note: this stack uses **OpenSearch + OpenSearch Dashboards**, not Kibana.
> Kibana is Elastic's proprietary UI and doesn't run against OpenSearch.

Part of the broader initiative: **Centralized Security Monitoring & Attack
Detection – PoC**. This repo (`security-monitoring-sandbox`) is the
technical implementation.

## Stack

| Component | Purpose |
|---|---|
| OpenSearch | Storage + search engine |
| OpenSearch Dashboards | UI, visualizations |
| Data Prepper | Ingest pipelines: parse + normalize raw logs into a common ECS-style schema |
| Log generators (Python) | Simulate firewall/cloud/app traffic: normal baseline, port scan, brute force, credential stuffing, API enumeration, SQL injection, DNS tunneling, DDoS (volumetric + SYN flood) |
| Detection engine (Python) | Custom rule-based detections queried directly against OpenSearch, plus a correlation/incident layer |

## Why ECS, not OCSF

We normalize to ECS-style flat fields (`source.ip`, `destination.ip`, ...)
because OpenSearch's Security Analytics plugin (Sigma rules) expects that
shape natively. See `docs/DATA_SCHEMA.md` for the full reasoning and the
per-source field mappings.

## Quick start

```bash
docker compose up -d
```

Wait for OpenSearch to report healthy, then open OpenSearch Dashboards at
http://localhost:5601 (login: `admin` / see `.env`).

Apply the index templates once (before or after `docker compose up`):

```bash
for name in network-events security-findings security-incidents; do
  curl -sk -u admin:'<password from .env>' \
    -X PUT "https://localhost:9200/_index_template/${name}" \
    -H 'Content-Type: application/json' \
    -d @opensearch/index-template-${name}.json
done
```

Generate traffic (run these from `log-generator/`, no dependencies needed
beyond the Python standard library):

```bash
cd log-generator
python3 generate_normal_traffic.py --minutes 10   # baseline first, always
python3 generate_portscan.py
python3 generate_bruteforce.py
python3 generate_credential_stuffing.py
python3 generate_api_enumeration.py
python3 generate_sqli.py
python3 generate_dns_tunneling.py
python3 generate_ddos.py
python3 generate_ddos_volumetric.py
python3 generate_ddos_syn_flood.py
```

Run detections (from `detection-engine/`, requires `opensearch-py`):

```bash
cd detection-engine
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

## Project layout

```
.
├── docker-compose.yml
├── .env / .env.example
├── data-prepper/
│   ├── pipelines.yaml            # one pipeline per source, normalizing to ECS
│   └── data-prepper-config.yaml
├── opensearch/
│   ├── index-template-network-events.json
│   ├── index-template-security-findings.json
│   ├── index-template-security-incidents.json
│   └── detection-rules/          # future: Sigma rules for Security Analytics plugin
├── log-generator/
│   ├── common.py                 # shared helpers, per-source raw log emitters
│   ├── generate_normal_traffic.py
│   ├── generate_portscan.py
│   ├── generate_bruteforce.py
│   ├── generate_credential_stuffing.py
│   ├── generate_api_enumeration.py
│   ├── generate_sqli.py
│   ├── generate_dns_tunneling.py
│   ├── generate_ddos.py
│   ├── generate_ddos_volumetric.py
│   ├── generate_ddos_syn_flood.py
│   └── output/                   # generated raw logs (gitignored)
├── detection-engine/
│   ├── main.py                   # runs all rules + correlation + persists results
│   ├── opensearch_client.py
│   ├── persistence.py            # writes findings/incidents to OpenSearch
│   ├── rules/
│   │   ├── port_scan.py
│   │   ├── brute_force.py
│   │   ├── credential_stuffing.py
│   │   ├── api_enumeration.py
│   │   ├── sqli.py
│   │   ├── dns_tunneling.py
│   │   ├── ddos.py
│   │   ├── ddos_classifier.py
│   │   └── test_ddos.py          # unit tests (mocked, deterministic)
│   └── correlation/
│       └── incident_engine.py
├── dashboards/
│   ├── create_dashboard.sh       # builds index patterns + visualizations + dashboard
│   └── dashboard-configuration.md
└── docs/
    ├── LEARNING_PATH.md           # phased build order - read this first
    ├── DATA_SCHEMA.md             # ECS rationale + per-source field mappings
    └── DETECTION_USE_CASES.md     # what each rule detects and how to test it
```

## Build order (status)

Read `docs/LEARNING_PATH.md` for the full phase-by-phase plan:

1. ✅ Sandbox up
2. ✅ One log source (firewall) end to end
3. ✅ Cloud + application sources, normalization proven across genuinely different formats
4. ✅ Realistic normal-traffic baseline generator
5. ✅ Rule-based detections: port scan, brute force, credential stuffing, API enumeration, SQL injection, DNS tunneling
6. ✅ DDoS detection (multi-signal, baseline-relative, plus volumetric/SYN-flood classifiers) + correlation into incidents
7. ✅ Investigation dashboard (`dashboards/create_dashboard.sh`)

Native OpenSearch plugins (Security Analytics Sigma rules, Anomaly
Detection RCF) are a natural next step once the custom detection engine
is solid. The ECS schema was chosen specifically to make that migration
smooth when the time comes.

## Viewing the dashboard

```bash
cd dashboards
./create_dashboard.sh   # idempotent, safe to re-run
```

Then open http://localhost:5601/app/dashboards → **Security Monitoring -
Investigation Dashboard**. See `dashboards/dashboard-configuration.md` for
what each panel shows.
