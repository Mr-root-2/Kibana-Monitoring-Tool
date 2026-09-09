# Dashboard Configuration (Phase 7)

The investigation dashboard is built and populated. Open it at:

http://localhost:5601/app/dashboards → **Security Monitoring - Investigation Dashboard**

## What's in it

| Panel | Index pattern | Shows |
|---|---|---|
| Findings by Type | `security-findings-*` | Pie chart: proportion of port_scan / brute_force / api_enumeration / ddos findings |
| Findings by Confidence | `security-findings-*` | Stacked histogram: finding type vs confidence (medium/high) |
| Findings Over Time | `security-findings-*` | Time series of findings, colored by type - shows when attacks were detected |
| Top Attacker Source IPs | `security-findings-*` | Table: which `source_ip` values triggered the most findings |
| Top Targeted Endpoints (DDoS findings) | `security-findings-*` | Table: which `target_path` values were hit by DDoS findings |
| Recent Incidents | `security-incidents-*` | Table: correlated incidents by target + confidence |
| Network Events Volume Over Time | `network-events-*` | Time series of raw traffic by `event.dataset` (firewall/cloud/application) - the baseline you're comparing attacks against |

## How it's built

Everything is created via `dashboards/create_dashboard.sh`, which calls the
OpenSearch Dashboards saved objects API directly (`osd-xsrf` header +
basic auth) rather than being built by hand in the UI. This makes the
dashboard reproducible - delete it, re-run the script, get the same result.

```bash
cd dashboards
./create_dashboard.sh
```

Safe to re-run: it uses explicit saved-object IDs and `?overwrite=true`, so
re-running updates in place instead of duplicating panels.

## Prerequisites

The script assumes:
- OpenSearch Dashboards is reachable at `http://localhost:5601` (override with `DASHBOARDS_URL` env var)
- The `security-findings` and `security-incidents` index templates are applied (`opensearch/index-template-security-*.json`)
- There's at least some data in `network-events-*`, `security-findings-*`, `security-incidents-*` for the panels to show anything meaningful - run the log generators and `detection-engine/main.py` first

## If the dashboard looks empty

The dashboard has `timeRestore: true` set to "Last 7 days" by default, so
this shouldn't normally happen. If it still looks empty:

1. **Check the time picker (top right of the dashboard page)** - if it's
   somehow reset to something narrow like "Last 15 minutes" and your test
   data is older than that, widen it (e.g. "Last 24 hours" or "Last 7
   days").
2. **Confirm there's actually data**, since an empty dashboard usually just
   means no findings/incidents have been generated and persisted yet:
   ```bash
   curl -sk -u admin:'<password>' "https://localhost:9200/security-findings-*/_count"
   curl -sk -u admin:'<password>' "https://localhost:9200/security-incidents-*/_count"
   ```
   If these are 0, run the log generators + `detection-engine/main.py`
   first (see Quick Start in the main README).
3. **Confirm you're in the right tenant.** These saved objects were created
   without an explicit `securitytenant` header, which puts them in the
   **Private** tenant for whichever user created them (in this setup,
   `admin`). Select **Private** on the tenant picker at login - if you
   select **Global** instead, the dashboard won't show up at all in the
   list.

## Known gaps (not built yet)

- **Source → destination geo map**: needs a `geoip` Data Prepper processor
  added to the ingest pipelines (not yet wired up - see
  `docs/ARCHITECTURE.md`) before `source.geo.location` /
  `destination.geo.location` have real values to map.
- **Auto-refresh / live view**: the dashboard is a static saved view; for a
  live SOC-style monitor you'd add auto-refresh in the dashboard's time
  picker (top right in the UI) and run `detection-engine/main.py` on a
  schedule (cron) rather than manually.
- **Drill-down from incident to underlying raw events**: currently the
  incidents table shows the correlated summary only; clicking through to
  the exact `network-events-*` documents that caused a finding is a manual
  Discover-app query (filter by `source.ip` / `url.path` and the relevant
  time window), not yet a built-in link.
