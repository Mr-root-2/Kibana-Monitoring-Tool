# Architecture

```
[log-generator scripts]           (stand-in for real firewall/cloud/app sources)
        │  (writes raw JSON lines per source, distinct field names per source)
        ▼
[Data Prepper]                    (data-prepper/pipelines.yaml)
        │  tail file -> parse -> rename/normalize -> write
        ▼
[OpenSearch]                      network-events-{firewall,cloud,app}-* indices
        │  shared index template enforces consistent field types
        ▼
┌───────────────────┬──────────────────────┐
│                   │                      │
[Detection engine]   [OpenSearch Dashboards]
(detection-engine/)  (ad-hoc queries, later: saved dashboards)
        │
        ▼
[Correlation / incident engine]
(detection-engine/correlation/incident_engine.py)
        │
        ▼
Incidents (currently printed to stdout by main.py;
           later: written back to OpenSearch as their own index,
           surfaced in a dashboard)
```

## Why this shape

- **One pipeline per source** (not one shared pipeline with conditional
  logic) because each source's raw format is genuinely different. Keeping
  them separate makes it obvious which mapping belongs to which source
  and makes adding a fourth source additive, not a rewrite.
- **Custom Python detection engine before native OpenSearch plugins**
  because the goal right now is understanding what a detection actually
  looks for. A plugin UI would hide that logic behind configuration you
  don't yet have context to tune well. See `docs/LEARNING_PATH.md`.
- **Correlation is a separate stage from detection**, not baked into each
  rule, so new detections can be added without touching correlation logic,
  and correlation logic can evolve (e.g. time-windowed grouping, richer
  target matching) without touching detection rules.
