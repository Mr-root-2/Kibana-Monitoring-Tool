# Data Schema

## Why ECS, not OCSF

We normalize everything to **ECS-style flat field names** (`source.ip`,
`destination.ip`, `network.bytes`, ...) rather than OCSF.

- OpenSearch Security Analytics' Sigma rule engine expects ECS-style field
  names. Normalizing to ECS means detections plug in with minimal extra
  mapping. OCSF's class-based nested schema would need translation back to
  Sigma-compatible fields before detection works at all.
- OCSF is built for schema interchange across many separate downstream
  tools/data lakes. We're normalizing for one destination (OpenSearch), so
  the flatter schema is simpler to hand-roll in Data Prepper processors.
- If a source ever arrives pre-normalized to OCSF (e.g. Datadog's OCSF log
  pipeline), that's a single per-source translation step at ingestion, not
  a reason to rebuild the whole schema.

## Common (normalized) event shape

```json
{
  "@timestamp": "2026-08-21T10:00:00.000Z",
  "event": {
    "action": "allow",
    "category": "network",
    "dataset": "firewall",
    "outcome": "success",
    "duration_ms": 95
  },
  "source": {
    "ip": "10.10.1.10",
    "port": 51000
  },
  "destination": {
    "ip": "10.20.1.5",
    "port": 443
  },
  "network": {
    "protocol": "tcp",
    "bytes": 1200,
    "packets": 3
  },
  "http": {
    "request": { "method": "GET" },
    "response": { "status_code": 200 }
  },
  "url": { "path": "/api/checkout" },
  "log": { "source": { "type": "firewall" } }
}
```

## Per-source field mapping

Each source uses genuinely different raw field names for the same concept.
Normalization means all three converge on the same target fields below.

### Firewall (JSON)

| Raw field | Normalized field |
|---|---|
| `timestamp` | `@timestamp` |
| `src_ip` | `source.ip` |
| `src_port` | `source.port` |
| `dst_ip` | `destination.ip` |
| `dst_port` | `destination.port` |
| `protocol` | `network.protocol` |
| `bytes` | `network.bytes` |
| `action` | `event.action` |

Example raw line:
```json
{"timestamp":"2026-08-21T10:00:00Z","src_ip":"10.10.1.10","dst_ip":"10.20.1.5","dst_port":443,"protocol":"TCP","action":"ALLOW","bytes":1200}
```

### Cloud (JSON, VPC-flow-log style)

| Raw field | Normalized field |
|---|---|
| `eventTime` | `@timestamp` |
| `sourceIPAddress` | `source.ip` |
| `sourcePort` | `source.port` |
| `destinationIPAddress` | `destination.ip` |
| `destinationPort` | `destination.port` |
| `protocolName` | `network.protocol` |
| `bytesTransferred` | `network.bytes` |
| `actionTaken` | `event.action` |

Example raw line:
```json
{"eventTime":"2026-08-21T10:00:05Z","sourceIPAddress":"54.23.11.90","sourcePort":51122,"destinationIPAddress":"10.20.1.5","destinationPort":443,"protocolName":"TCP","bytesTransferred":890,"actionTaken":"ACCEPT"}
```

### Application (JSON access log)

| Raw field | Normalized field |
|---|---|
| `time` | `@timestamp` |
| `client_ip` | `source.ip` |
| `method` | `http.request.method` |
| `path` | `url.path` |
| `status` | `http.response.status_code` |
| `response_bytes` | `network.bytes` |
| `latency_ms` | `event.duration_ms` |

Example raw line:
```json
{"time":"2026-08-21T10:00:07Z","client_ip":"203.0.113.5","method":"GET","path":"/api/checkout","status":200,"response_bytes":512,"latency_ms":95}
```

## Index pattern

Each source writes to its own index, all matching the shared index template
so field types stay consistent for cross-source queries:

- `network-events-firewall-*`
- `network-events-cloud-*`
- `network-events-app-*`

Querying `network-events-*` (all of them) is what makes cross-source
detection and correlation possible - same field names, same types,
regardless of which pipeline wrote the document.
