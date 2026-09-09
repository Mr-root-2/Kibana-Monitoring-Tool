#!/usr/bin/env bash
# Creates the comprehensive security investigation dashboard in OpenSearch Dashboards.
# Idempotent - safe to re-run.
#
# Usage: ./create_dashboard.sh
# Override: DASHBOARDS_URL=... OPENSEARCH_PASSWORD=... ./create_dashboard.sh

set -euo pipefail

DASHBOARDS_URL="${DASHBOARDS_URL:-http://localhost:5601}"
AUTH_USER="${OPENSEARCH_USER:-admin}"
AUTH_PASS="${OPENSEARCH_PASSWORD:-Sbx-Monitor#2026!}"

put() {
  local type="$1" id="$2" body="$3"
  curl -s -u "${AUTH_USER}:${AUTH_PASS}" \
    -X POST "${DASHBOARDS_URL}/api/saved_objects/${type}/${id}?overwrite=true" \
    -H 'osd-xsrf: true' -H 'Content-Type: application/json' \
    -d "${body}" > /dev/null
  echo "  ✓ ${type}/${id}"
}

echo "=== Index Patterns ==="
put index-pattern network-events \
  '{"attributes":{"title":"network-events-*","timeFieldName":"@timestamp"}}'
put index-pattern security-findings \
  '{"attributes":{"title":"security-findings-*","timeFieldName":"@timestamp"}}'
put index-pattern security-incidents \
  '{"attributes":{"title":"security-incidents-*","timeFieldName":"@timestamp"}}'

echo ""
echo "=== Visualizations ==="

# ─── ROW 1: KEY METRICS (Metric panels) ───────────────────────────────

put visualization metric-total-events '{
  "attributes": {
    "title": "Total Network Events",
    "visState": "{\"title\":\"Total Network Events\",\"type\":\"metric\",\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"None\",\"colorsRange\":[{\"from\":0,\"to\":10000}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"\",\"fontSize\":60}}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

put visualization metric-total-findings '{
  "attributes": {
    "title": "Total Security Findings",
    "visState": "{\"title\":\"Total Security Findings\",\"type\":\"metric\",\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"Labels\",\"colorsRange\":[{\"from\":0,\"to\":5},{\"from\":5,\"to\":50}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"\",\"fontSize\":60}}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "security-findings"}]
}'

put visualization metric-total-incidents '{
  "attributes": {
    "title": "Total Incidents",
    "visState": "{\"title\":\"Total Incidents\",\"type\":\"metric\",\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"Labels\",\"colorsRange\":[{\"from\":0,\"to\":3},{\"from\":3,\"to\":50}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"\",\"fontSize\":60}}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "security-incidents"}]
}'

put visualization metric-unique-sources '{
  "attributes": {
    "title": "Unique Source IPs",
    "visState": "{\"title\":\"Unique Source IPs\",\"type\":\"metric\",\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"None\",\"colorsRange\":[{\"from\":0,\"to\":10000}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"\",\"fontSize\":60}}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"cardinality\",\"schema\":\"metric\",\"params\":{\"field\":\"source.ip\"}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

# ─── ROW 2: TRAFFIC OVERVIEW ──────────────────────────────────────────

put visualization geo-source-map '{
  "attributes": {
    "title": "Attack Source Geo Map",
    "visState": "{\"title\":\"Attack Source Geo Map\",\"type\":\"tile_map\",\"params\":{\"colorSchema\":\"Yellow to Red\",\"mapType\":\"Scaled Circle Markers\",\"isDesaturated\":true,\"addTooltip\":true,\"heatClusterSize\":1.5,\"legendPosition\":\"bottomright\",\"mapZoom\":2,\"mapCenter\":[20,0],\"wms\":{\"enabled\":false,\"url\":\"\",\"options\":{\"format\":\"image/png\",\"transparent\":true}}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"geohash_grid\",\"schema\":\"segment\",\"params\":{\"field\":\"source.geo.location\",\"autoPrecision\":true,\"precision\":3}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

put visualization top-source-countries '{
  "attributes": {
    "title": "Top Source Countries",
    "visState": "{\"title\":\"Top Source Countries\",\"type\":\"horizontal_bar\",\"params\":{\"type\":\"histogram\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"BottomAxis-1\",\"type\":\"value\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Events\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"normal\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":false,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false,\"labels\":{\"show\":true},\"thresholdLine\":{\"show\":false}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"source.geo.country_name\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":15}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

put visualization traffic-over-time '{
  "attributes": {
    "title": "Traffic Volume Over Time (by Source)",
    "visState": "{\"title\":\"Traffic Volume Over Time (by Source)\",\"type\":\"area\",\"params\":{\"type\":\"area\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Events\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"area\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"interpolate\":\"linear\",\"showCircles\":false}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false,\"labels\":{\"show\":false},\"thresholdLine\":{\"show\":false,\"value\":10,\"width\":1,\"style\":\"full\",\"color\":\"#E7664C\"}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"schema\":\"segment\",\"params\":{\"field\":\"@timestamp\",\"useNormalizedOpenSearchInterval\":true,\"scaleMetricValues\":false,\"interval\":\"auto\",\"drop_partials\":false,\"min_doc_count\":1,\"extended_bounds\":{}}},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"group\",\"params\":{\"field\":\"event.dataset\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":5}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

put visualization traffic-by-protocol '{
  "attributes": {
    "title": "Traffic by Protocol",
    "visState": "{\"title\":\"Traffic by Protocol\",\"type\":\"pie\",\"params\":{\"type\":\"pie\",\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true,\"labels\":{\"show\":true,\"values\":true,\"last_level\":true,\"truncate\":100}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"network.protocol\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

put visualization top-destination-ports '{
  "attributes": {
    "title": "Top Destination Ports",
    "visState": "{\"title\":\"Top Destination Ports\",\"type\":\"horizontal_bar\",\"params\":{\"type\":\"histogram\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"BottomAxis-1\",\"type\":\"value\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"normal\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":false,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false,\"labels\":{\"show\":false},\"thresholdLine\":{\"show\":false}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"destination.port\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

# ─── ROW 3: APPLICATION LAYER ─────────────────────────────────────────

put visualization http-status-breakdown '{
  "attributes": {
    "title": "HTTP Response Status Codes",
    "visState": "{\"title\":\"HTTP Response Status Codes\",\"type\":\"pie\",\"params\":{\"type\":\"pie\",\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true,\"labels\":{\"show\":true,\"values\":true,\"last_level\":true,\"truncate\":100}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"http.response.status_code\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

put visualization top-endpoints '{
  "attributes": {
    "title": "Top Accessed Endpoints",
    "visState": "{\"title\":\"Top Accessed Endpoints\",\"type\":\"horizontal_bar\",\"params\":{\"type\":\"histogram\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":200},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"BottomAxis-1\",\"type\":\"value\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Requests\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"normal\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":false,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false,\"labels\":{\"show\":false},\"thresholdLine\":{\"show\":false}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"url.path\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":15}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

put visualization avg-latency-over-time '{
  "attributes": {
    "title": "Average Latency Over Time (ms)",
    "visState": "{\"title\":\"Average Latency Over Time (ms)\",\"type\":\"line\",\"params\":{\"type\":\"line\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Avg Latency (ms)\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"line\",\"mode\":\"normal\",\"data\":{\"label\":\"Avg Latency\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"interpolate\":\"linear\",\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":false,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false,\"labels\":{\"show\":false},\"thresholdLine\":{\"show\":false}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"avg\",\"schema\":\"metric\",\"params\":{\"field\":\"event.duration_ms\"}},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"schema\":\"segment\",\"params\":{\"field\":\"@timestamp\",\"useNormalizedOpenSearchInterval\":true,\"scaleMetricValues\":false,\"interval\":\"auto\",\"drop_partials\":false,\"min_doc_count\":1,\"extended_bounds\":{}}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"event.dataset: application\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

# ─── ROW 4: SECURITY FINDINGS ─────────────────────────────────────────

put visualization findings-by-type '{
  "attributes": {
    "title": "Findings by Attack Type",
    "visState": "{\"title\":\"Findings by Attack Type\",\"type\":\"pie\",\"params\":{\"type\":\"pie\",\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true,\"labels\":{\"show\":true,\"values\":true,\"last_level\":true,\"truncate\":100}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"type\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "security-findings"}]
}'

put visualization findings-over-time '{
  "attributes": {
    "title": "Security Findings Over Time",
    "visState": "{\"title\":\"Security Findings Over Time\",\"type\":\"histogram\",\"params\":{\"type\":\"histogram\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Findings\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false,\"labels\":{\"show\":false},\"thresholdLine\":{\"show\":false}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"schema\":\"segment\",\"params\":{\"field\":\"@timestamp\",\"useNormalizedOpenSearchInterval\":true,\"scaleMetricValues\":false,\"interval\":\"auto\",\"drop_partials\":false,\"min_doc_count\":1,\"extended_bounds\":{}}},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"group\",\"params\":{\"field\":\"type\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":5}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "security-findings"}]
}'

put visualization top-attacker-ips '{
  "attributes": {
    "title": "Top Attacker Source IPs",
    "visState": "{\"title\":\"Top Attacker Source IPs\",\"type\":\"table\",\"params\":{\"perPage\":10,\"showPartialRows\":false,\"showMetricsAtAllLevels\":false,\"showToolbar\":true,\"totalFunc\":\"sum\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"source_ip\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":15}},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"type\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":5}},{\"id\":\"4\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"confidence\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":3}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "security-findings"}]
}'

# ─── ROW 5: INCIDENTS & NETWORK DETAIL ────────────────────────────────

put visualization incidents-table '{
  "attributes": {
    "title": "Correlated Incidents",
    "visState": "{\"title\":\"Correlated Incidents\",\"type\":\"table\",\"params\":{\"perPage\":10,\"showPartialRows\":false,\"showMetricsAtAllLevels\":false,\"showToolbar\":true,\"totalFunc\":\"sum\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"target\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":20}},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"type\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":5}},{\"id\":\"4\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"confidence\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":3}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "security-incidents"}]
}'

put visualization top-source-ips-network '{
  "attributes": {
    "title": "Top Source IPs (by traffic volume)",
    "visState": "{\"title\":\"Top Source IPs (by traffic volume)\",\"type\":\"table\",\"params\":{\"perPage\":10,\"showPartialRows\":false,\"showMetricsAtAllLevels\":false,\"showToolbar\":true,\"totalFunc\":\"sum\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"3\",\"enabled\":true,\"type\":\"sum\",\"schema\":\"metric\",\"params\":{\"field\":\"network.bytes\"}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"source.ip\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":15}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

put visualization top-destinations '{
  "attributes": {
    "title": "Top Targeted Destination IPs",
    "visState": "{\"title\":\"Top Targeted Destination IPs\",\"type\":\"table\",\"params\":{\"perPage\":10,\"showPartialRows\":false,\"showMetricsAtAllLevels\":false,\"showToolbar\":true,\"totalFunc\":\"sum\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"3\",\"enabled\":true,\"type\":\"sum\",\"schema\":\"metric\",\"params\":{\"field\":\"network.bytes\"}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"destination.ip\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

put visualization bandwidth-over-time '{
  "attributes": {
    "title": "Bandwidth Over Time (bytes)",
    "visState": "{\"title\":\"Bandwidth Over Time (bytes)\",\"type\":\"area\",\"params\":{\"type\":\"area\",\"grid\":{\"categoryLines\":false},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"filter\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Bytes\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"area\",\"mode\":\"stacked\",\"data\":{\"label\":\"Total Bytes\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"lineWidth\":2,\"interpolate\":\"linear\",\"showCircles\":false}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false,\"labels\":{\"show\":false},\"thresholdLine\":{\"show\":false}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"sum\",\"schema\":\"metric\",\"params\":{\"field\":\"network.bytes\"}},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"schema\":\"segment\",\"params\":{\"field\":\"@timestamp\",\"useNormalizedOpenSearchInterval\":true,\"scaleMetricValues\":false,\"interval\":\"auto\",\"drop_partials\":false,\"min_doc_count\":1,\"extended_bounds\":{}}},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"group\",\"params\":{\"field\":\"destination.ip\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":5}}]}",
    "uiStateJSON": "{}",
    "kibanaSavedObjectMeta": {"searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[],\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\"}"}
  },
  "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": "network-events"}]
}'

echo ""
echo "=== Dashboard ==="

# Build dashboard body with Python for proper JSON handling
DASHBOARD_BODY=$(python3 << 'PYEOF'
import json

panels = [
    # Row 1: Key metrics (small, 12w each)
    {"gridData":{"x":0,"y":0,"w":12,"h":8,"i":"1"},"panelIndex":"1","panelRefName":"panel_1"},
    {"gridData":{"x":12,"y":0,"w":12,"h":8,"i":"2"},"panelIndex":"2","panelRefName":"panel_2"},
    {"gridData":{"x":24,"y":0,"w":12,"h":8,"i":"3"},"panelIndex":"3","panelRefName":"panel_3"},
    {"gridData":{"x":36,"y":0,"w":12,"h":8,"i":"4"},"panelIndex":"4","panelRefName":"panel_4"},
    # Row 2: Geo map + top countries
    {"gridData":{"x":0,"y":8,"w":24,"h":18,"i":"18"},"panelIndex":"18","panelRefName":"panel_18"},
    {"gridData":{"x":24,"y":8,"w":24,"h":18,"i":"19"},"panelIndex":"19","panelRefName":"panel_19"},
    # Row 3: Traffic over time + protocol
    {"gridData":{"x":0,"y":26,"w":32,"h":14,"i":"5"},"panelIndex":"5","panelRefName":"panel_5"},
    {"gridData":{"x":32,"y":26,"w":16,"h":14,"i":"6"},"panelIndex":"6","panelRefName":"panel_6"},
    # Row 4: Ports + bandwidth
    {"gridData":{"x":0,"y":40,"w":16,"h":14,"i":"10"},"panelIndex":"10","panelRefName":"panel_10"},
    {"gridData":{"x":16,"y":40,"w":32,"h":14,"i":"11"},"panelIndex":"11","panelRefName":"panel_11"},
    # Row 5: Application layer
    {"gridData":{"x":0,"y":54,"w":16,"h":14,"i":"7"},"panelIndex":"7","panelRefName":"panel_7"},
    {"gridData":{"x":16,"y":54,"w":16,"h":14,"i":"8"},"panelIndex":"8","panelRefName":"panel_8"},
    {"gridData":{"x":32,"y":54,"w":16,"h":14,"i":"9"},"panelIndex":"9","panelRefName":"panel_9"},
    # Row 6: Findings section
    {"gridData":{"x":0,"y":68,"w":16,"h":14,"i":"12"},"panelIndex":"12","panelRefName":"panel_12"},
    {"gridData":{"x":16,"y":68,"w":32,"h":14,"i":"13"},"panelIndex":"13","panelRefName":"panel_13"},
    # Row 7: Attacker table + incidents
    {"gridData":{"x":0,"y":82,"w":24,"h":14,"i":"14"},"panelIndex":"14","panelRefName":"panel_14"},
    {"gridData":{"x":24,"y":82,"w":24,"h":14,"i":"15"},"panelIndex":"15","panelRefName":"panel_15"},
    # Row 8: Network detail tables
    {"gridData":{"x":0,"y":96,"w":24,"h":14,"i":"16"},"panelIndex":"16","panelRefName":"panel_16"},
    {"gridData":{"x":24,"y":96,"w":24,"h":14,"i":"17"},"panelIndex":"17","panelRefName":"panel_17"},
]

for p in panels:
    p["version"] = "2.19.0"
    p["embeddableConfig"] = {}

body = {
    "attributes": {
        "title": "Security Monitoring - Investigation Dashboard",
        "hits": 0,
        "description": "Comprehensive security monitoring: from traffic overview down to individual attack findings and correlated incidents.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": True,
        "timeFrom": "now-24h",
        "timeTo": "now",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        }
    },
    "references": [
        {"name":"panel_1","type":"visualization","id":"metric-total-events"},
        {"name":"panel_2","type":"visualization","id":"metric-total-findings"},
        {"name":"panel_3","type":"visualization","id":"metric-total-incidents"},
        {"name":"panel_4","type":"visualization","id":"metric-unique-sources"},
        {"name":"panel_18","type":"visualization","id":"geo-source-map"},
        {"name":"panel_19","type":"visualization","id":"top-source-countries"},
        {"name":"panel_5","type":"visualization","id":"traffic-over-time"},
        {"name":"panel_6","type":"visualization","id":"traffic-by-protocol"},
        {"name":"panel_10","type":"visualization","id":"top-destination-ports"},
        {"name":"panel_11","type":"visualization","id":"bandwidth-over-time"},
        {"name":"panel_7","type":"visualization","id":"http-status-breakdown"},
        {"name":"panel_8","type":"visualization","id":"top-endpoints"},
        {"name":"panel_9","type":"visualization","id":"avg-latency-over-time"},
        {"name":"panel_12","type":"visualization","id":"findings-by-type"},
        {"name":"panel_13","type":"visualization","id":"findings-over-time"},
        {"name":"panel_14","type":"visualization","id":"top-attacker-ips"},
        {"name":"panel_15","type":"visualization","id":"incidents-table"},
        {"name":"panel_16","type":"visualization","id":"top-source-ips-network"},
        {"name":"panel_17","type":"visualization","id":"top-destinations"},
    ]
}
print(json.dumps(body))
PYEOF
)

put dashboard security-investigation-dashboard "$DASHBOARD_BODY"

echo ""
echo "✅ Done! Open: ${DASHBOARDS_URL}/app/dashboards"
echo "   Dashboard: 'Security Monitoring - Investigation Dashboard'"
echo "   Default time range: Last 24 hours"
