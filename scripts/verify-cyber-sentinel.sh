#!/usr/bin/env bash
# Cyber Sentinel technical verification
# Run parts on cyberVM (OpenCTI) and ELK as marked.
set -euo pipefail

section() { echo; echo "======== $1 ========"; }

if [[ "${1:-}" == "opencti" ]]; then
  section "1) Containers"
  cd /opt/opencti
  docker compose ps | grep -iE 'opencti|elastic-security-intel|NAME' || true

  section "2) Intel connector recent logs (errors?)"
  docker compose logs --tail=80 connector-elastic-security-intel 2>&1 \
    | grep -iE 'ERROR|KeyError|Created threat|Connected|Listening|Unauthorized|401|410' \
    | tail -40 || true

  section "3) Live stream / env presence (no secrets printed)"
  grep -E '^(CONNECTOR_ELASTIC_LIVE_STREAM_ID|ELASTICSEARCH_EXTERNAL_HOSTS|ELASTIC_SECURITY_INDEX_NAME|ELASTIC_SECURITY_API_KEY)=' .env \
    | sed 's/\(API_KEY=\).*/\1***redacted***/'

  section "4) OpenCTI health"
  curl -s -o /dev /null -w "HTTP %{http_code}\n" "http://127.0.0.1:9080/" || true
  exit 0
fi

if [[ "${1:-}" == "elk" ]]; then
  ES_USER="${ES_USER:-elastic}"
  ES_PASS="${ES_PASS:-Roger?!91}"
  AUTH=(-u "${ES_USER}:${ES_PASS}")

  section "1) Cluster health"
  curl -s "${AUTH[@]}" "http://127.0.0.1:9200/_cluster/health?pretty" | head -20

  section "2) TI index (OpenCTI IOC) count + newest doc"
  curl -s "${AUTH[@]}" "http://127.0.0.1:9200/_cat/indices/logs-ti*?v"
  echo
  curl -s "${AUTH[@]}" "http://127.0.0.1:9200/logs-ti_*/_count?pretty"
  echo
  curl -s "${AUTH[@]}" "http://127.0.0.1:9200/logs-ti_*/_search?pretty" \
    -H 'Content-Type: application/json' -d '{
      "size": 1,
      "sort": [{"@timestamp":"desc"}],
      "_source": ["@timestamp","threat.indicator.ip","threat.indicator.domain","threat.indicator.type"]
    }'

  section "3) Filebeat newest event (realtime?)"
  curl -s "${AUTH[@]}" "http://127.0.0.1:9200/filebeat-*/_search?pretty" \
    -H 'Content-Type: application/json' -d '{
      "size": 1,
      "sort": [{"@timestamp":"desc"}],
      "_source": ["@timestamp","destination.ip","source.ip","event.dataset"]
    }'

  section "4) Sample IOC overlap (top dest IPs last 24h vs any TI hit count)"
  curl -s "${AUTH[@]}" "http://127.0.0.1:9200/filebeat-*/_search?pretty" \
    -H 'Content-Type: application/json' -d '{
      "size": 0,
      "query": {"range": {"@timestamp": {"gte": "now-24h"}}},
      "aggs": {"top_dst": {"terms": {"field": "destination.ip", "size": 5}}}
    }'

  section "5) Alerts from OpenCTI TI match (last count)"
  curl -s "${AUTH[@]}" "http://127.0.0.1:9200/.alerts-security.alerts-*/_count?pretty" \
    -H 'Content-Type: application/json' -d '{
      "query": {
        "bool": {
          "must": [
            {"match_phrase": {"kibana.alert.rule.name": "OpenCTI TI match – FortiGate traffic"}},
            {"range": {"@timestamp": {"gte": "now-7d"}}}
          ]
        }
      }
    }'

  section "6) Filebeat output test (needs sudo)"
  if command -v filebeat >/dev/null 2>&1; then
    sudo filebeat test output 2>&1 | tail -20 || true
  else
    echo "filebeat binary not in PATH / not this host"
  fi
  exit 0
fi

echo "Usage:"
echo "  On cyberVM:  bash verify-cyber-sentinel.sh opencti"
echo "  On ELK:      bash verify-cyber-sentinel.sh elk"
exit 1
