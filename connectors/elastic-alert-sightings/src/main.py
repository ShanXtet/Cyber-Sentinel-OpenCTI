#!/usr/bin/env python3
"""Elastic Security Indicator Match alerts → OpenCTI Sightings (IPv4).

No pycti dependency (avoids libmagic + GraphQL schema drift). Uses:
  - elasticsearch client for .alerts-*
  - requests for OpenCTI GraphQL (/graphql)
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from dateutil.parser import isoparse
from elasticsearch import Elasticsearch

LOG = logging.getLogger("elastic-alert-sightings")
STATE_PATH = Path(os.getenv("STATE_FILE", "/var/cache/elastic-alert-sightings/state.json"))
DEFAULT_DURATION_SEC = 900


def env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise SystemExit(f"Missing required env: {name}")
    return value


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def parse_duration_seconds(period: str) -> int:
    period = (period or "PT15M").strip().upper()
    if not period.startswith("PT"):
        return DEFAULT_DURATION_SEC
    body = period[2:]
    total = 0
    num = ""
    for ch in body:
        if ch.isdigit():
            num += ch
            continue
        if not num:
            continue
        n = int(num)
        num = ""
        if ch == "H":
            total += n * 3600
        elif ch == "M":
            total += n * 60
        elif ch == "S":
            total += n
    return total or DEFAULT_DURATION_SEC


def load_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return {"processed_alert_ids": [], "last_run_end": None}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"processed_alert_ids": [], "last_run_end": None}


def save_state(state: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ids = state.get("processed_alert_ids") or []
    state["processed_alert_ids"] = ids[-5000:]
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


# ---------- Elastic ----------


def es_client() -> Elasticsearch:
    url = env("ELASTIC_SECURITY_URL", os.getenv("ELASTICSEARCH_EXTERNAL_HOSTS"))
    api_key = os.getenv("ELASTIC_SECURITY_API_KEY")
    verify = env_bool("ELASTIC_SECURITY_VERIFY_SSL", False)
    if api_key:
        return Elasticsearch(url, api_key=api_key, verify_certs=verify)
    return Elasticsearch(
        url,
        basic_auth=(env("ELASTICSEARCH_EXTERNAL_USERNAME"), env("ELASTICSEARCH_EXTERNAL_PASSWORD")),
        verify_certs=verify,
    )


def build_alert_query(start: datetime, end: datetime) -> dict:
    rule_filter = os.getenv("ALERT_RULE_NAME_CONTAINS", "OpenCTI TI match")
    return {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}},
                {"term": {"kibana.alert.rule.type": "threat_match"}},
                {
                    "wildcard": {
                        "kibana.alert.rule.name": {
                            "value": f"*{rule_filter}*",
                            "case_insensitive": True,
                        }
                    }
                },
            ]
        }
    }


def fetch_alerts(es: Elasticsearch, start: datetime, end: datetime) -> list[dict]:
    index = os.getenv(
        "ELASTIC_ALERTS_INDEX",
        ".alerts-security.alerts-*,.internal.alerts-security.alerts-*",
    )
    size = int(os.getenv("ELASTIC_ALERTS_PAGE_SIZE", "200"))
    max_alerts = int(os.getenv("ELASTIC_ALERTS_MAX_PER_RUN", "500"))
    # Newest first so recent test alerts are not starved when max_alerts caps the batch
    body: dict[str, Any] = {
        "size": size,
        "sort": [{"@timestamp": "desc"}],
        "query": build_alert_query(start, end),
        "_source": True,
    }
    resp = es.search(index=index, body=body, ignore_unavailable=True)
    hits = list(resp.get("hits", {}).get("hits", []))
    while len(hits) < max_alerts and len(resp.get("hits", {}).get("hits", [])) == size:
        body["search_after"] = resp["hits"]["hits"][-1]["sort"]
        resp = es.search(index=index, body=body, ignore_unavailable=True)
        batch = resp.get("hits", {}).get("hits", [])
        if not batch:
            break
        hits.extend(batch)
    return hits[:max_alerts]


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    try:
        a, b, *_ = (int(x) for x in ip.split("."))
    except ValueError:
        return True
    if a == 10 or a == 127:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    return False


def skip_ip_list() -> set[str]:
    """Known-good / noise public IPs that must not become Sightings."""
    raw = os.getenv(
        "SKIP_PUBLIC_IPS",
        "8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1,9.9.9.9,208.67.222.222,208.67.220.220",
    )
    return {p.strip() for p in raw.split(",") if p.strip()}


def should_skip_ip(ip: str, skip_private: bool) -> bool:
    if skip_private and is_private_ip(ip):
        return True
    if ip in skip_ip_list():
        return True
    return False


def extract_matched_ip(src: dict) -> str | None:
    for item in (src.get("threat") or {}).get("enrichments") or []:
        matched = (item or {}).get("matched") or {}
        atomic = matched.get("atomic")
        if isinstance(atomic, str) and _looks_like_ipv4(atomic):
            return atomic
        ips = ((item or {}).get("indicator") or {}).get("ip")
        if isinstance(ips, list) and ips and _looks_like_ipv4(str(ips[0])):
            return str(ips[0])
        if isinstance(ips, str) and _looks_like_ipv4(ips):
            return ips
    dip = (src.get("destination") or {}).get("ip")
    if isinstance(dip, str) and _looks_like_ipv4(dip):
        return dip
    return None


# ---------- OpenCTI GraphQL (requests) ----------


class OpenCTI:
    def __init__(self) -> None:
        base = env("OPENCTI_URL").rstrip("/")
        self.url = f"{base}/graphql"
        self.token = env("OPENCTI_TOKEN")
        self.verify = env_bool("OPENCTI_SSL_VERIFY", False)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            }
        )

    def gql(self, query: str, variables: dict | None = None) -> dict:
        payload = {"query": query, "variables": variables or {}}
        resp = self.session.post(self.url, json=payload, verify=self.verify, timeout=60)
        resp.raise_for_status()
        body = resp.json()
        if body.get("errors"):
            raise RuntimeError(f"GraphQL errors: {body['errors']}")
        return body.get("data") or {}


def ensure_siem_identity(octi: OpenCTI) -> dict:
    name = os.getenv("SIGHTING_IDENTITY_NAME", "Elastic Detection Cluster")
    description = os.getenv(
        "SIGHTING_IDENTITY_DESCRIPTION",
        "SIEM / FortiGate detection path that sighted OpenCTI indicators",
    )
    data = octi.gql(
        """
        query($filters: FilterGroup) {
          identities(filters: $filters, first: 10) {
            edges { node { id standard_id name entity_type } }
          }
        }
        """,
        {
            "filters": {
                "mode": "and",
                "filters": [
                    {"key": "name", "values": [name], "operator": "eq", "mode": "or"},
                ],
                "filterGroups": [],
            }
        },
    )
    for edge in ((data.get("identities") or {}).get("edges") or []):
        node = edge.get("node") or {}
        if node.get("name") == name:
            return node

    data = octi.gql(
        """
        mutation($input: IdentityAddInput!) {
          identityAdd(input: $input) { id standard_id name entity_type }
        }
        """,
        {"input": {"type": "Organization", "name": name, "description": description}},
    )
    node = data.get("identityAdd")
    if not node:
        raise RuntimeError(f"identityAdd failed: {data}")
    return node


def get_or_create_ipv4(octi: OpenCTI, ip: str) -> dict:
    data = octi.gql(
        """
        query($filters: FilterGroup) {
          stixCyberObservables(filters: $filters, first: 5) {
            edges { node { id standard_id entity_type observable_value } }
          }
        }
        """,
        {
            "filters": {
                "mode": "and",
                "filters": [
                    {"key": "value", "values": [ip], "operator": "eq", "mode": "or"},
                    {"key": "entity_type", "values": ["IPv4-Addr"], "operator": "eq", "mode": "or"},
                ],
                "filterGroups": [],
            }
        },
    )
    for edge in ((data.get("stixCyberObservables") or {}).get("edges") or []):
        node = edge.get("node") or {}
        if node.get("id"):
            return node

    score = int(os.getenv("SIGHTING_OBSERVABLE_SCORE", "50"))
    # Argument name must be IPv4-Addr in OpenCTI GraphQL
    data = octi.gql(
        f"""
        mutation {{
          stixCyberObservableAdd(
            type: "IPv4-Addr"
            IPv4-Addr: {{ value: "{ip}" }}
            x_opencti_score: {score}
          ) {{
            id standard_id entity_type observable_value
          }}
        }}
        """
    )
    node = data.get("stixCyberObservableAdd")
    if not node:
        raise RuntimeError(f"stixCyberObservableAdd failed for {ip}: {data}")
    return node


def already_sighted(octi: OpenCTI, alert_uuid: str) -> bool:
    data = octi.gql(
        """
        query($filters: FilterGroup) {
          externalReferences(filters: $filters, first: 1) {
            edges { node { id } }
          }
        }
        """,
        {
            "filters": {
                "mode": "and",
                "filters": [
                    {
                        "key": "source_name",
                        "values": ["elastic-security-alert"],
                        "operator": "eq",
                        "mode": "or",
                    },
                    {
                        "key": "external_id",
                        "values": [alert_uuid],
                        "operator": "eq",
                        "mode": "or",
                    },
                ],
                "filterGroups": [],
            }
        },
    )
    return bool(((data.get("externalReferences") or {}).get("edges") or []))


def _esc(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "")
    )


def create_ext_ref(octi: OpenCTI, alert_uuid: str, ip: str, url: str) -> str | None:
    url_part = f'url: "{_esc(url)}"' if url else ""
    data = octi.gql(
        f"""
        mutation {{
          externalReferenceAdd(input: {{
            source_name: "elastic-security-alert"
            external_id: "{_esc(alert_uuid)}"
            description: "Elastic alert for {_esc(ip)}"
            {url_part}
          }}) {{ id }}
        }}
        """
    )
    return ((data.get("externalReferenceAdd") or {}).get("id"))


def create_sighting(
    octi: OpenCTI,
    *,
    from_id: str,
    to_id: str,
    description: str,
    seen: str,
    confidence: int,
    ext_ref_id: str | None,
) -> dict:
    ext = f'externalReferences: ["{ext_ref_id}"]' if ext_ref_id else ""
    data = octi.gql(
        f"""
        mutation {{
          stixSightingRelationshipAdd(input: {{
            fromId: "{from_id}"
            toId: "{to_id}"
            description: "{_esc(description)}"
            first_seen: "{seen}"
            last_seen: "{seen}"
            attribute_count: 1
            confidence: {confidence}
            createdBy: "{to_id}"
            {ext}
          }}) {{
            id standard_id entity_type
          }}
        }}
        """
    )
    node = data.get("stixSightingRelationshipAdd")
    if not node:
        raise RuntimeError(f"stixSightingRelationshipAdd failed: {data}")
    return node


def create_sighting_for_alert(
    octi: OpenCTI,
    identity: dict,
    hit: dict,
    skip_private: bool,
) -> bool:
    src = hit.get("_source") or {}
    alert_uuid = src.get("kibana.alert.uuid") or hit.get("_id")
    if not alert_uuid:
        return False
    if already_sighted(octi, str(alert_uuid)):
        LOG.info("Skip already sighted alert %s", alert_uuid)
        return False

    ip = extract_matched_ip(src)
    if not ip:
        LOG.warning("No matched IP on alert %s", alert_uuid)
        return False
    if should_skip_ip(ip, skip_private):
        LOG.info("Skip IP %s (private/allowlist) alert=%s", ip, alert_uuid)
        return False

    observable = get_or_create_ipv4(octi, ip)
    ts_raw = src.get("kibana.alert.original_time") or src.get("@timestamp")
    try:
        seen = isoparse(str(ts_raw)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        seen = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    source_ip = (src.get("source") or {}).get("ip")
    nat_ip = ((src.get("source") or {}).get("nat") or {}).get("ip")
    rule_name = src.get("kibana.alert.rule.name") or "threat_match"
    reason = src.get("kibana.alert.reason") or ""
    proto = (src.get("network") or {}).get("protocol") or (src.get("network") or {}).get(
        "transport"
    )
    kibana_url = os.getenv("ELASTIC_SECURITY_KIBANA_URL", "").rstrip("/")
    alert_link = f"{kibana_url}/app/security/alerts" if kibana_url else ""

    description = (
        f"Elastic Indicator Match sighting\n"
        f"Rule: {rule_name}\n"
        f"Matched IP: {ip}\n"
        f"Source IP: {source_ip}"
        + (f" (NAT {nat_ip})" if nat_ip else "")
        + f"\nProtocol: {proto}\n"
        f"Reason: {reason}\n"
        f"Alert UUID: {alert_uuid}"
    )

    ext_id = create_ext_ref(octi, str(alert_uuid), ip, alert_link)
    sighting = create_sighting(
        octi,
        from_id=observable["id"],
        to_id=identity["id"],
        description=description,
        seen=seen,
        confidence=int(os.getenv("SIGHTING_CONFIDENCE", "75")),
        ext_ref_id=ext_id,
    )
    LOG.info("Created sighting id=%s ip=%s alert=%s", sighting.get("id"), ip, alert_uuid)
    return True


def run_once(es: Elasticsearch, octi: OpenCTI, identity: dict, state: dict) -> dict:
    now = datetime.now(timezone.utc)
    lookback_min = int(os.getenv("LOOKBACK_MINUTES", "40"))
    first_lookback_min = int(os.getenv("FIRST_RUN_LOOKBACK_MINUTES", "1440"))
    overlap_min = int(os.getenv("LOOKBACK_OVERLAP_MINUTES", "5"))

    if state.get("last_run_end"):
        try:
            start = isoparse(state["last_run_end"]) - timedelta(minutes=overlap_min)
        except Exception:
            start = now - timedelta(minutes=lookback_min)
    else:
        start = now - timedelta(minutes=first_lookback_min)
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)

    LOG.info("Polling alerts from %s to %s", start.isoformat(), now.isoformat())
    hits = fetch_alerts(es, start, now)
    LOG.info("Fetched %s threat_match alerts", len(hits))

    skip_private = env_bool("SKIP_PRIVATE_DEST_IP", True)
    processed = set(state.get("processed_alert_ids") or [])
    created = 0
    for hit in hits:
        src = hit.get("_source") or {}
        alert_uuid = src.get("kibana.alert.uuid") or hit.get("_id")
        if alert_uuid in processed:
            continue
        try:
            if create_sighting_for_alert(octi, identity, hit, skip_private):
                created += 1
            if alert_uuid:
                processed.add(alert_uuid)
        except Exception:
            LOG.exception("Failed processing alert %s", alert_uuid)

    state["processed_alert_ids"] = list(processed)
    state["last_run_end"] = now.isoformat()
    save_state(state)
    LOG.info("Run complete: sightings_created=%s", created)
    return state


def main() -> None:
    logging.basicConfig(
        level=getattr(logging, os.getenv("CONNECTOR_LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )
    duration = parse_duration_seconds(os.getenv("CONNECTOR_DURATION_PERIOD", "PT15M"))
    LOG.info("Starting Elastic alert → Sighting connector (period=%ss)", duration)

    es = es_client()
    health = es.cluster.health()
    LOG.info(
        "Elastic connected status=%s cluster=%s",
        health.get("status"),
        health.get("cluster_name"),
    )

    octi = OpenCTI()
    # ping GraphQL
    about = octi.gql("{ about { version } }")
    LOG.info("OpenCTI GraphQL OK version=%s", ((about.get("about") or {}).get("version")))

    identity = ensure_siem_identity(octi)
    LOG.info("SIEM identity id=%s name=%s", identity.get("id"), identity.get("name"))

    state = load_state()
    while True:
        try:
            state = run_once(es, octi, identity, state)
        except Exception:
            LOG.exception("Run failed; will retry after period")
        time.sleep(duration)


if __name__ == "__main__":
    main()
