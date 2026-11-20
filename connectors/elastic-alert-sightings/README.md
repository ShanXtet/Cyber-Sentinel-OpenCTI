# Elastic Alert → OpenCTI Sightings

Creates OpenCTI **Sightings** on IPv4 observables from Elastic Security
**Indicator Match** alerts (`threat_match`).

Uses `requests` + Elasticsearch only (no `pycti` / libmagic).

## Deploy

Copy this folder + updated `docker-compose.yml` to the OpenCTI host, then:

```bash
cd /opt/opencti
docker compose --profile elastic-sightings up -d --build --force-recreate connector-elastic-alert-sightings
docker compose logs -f --tail=80 connector-elastic-alert-sightings
```

Required env (usually already set for incidents connector):

- `OPENCTI_ADMIN_TOKEN`
- `ELASTICSEARCH_EXTERNAL_HOSTS=http://192.168.11.227:9200`
- `ELASTIC_SECURITY_API_KEY` with `cluster: monitor` + read on `.alerts-security.alerts-*`

## Verify

OpenCTI → search IP → **Sightings** tab  
or **Events → Sightings**

Expected logs: `OpenCTI GraphQL OK`, `SIEM identity`, `Created sighting id=...`
