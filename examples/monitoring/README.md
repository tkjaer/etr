# ETR Monitoring Example

Example Prometheus + Grafana monitoring stack showing how to visualize ETR ECMP traceroute data.

## Quick Start

**1. Start the monitoring stack:**

```bash
cd examples/monitoring
docker-compose up -d
```

**2. Run ETR with JSON output:**

```bash
# From the repo root
# Build ETR first
go build -o etr ./cmd/etr

# Run with JSON output
mkdir -p examples/monitoring/data
sudo ./etr --json-file examples/monitoring/data/etr.json 192.0.2.1
```

**3. View metrics:**

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3000 (login: admin/admin)
- **Raw metrics**: http://localhost:8080/metrics

Import the dashboard at `examples/monitoring/grafana/dashboards/etr-dashboard.json` into Grafana to visualize your data.

## Metrics

The exporter exposes these Prometheus metrics from ETR JSON output:

| Metric | Type | Description |
|--------|------|-------------|
| `etr_hop_rtt_ms` | Gauge | Round-trip time to each hop (ms) |
| `etr_hop_timeout` | Gauge | Hop timeout status (1=timeout, 0=ok) |
| `etr_path_changes_total` | Counter | Path changes detected |
| `etr_destination_reached` | Gauge | Destination reachability (1=yes, 0=no) |
| `etr_probes_total` | Counter | Total probes sent |
| `etr_last_probe_timestamp` | Gauge | Last probe timestamp |

All metrics include labels: `destination`, `destination_ptr`, `protocol`. Hop metrics also include `ttl`, `hop_ip`, `hop_ptr`.

## Configuration

**Change JSON file location** - Edit `docker-compose.yml`:
```yaml
etr-exporter:
  environment:
    - ETR_JSON_FILE=/data/custom.json
```

**Continuous monitoring** - ETR runs infinitely by default (like mtr):
```bash
sudo ./etr --json-file examples/monitoring/data/etr.json 192.0.2.1
```

To run a specific number of probes, use `--count`:
```bash
sudo ./etr --json-file examples/monitoring/data/etr.json --count 10 192.0.2.1
```

**Stop the stack:**
```bash
docker-compose down
```

## Cleanup

**Remove all containers, volumes, and data:**
```bash
cd examples/monitoring
docker-compose down -v
rm -rf data/
```

This removes:
- All containers (Prometheus, Grafana, exporter)
- Named volumes (prometheus-data, grafana-data)
- Local data directory with ETR JSON files

To also remove the locally built etr-exporter image run:
```bash
docker rmi monitoring-etr-exporter
```
