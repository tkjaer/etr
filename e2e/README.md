# E2E Tests

Simple end-to-end tests using Docker Compose to verify ETR functionality in CI.

> **Note**: Docker networking isn't ideal for testing network tools due to container networking limitations. These tests exist primarily to catch regressions in GitHub Actions, not to comprehensively test ECMP discovery.

## Quick Start

```bash
# Start the topology
docker-compose up -d

# Relaunch probe container with a rebuilt etr
docker-compose build --no-cache probe && docker-compose up -d probe

# Run ETR from the probe container
docker exec -it probe etr 10.4.1.102

# With parallel probes to test ECMP
docker exec -it probe etr -P2 10.4.1.102 -c10

# JSON output
docker exec -it probe etr -P2 10.4.1.102 -c10 -J

# Cleanup
docker-compose down -v
```

## Automated Tests

The `test_paths.sh` script validates basic ECMP path discovery:

```bash
# ipv4
./test_paths.sh 10.4.1.102 10.2.1.102 10.2.2.102

# ipv6
./test_paths.sh fd16:24b7:6fcd:41::102 fd16:24b7:6fcd:21::102 fd16:24b7:6fcd:22::102
```

This runs automatically in GitHub Actions on every push/PR.
