# E2E Tests

Simple end-to-end tests using Docker Compose to verify ETR functionality in CI.

> **Note**: Docker networking isn't ideal for testing network tools due to container networking limitations. These tests exist primarily to catch regressions in GitHub Actions, not to comprehensively test ECMP discovery.

## Quick Start

```bash
# Start the topology
docker-compose up -d

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
./test_paths.sh
```

This runs automatically in GitHub Actions on every push/PR.
