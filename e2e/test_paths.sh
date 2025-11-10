#!/bin/bash
set -e

echo "Running ETR e2e path discovery test..."

# Run etr with 2 parallel probes, 10 iterations
OUTPUT=$(docker exec probe etr -P4 10.4.1.102 -p 50001 -c10 -J 2>/dev/null)

# Save output to file for debugging
echo "$OUTPUT" > /tmp/etr_output.json

# Extract unique path hashes
UNIQUE_PATHS=$(echo "$OUTPUT" | jq -r '.path_hash' | sort -u | wc -l)

echo "Found $UNIQUE_PATHS unique paths"

# Verify we found 2 paths
if [ "$UNIQUE_PATHS" -ne 2 ]; then
    echo "ERROR: Expected 2 paths, found $UNIQUE_PATHS"
    echo "=== ETR Output ==="
    cat /tmp/etr_output.json
    exit 1
fi

# Extract second hop IPs from both probes
HOP2_IPS=$(echo "$OUTPUT" | jq -r '.hops[] | select(.ttl == 2) | .ip' | sort -u)
HOP2_COUNT=$(echo "$HOP2_IPS" | wc -l)

echo "Found $HOP2_COUNT unique hop2 addresses:"
echo "$HOP2_IPS"

# Verify we have 2 different hop2 addresses (hop2a and hop2b)
if [ "$HOP2_COUNT" -ne 2 ]; then
    echo "ERROR: Expected 2 different hop2 addresses, found $HOP2_COUNT"
    echo "=== ETR Output ==="
    cat /tmp/etr_output.json
    exit 1
fi

# Verify hop2a (10.2.1.102) and hop2b (10.2.2.102) are both present
if ! echo "$HOP2_IPS" | grep -q "10.2.1.102"; then
    echo "ERROR: Expected to find hop2a (10.2.1.102)"
    echo "=== ETR Output ==="
    cat /tmp/etr_output.json
    exit 1
fi

if ! echo "$HOP2_IPS" | grep -q "10.2.2.102"; then
    echo "ERROR: Expected to find hop2b (10.2.2.102)"
    echo "=== ETR Output ==="
    cat /tmp/etr_output.json
    exit 1
fi

echo "✓ Test passed: Found 2 ECMP paths through hop2a and hop2b"
exit 0
