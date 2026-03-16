#!/bin/bash
set -e

# Usage: test_paths.sh <destination_ip> <hop2a_ip> <hop2b_ip>
# Example: test_paths.sh 10.4.1.102 10.2.1.102 10.2.2.102
# Example: test_paths.sh fd00:4::102 fd00:2:1::102 fd00:2:2::102

if [ $# -ne 3 ]; then
    echo "Usage: $0 <destination_ip> <hop2a_ip> <hop2b_ip>"
    echo "  destination_ip: The target destination IP address"
    echo "  hop2a_ip:       Expected IP address for hop2 path A"
    echo "  hop2b_ip:       Expected IP address for hop2 path B"
    exit 1
fi

DESTINATION_IP="$1"
HOP2A_IP="$2"
HOP2B_IP="$3"

echo "Running ETR e2e path discovery test..."
echo "Destination: $DESTINATION_IP"
echo "Expected hop2 IPs: $HOP2A_IP, $HOP2B_IP"

# 16 parallel probes = 16 distinct source ports = 16 different ECMP hash
# inputs. With 2-way ECMP the probability of all landing on one side is
# 1/2^15 ≈ 0.003%.
OUTPUT=$(docker exec probe etr -P16 "$DESTINATION_IP" -c1 -J 2>/dev/null)

echo "$OUTPUT" > /tmp/etr_output.json

UNIQUE_PATHS=$(echo "$OUTPUT" | jq -r '.path_hash' | sort -u | wc -l)
echo "Found $UNIQUE_PATHS unique paths"

HOP2_IPS=$(echo "$OUTPUT" | jq -r '.hops[] | select(.ttl == 2) | .ip' | sort -u)
HOP2_COUNT=$(echo "$HOP2_IPS" | wc -l)
echo "Found $HOP2_COUNT unique hop2 addresses: $(echo "$HOP2_IPS" | tr '\n' ' ')"

if [ "$UNIQUE_PATHS" -lt 2 ]; then
    echo "ERROR: Expected at least 2 paths, found $UNIQUE_PATHS"
    echo "=== ETR Output ==="
    cat /tmp/etr_output.json
    exit 1
fi

if ! echo "$HOP2_IPS" | grep -qF "$HOP2A_IP"; then
    echo "ERROR: Expected to find hop2a ($HOP2A_IP)"
    echo "=== ETR Output ==="
    cat /tmp/etr_output.json
    exit 1
fi

if ! echo "$HOP2_IPS" | grep -qF "$HOP2B_IP"; then
    echo "ERROR: Expected to find hop2b ($HOP2B_IP)"
    echo "=== ETR Output ==="
    cat /tmp/etr_output.json
    exit 1
fi

echo "✓ Test passed: Found 2 ECMP paths through $HOP2A_IP and $HOP2B_IP"
exit 0
