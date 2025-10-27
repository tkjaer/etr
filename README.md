# ETR - ECMP Traceroute

An MTR-like tool for discovering and analyzing ECMP (Equal-Cost Multi-Path) network routes.

> **Note**: ETR is a work in progress, built as a learning project while exploring Go, and having fun with networking. It was created out of a desire for an MTR-like tool that is ECMP-aware and capable of probing specific ECMP paths using consistent 5-tuple hashing. While functional and useful for network exploration, it's not yet recommended for production environments.

## Features

ETR discovers multiple network paths by running parallel traceroute probes with different source ports, causing routers to select different ECMP routes. Each probe maintains a consistent 5-tuple (src IP, src port, dst IP, dst port, protocol) to repeatedly test the same path.

- **Real-time TUI**: MTR-like interface with live statistics (RTT, delay variation, packet loss per hop)
- **Parallel probes**: Run multiple simultaneous probes to discover different ECMP paths
- **Protocol support**: TCP SYN and UDP probes (UDP payload length encodes probe details)
- **JSON export**: Stream results to stdout or file for analysis and integration
- **Path identification**: CRC32 or SHA256 hashing to identify unique routes
- **Automatic destination detection**: Stops probing beyond the final destination

**Use cases**: Network troubleshooting, ECMP path discovery, finding specific paths for tools like iperf

## Installation

```bash
go install github.com/tkjaer/etr@latest
```

Or build from source:

```bash
git clone https://github.com/tkjaer/etr.git
cd etr
go build
```

**Permissions**: ETR requires raw socket access.

- **macOS**: Run with `sudo` or add your user to the `access_bpf` group:
   ```bash
   sudo dseditgroup -o edit -a $USER -t user access_bpf
   ```

- **Linux**: Run with `sudo` or grant CAP_NET_RAW capability:
  ```bash
  sudo setcap cap_net_raw+ep ./etr
  ```

## Usage

```bash
# Basic TCP traceroute
etr example.com

# UDP with 10 parallel probes to discover multiple paths
etr -U -P 10 example.com

# Export JSON while showing TUI
etr -J output.json example.com

# JSON-only output (no TUI)
etr -j example.com > results.json

# Custom port and extended monitoring
etr -p 80 -c 1000 -d 5s target.example.com
```

**Common options**: 
- `-T/-U`: TCP (default) or UDP probes
- `-P <n>`: Number of parallel probes (default: 5)
- `-p <port>`: Destination port (default: 443)
- `-c <n>`: Probe iterations (default: 10)
- `-j/-J <file>`: JSON output
- `--help`: Full option list

**TUI controls**: `↑/↓` scroll, `←/→` or `Tab` switch views, `q` quit

## Example: Finding ECMP Paths for iperf Testing

```bash
# Discover paths with many parallel probes
etr -U -P 20 -J paths.json target.example.com

# Analyze JSON to find paths with specific characteristics
# Use iperf with matching source ports to test the exact same path
```

## JSON Output Format

Each probe iteration outputs:

```json
{
  "probe_id": 0,
  "iteration": 1,
  "timestamp": "2025-10-27T12:00:00Z",
  "destination": "example.com",
  "protocol": "TCP",
  "dst_port": 443,
  "src_port": 65000,
  "hops": [
    {
      "ttl": 1,
      "ip": "192.0.2.1",
      "rtt": 1234567,
      "timeout": false,
      "ptr": "gateway.local"
    }
  ]
}
```

## License

MIT License - see LICENSE file for details.