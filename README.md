# ETR - ECMP Traceroute

An MTR-like tool for discovering and analyzing ECMP (Equal-Cost Multi-Path) network routes.

> **Note**: ETR is a work in progress, built as a learning project while exploring Go in a familiar (network engineering) domain. It was created out of a desire for an MTR-like tool that is ECMP-"aware" and capable of probing specific ECMP paths using consistent 5-tuple hashing. While functional and useful for network exploration, it's not yet recommended for production environments.

## Features

ETR discovers multiple network paths by running parallel traceroute probes with different source ports, causing routers to select different ECMP routes. Each probe maintains a consistent 5-tuple (src IP, src port, dst IP, dst port, protocol) to repeatedly test the same path.

- **Real-time TUI**: MTR-like interface with live statistics (RTT, delay variation, packet loss per hop)
- **Parallel probes**: Run multiple simultaneous probes to discover different ECMP paths
- **Protocol support**: TCP SYN and UDP probes (UDP payload length encodes probe details)
- **JSON export**: Stream results to stdout or file for analysis and integration
- **Path identification**: CRC32 or SHA256 hashing to identify unique routes
- **Automatic destination detection**: Stops probing beyond the final destination

**Use cases**: Network troubleshooting, ECMP path discovery, finding specific paths for tools like iperf

## Demo

![etr tui demo](https://github.com/user-attachments/assets/f5803a12-a4f1-4fa1-82a9-8526ba85d5af)

## Installation

- **Releases**: Download the latest macOS/Linux binary from the [releases page](https://github.com/tkjaer/etr/releases).
- **Source**: `go install github.com/tkjaer/etr/cmd/etr@latest` (requires libpcap headers).
- **BSD**: Supported via source builds (OpenBSD/NetBSD limited to Ethernet source interfaces).

Detailed platform notes (Gatekeeper prompts, package installs, raw-socket permissions) live in [docs/install.md](docs/install.md).

## Usage

```bash
# Basic TCP traceroute
etr example.com

# UDP with 10 parallel probes to discover multiple paths
etr -U -P 10 example.com

# Export JSON while showing TUI
etr -j output.json example.com

# JSON-only output (no TUI)
etr -J example.com > results.json

# Custom port and extended monitoring
etr -p 80 -c 1000 -d 5s target.example.com
```

**Common options**:
- `-4/-6`: Force IPv4 or IPv6 routing
- `-T/-U`: TCP (default) or UDP probes
- `-n`: Skip DNS lookups (show IPs only)
- `-c <n>`: Probe iterations (default: unlimited)
- `-P <n>`: Number of parallel probes (default: 5)
- `-p <port>`: Destination port (default: 443 for TCP, 33434 for UDP)
- `-s <port>`: Base source port (default: 50000)
- `-j <file>`: JSON output to file (keeps TUI)
- `-J`: JSON output to stdout (disables TUI)
- `--help`: Full option list

**TUI controls**: `↑/↓` scroll, `←/→` or `Tab` switch views, `q` quit

**Styling**: set the `NO_COLOR` environment variable to disable ANSI styling in the TUI.

## Example: Finding ECMP Paths for iperf Testing

```bash
# Discover paths with many parallel probes
etr -U -P 20 -j paths.json target.example.com

# Analyze JSON to find paths with specific characteristics
# Use iperf with matching source ports to test the exact same path
```

## JSON Output Format

Each probe iteration outputs one line of JSON (newline-delimited):

```json
{
  "probe_id": 0,
  "probe_num": 1,
  "path_hash": "a3f5c2d1",
  "source_ip": "198.51.100.1",
  "source_port": 50000,
  "destination_ip": "203.0.113.1",
  "destination_port": 443,
  "destination_ptr": "example.com",
  "protocol": "TCP",
  "reached_dest": true,
  "hops": [
    {
      "ttl": 1,
      "ip": "192.0.2.1",
      "rtt": 1234567,
      "timeout": false,
      "ptr": "gateway.local",
      "recv_time": "2025-10-27T12:00:00Z"
    }
  ],
  "timestamp": "2025-10-27T12:00:00Z"
}
```

**Key fields:**
- `path_hash`: Unique identifier for this network path (CRC32 or SHA256)
- `probe_id`: Which parallel probe (0 to N-1)
- `probe_num`: Iteration number (0, 1, 2, ...)
- `reached_dest`: Whether the final destination was reached
- `rtt`: Round-trip time in microseconds

## License

MIT License - see LICENSE file for details.

## Further Reading

- [Installation details](docs/install.md)
- [Developing ETR](docs/developing.md)
- [Probe encoding design](docs/probe-encoding-design.md)
