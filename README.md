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

### Pre-built Binaries

Download the latest release for macOS or Linux from the [releases page](https://github.com/tkjaer/etr/releases).

#### macOS Gatekeeper Warning

The macOS release binary is currently unsigned / un-notarized. If you see:

“Apple cannot verify this app is free of malware”

You can run it anyway:

1. Easiest (Finder):
   - Right‑click (or Control‑click) the binary → Open → then click “Open” in the dialog.
2. Or use System Settings:
   - System Settings → Privacy & Security → scroll to the bottom.
   - You should see “etr-darwin-arm64 was blocked…” → click “Allow Anyway”, then run it again (macOS will prompt once more; choose Open).
3. Or remove the quarantine flag (terminal):
   ```bash
   xattr -d com.apple.quarantine ./etr-darwin-arm64
   ./etr-darwin-arm64 --version
   ```

(Optionally) verify checksum first (from the release checksums file):
```bash
shasum -a 256 etr-darwin-arm64
```

Once allowed/trusted, macOS won’t prompt again unless you replace the file. You can also choose to install from source instead.

### From Source

```bash
go install github.com/tkjaer/etr@latest
```

Or build from source:

```bash
git clone https://github.com/tkjaer/etr.git
cd etr
go build
```

### BSD Systems

ETR is not yet tested on or built for BSD systems ([help appreciated!](https://github.com/tkjaer/etr/issues/41)). FreeBSD, OpenBSD, and NetBSD users should build from source. First install dependencies:

**FreeBSD:**
```bash
pkg install go libpcap
```

**OpenBSD:**
```bash
pkg_add go libpcap
```

**NetBSD:**
```bash
pkgin install go libpcap
```

Then build:
```bash
go install github.com/tkjaer/etr@latest
```

Or clone and build locally as shown above.

### Permissions

ETR requires raw socket access.

- **macOS**: Run with `sudo` or add your user to the `access_bpf` group:
   ```bash
   sudo dseditgroup -o edit -a $USER -t user access_bpf
   ```

- **Linux**: Run with `sudo`, grant CAP_NET_RAW capability, or add your user to a capture group:
  ```bash
  # Option 1: Set capabilities on the binary
  sudo setcap cap_net_raw+ep ./etr

  # Option 2: Use wireshark group (if it exists on your system)
  sudo usermod -a -G wireshark $USER
  # Then re-login and set capabilities with group restriction:
  sudo chgrp wireshark ./etr
  sudo chmod 750 ./etr
  sudo setcap cap_net_raw+ep ./etr
  ```

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
- `-T/-U`: TCP (default) or UDP probes
- `-P <n>`: Number of parallel probes (default: 5)
- `-p <port>`: Destination port (default: 443)
- `-c <n>`: Probe iterations (default: 10)
- `-j <file>`: JSON output to file (keeps TUI)
- `-J`: JSON output to stdout (disables TUI)
- `--help`: Full option list

**TUI controls**: `↑/↓` scroll, `←/→` or `Tab` switch views, `q` quit

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
  "source_port": 33434,
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
