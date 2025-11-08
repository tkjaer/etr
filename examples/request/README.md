# HTTP Request Tool

A simple HTTP client that binds to a specific source port for testing ECMP paths discovered by ETR.

## Usage

```bash
go run request.go [options] <URL>
```

## Options

- `-p <port>`: Source port to bind to (required)
- `-4`: Force IPv4
- `-6`: Force IPv6
- `-t <duration>`: Request timeout (default: 30s)
- `-v`: Verbose output

**Note**: If the specified port is within the ephemeral port range (typically 32768-65535 on Linux, 49152-65535 on macOS/Windows), the bind may fail if the port is already in use by another process. Simply try again with the same port or use a different port number.

To check your system's ephemeral port range:
- **Linux**: `cat /proc/sys/net/ipv4/ip_local_port_range`
- **macOS**: `sysctl net.inet.ip.portrange.first net.inet.ip.portrange.last`

## Examples

```bash
# Basic request from source port 50000
go run request.go -p 50000 https://example.com

# Verbose output with IPv4 forced
go run request.go -p 50000 -4 -v https://example.com

# IPv6 request with custom timeout
go run request.go -p 50000 -6 -t 10s -v https://example.com

# Save response to file
go run request.go -p 50000 https://example.com > response.html
```

## Use Case: Testing ECMP Paths

After discovering network paths with ETR, you can test HTTP traffic on the same paths:

```bash
# 1. Discover ECMP paths with ETR
etr -P 10 -j paths.json example.com

# 2. Analyze paths and pick a source port
jq -r '.source_port' paths.json | sort -u

# 3. Test HTTP requests using the same source port
go run request.go -p 50000 -v https://example.com
```

This ensures your HTTP traffic follows the same network path that ETR discovered, useful for:
- Testing specific ECMP routes
- Debugging path-specific issues
- Performance testing on known paths
- Reproducing network behavior

## Output

In verbose mode, shows:
- Source port and IP version used
- Connection details
- Response time
- HTTP status and headers
- Content length

Response body is always written to stdout (like curl).
