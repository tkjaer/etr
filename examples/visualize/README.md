# ETR Visualization Tools

Tools for visualizing ETR traceroute results.

## path-diagram

Generate visual diagrams from ETR JSON output showing ECMP path diversity.

**Features:**
- ASCII output - terminal-friendly text visualization
- Image output - PNG/SVG/PDF diagrams with Graphviz
- Color-coded paths showing common vs divergent hops
- Dark mode support for images
- 5-tuple flow information display
- Path statistics and distribution

### ASCII Mode (no dependencies)

```bash
# Basic ASCII output
./examples/visualize/path-diagram --ascii examples/monitoring/data/etr.json

# stdin
./etr --count 5 --tcp -J 192.0.2.1 | ./path-diagram --ascii -
```

### Image Mode (requires graphviz)

```bash
# Install dependencies
pip install graphviz      # pip
brew install graphviz     # macOS
apt-get install graphviz  # Linux

# Generate PNG diagram
./examples/visualize/path-diagram examples/monitoring/data/etr.json

# Generate SVG (better for zooming)
./examples/visualize/path-diagram examples/monitoring/data/etr.json --output paths.svg

# Generate PDF
./examples/visualize/path-diagram examples/monitoring/data/etr.json --output paths.pdf

# Dark mode (for dark backgrounds)
./examples/visualize/path-diagram examples/monitoring/data/etr.json --output paths-dark.png --dark
```

### Color Legend

**Image Mode:**
- 🟢 Green: Common hop (same across all paths)
- 🟠 Orange: Different hop (ECMP divergence)
- 🟡 Yellow: Timeout (no response)

**ASCII Mode:**
- `[COMMON]` - Same across all paths
- `<DIFFER>` - ECMP divergence point
- `*` - Timeout

### Example Output

```
====================================================================================================
ETR Path Diagram - Destination: 8.8.8.8 (dns.google)
Total Probes: 75 | Unique Paths: 7
====================================================================================================

Legend: [COMMON] = Same across all paths  |  <DIFFER> = ECMP divergence  |  * = Timeout
====================================================================================================

Path 1: 20386dc3 - 15 probes (20.0%)
Flow: 10.0.1.51:33438 -> 8.8.8.8:443 (TCP)
----------------------------------------------------------------------------------------------------
TTL  1 │ [COMMON] │ 10.0.1.1
TTL  2 │ [COMMON] │ 91.100.34.1 (91.100.34.1.generic-hostname.arrownet.dk)
TTL  3 │ [COMMON] │ 85.24.4.1 (85.24.4.1.generic-hostname.arrownet.dk)
TTL  4 │ <DIFFER> │ 62.61.140.120 (62.61.140.120.generic-hostname.danskkabeltv.dk)
TTL  5 │ [COMMON] │ 82.150.156.122 (danskkabel.ixcph1.openpeering.nl)
TTL  6 │ [COMMON] │ 217.170.0.243 (telecity-cr.openpeering.nl)
TTL  7 │    *     │ * * * (timeout)
TTL  8 │ <DIFFER> │ 74.125.242.187
TTL  9 │ <DIFFER> │ 142.251.225.135
TTL 10 │ [COMMON] │ 8.8.8.8 (dns.google)
```

The **Flow** line shows the 5-tuple (source IP:port → destination IP:port + protocol) that identifies which network flow took this path. This is useful for understanding ECMP path selection and reproducing specific paths.

### Usage

```
./path-diagram [OPTIONS] INPUT

Arguments:
  INPUT              ETR JSON file (use - for stdin)

Options:
  --ascii            Generate ASCII output instead of image
  -o, --output FILE  Output filename (default: etr-paths.png for image, stdout for ASCII)
  --dark             Use dark mode color scheme for image output
  -h, --help         Show help message
```
