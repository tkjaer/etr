# ETR Visualization Tools

Tools for visualizing ETR traceroute results.

## path-diagram

Generate a merged DAG (directed acyclic graph) from ETR JSON output showing
ECMP path diversity. Paths that share hops are merged, and divergence/convergence
points are clearly visible.

**Features:**
- PNG/SVG/PDF output via Graphviz
- Merged DAG — shared hops appear once, branches fan out and rejoin
- Dark mode support
- Reads both probe-run JSON and discovery summary format

**Requirements:**
```bash
pip install graphviz      # Python bindings
brew install graphviz     # macOS
apt-get install graphviz  # Linux
```

### Usage

```bash
# From discovery output
etr -D -j paths.json example.com
./examples/visualize/path-diagram paths.json

# SVG (better for zooming)
./examples/visualize/path-diagram paths.json --output paths.svg

# Dark mode
./examples/visualize/path-diagram paths.json --output paths-dark.png --dark

# From stdin
etr -D -J example.com 2>/dev/null | ./examples/visualize/path-diagram -
```
```

Branch labels like `[dc297,e7b6d]` show which path hashes use that edge.
Edges used by all paths have no label.
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
