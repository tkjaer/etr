# ETR Examples

This directory contains practical examples and tools that complement ETR for network analysis and testing.

## Examples

### `/monitoring`
Prometheus + Grafana stack that visualizes ECMP paths from ETR JSON output: an overview of all targets (source → destination) with a per-target deep dive showing a live hop topology (Node Graph) colored by loss, per-flow path changes over time, and latency, loss and jitter per flow and per hop. Includes a demo mode with synthetic data, so no root or real target is needed.

### `/request`
Simple HTTP client that binds to specific source ports. Useful for testing HTTP traffic on ECMP paths discovered by ETR.

### `/visualize`
Path visualization tools that generate ASCII diagrams and Graphviz images from ETR JSON output, showing ECMP path diversity and flow information.

## Development

These examples were built as simple, focused tools to demonstrate ETR integration patterns. They were developed with assistance from GitHub Copilot to quickly prototype useful network testing utilities.

Each example includes its own README with detailed usage instructions and integration workflows.

## Contributing

Feel free to submit additional examples that showcase ETR usage in different scenarios or integrate with other network tools and monitoring systems.
