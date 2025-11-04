# ETR Examples

This directory contains practical examples and tools that complement ETR for network analysis and testing.

## Examples

### `/monitoring`
Prometheus + Grafana monitoring stack for visualizing ETR data in real-time. Shows how to collect and display ECMP path metrics using Docker containers.

### `/request`
Simple HTTP client that binds to specific source ports. Useful for testing HTTP traffic on ECMP paths discovered by ETR.

### `/visualize`
Path visualization tools that generate ASCII diagrams and Graphviz images from ETR JSON output, showing ECMP path diversity and flow information.

## Development

These examples were built as simple, focused tools to demonstrate ETR integration patterns. They were developed with assistance from GitHub Copilot to quickly prototype useful network testing utilities.

Each example includes its own README with detailed usage instructions and integration workflows.

## Contributing

Feel free to submit additional examples that showcase ETR usage in different scenarios or integrate with other network tools and monitoring systems.
