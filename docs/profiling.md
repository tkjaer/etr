# Profiling (pprof)

This document describes how to capture CPU and memory profiles for ETR using Go’s built-in pprof tooling.

## CLI flags

- `--pprof-addr` starts a local HTTP server with pprof endpoints (e.g. `127.0.0.1:6060`).
- `--cpu-profile` writes a CPU profile to the specified file.
- `--mem-profile` writes a heap profile to the specified file on exit.
- `--mutex-profile` enables mutex profiling (rate, e.g. `10`) for `/debug/pprof/mutex`.
- `--block-profile` enables block profiling (ns, e.g. `1000000`) for `/debug/pprof/block`.

## Common workflows

### 1) Interactive pprof via HTTP

Start ETR with a local pprof server:

- Example: `etr --pprof-addr 127.0.0.1:6060 <destination>`

Then inspect from another terminal:

- `go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=30`
- `go tool pprof http://127.0.0.1:6060/debug/pprof/heap`
- `go tool pprof http://127.0.0.1:6060/debug/pprof/goroutine`
- `go tool pprof http://127.0.0.1:6060/debug/pprof/mutex`
- `go tool pprof http://127.0.0.1:6060/debug/pprof/block`

### 2) CPU profile to file

- Example: `etr --cpu-profile cpu.pprof <destination>`
- Analyze: `go tool pprof cpu.pprof`

### 3) Heap profile to file

- Example: `etr --mem-profile heap.pprof <destination>`
- Analyze: `go tool pprof heap.pprof`

## Suggested scenarios

Capture profiles for representative runs:

- Short run: few probes, default settings.
- Long run: high `--count`, or `--count 0` for continuous.
- Stress run: higher `--parallel-probes` and `--max-ttl`.
- Output comparison: TUI vs JSON (`--json` or `--json-file`).

## Tips

- Record CPU profiles during steady state (30–60 seconds is usually enough).
- For memory, capture at the end of a long run to surface growth.
- Use `top`, `list`, and `web` inside `go tool pprof` to drill in.
