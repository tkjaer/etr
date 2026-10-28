# Contributing

Thanks for your interest in ETR.

ETR is a single-person project, written and maintained in spare time. The project is intentionally small in scope and already does most of what it should. As a result, I’m cautious about new features and broad changes.

## Before you propose changes

- Check existing issues and discussions.
- Prefer small, focused fixes over new features.
- Expect that some feature requests may be declined to keep scope tight.

## Submitting changes

- Open an issue first for non-trivial changes.
- Keep pull requests small and well-scoped.
- Include a clear description of the problem and the rationale for the change.
- Ensure code builds and tests pass (where applicable).

## Reporting bugs

Please include:

- ETR version (`etr -v`)
- Operating system and version
- Command line used
- Expected vs. actual behavior
- Logs or output (redact sensitive data)

### Collecting a packet capture

For problems with hops, paths or probe results, a packet capture of the same run as the JSON output shows what actually happened on the wire.

`etr -B` prints the BPF filter ETR uses, so tcpdump captures only the probe traffic. Use an IP address as the destination and the same options in steps 1 and 2. Start with `-c 1 -P 1`, and only raise `-c` (probe count) or `-P` (parallel probes) if the problem doesn't show up.

1. Start a capture:

   ```sh
   sudo tcpdump -w etr.pcap "$(etr <options> -c 1 -P 1 <destination> -B)"
   ```

2. In another terminal, run ETR with JSON output:

   ```sh
   sudo etr <options> -c 1 -P 1 -J <destination>
   ```

3. Stop the capture (Ctrl-C) and display it:

   ```sh
   tcpdump -nSv -r etr.pcap
   ```

Include both outputs in the issue. If you're comfortable sharing it, you can also attach `etr.pcap` compressed as `.zip` or `.gz` (GitHub doesn't accept `.pcap` files directly). Attachments on public repositories are publicly accessible.

## Code of conduct

Be respectful and constructive. Abuse, harassment, or toxic behavior will not be tolerated.

Thanks for understanding the project’s scope and constraints.
