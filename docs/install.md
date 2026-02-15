# Installing ETR

ETR can be installed via pre-built binaries (macOS/Linux), Homebrew (future), or from source on macOS, Linux, and BSD systems. This document collects the platform-specific steps that were previously in the root README.

## Pre-built Binaries (macOS/Linux)

Download the latest release from the [GitHub Releases page](https://github.com/tkjaer/etr/releases).

### macOS Gatekeeper Warning

Because the binary is currently unsigned and un-notarized, macOS may display:

> "Apple cannot verify this app is free of malware"

You can still run it using one of these options:

1. **Finder**: Right-click (or Control-click) the binary → **Open** → confirm the prompt.
2. **System Settings**: System Settings → Privacy & Security → permit the blocked app, then run it again and approve the prompt.
3. **Terminal**: Remove the quarantine flag:
   ```bash
   xattr -d com.apple.quarantine ./etr-darwin-arm64
   ./etr-darwin-arm64 --version
   ```

Optionally verify the checksum first (replace the filename to match your download):
```bash
shasum -a 256 etr-darwin-arm64
```

Once approved, macOS remembers the trust decision until the binary is replaced.

## Building From Source

ETR requires the Go toolchain plus libpcap headers.

### Install Dependencies

**Debian / Ubuntu**
```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

**RHEL / CentOS / Fedora**
```bash
sudo dnf install libpcap-devel
```

**Arch Linux**
```bash
sudo pacman -S libpcap
```

**macOS**
```bash
brew install libpcap
```

### Build / Install

The simplest install is:
```bash
go install github.com/tkjaer/etr/cmd/etr@latest
```

To build locally:
```bash
git clone https://github.com/tkjaer/etr.git
cd etr
go build -o etr ./cmd/etr
```

## Homebrew (macOS/Linux)

```bash
brew tap tkjaer/tap
brew install etr
```

## BSD Systems

ETR supports FreeBSD, OpenBSD, and NetBSD (Ethernet source interfaces only on OpenBSD/NetBSD). Pre-built binaries are not available; build from source after installing:

**FreeBSD**
```bash
pkg install go libpcap
```

**OpenBSD**
```bash
pkg_add go libpcap
```

**NetBSD**
```bash
pkgin install go libpcap
```

Then:
```bash
go install github.com/tkjaer/etr/cmd/etr@latest
```

## Permissions

ETR needs raw socket access.

**macOS**
- Run with `sudo`, *or*
- Add your user to the `access_bpf` group:
  ```bash
  sudo dseditgroup -o edit -a $USER -t user access_bpf
  ```

**Linux**
- Run with `sudo`, *or*
- Grant `CAP_NET_RAW` to the binary:
  ```bash
  sudo setcap cap_net_raw+ep ./etr
  ```
- Optionally restrict execution to a capture group (e.g., `wireshark`):
  ```bash
  sudo usermod -a -G wireshark $USER
  sudo chgrp wireshark ./etr
  sudo chmod 750 ./etr
  sudo setcap cap_net_raw+ep ./etr
  ```

These instructions also apply when installing via `go install` (just adjust the binary path).
