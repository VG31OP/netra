# NETRA
**Cross-Platform Portable Network Intelligence & Packet Analysis Platform**

NETRA is an independent, lightweight, high-performance network intelligence platform implemented in Rust. Inspired by Wireshark and Nmap, NETRA provides offline packet inspection, PCAP/PCAPNG analysis, subnet discovery, port scanning, and unified network inventory correlation—optimized for bounded memory and offline execution.

---

## Table of Contents

- [Core Principles](#core-principles)
- [Prerequisites](#prerequisites)
- [Build Instructions](#build-instructions)
- [Quick Start Guide](#quick-start-guide)
  - [1. Launching NETRA Desktop](#1-launching-netra-desktop)
  - [2. Using NETRA CLI](#2-using-netra-cli)
- [CLI Command Reference & Examples](#cli-command-reference--examples)
- [Portable Mode Setup](#portable-mode-setup)
- [Architecture & Crates](#architecture--crates)
- [Running Tests & Benchmarks](#running-tests--benchmarks)
- [License](#license)

---

## Core Principles

- **Offline-First & Zero Telemetry**: Operates completely offline with zero telemetry, background tracking, or remote vendor requests.
- **Bounded Memory Processing**: Large PCAP and PCAPNG capture files are streamed incrementally without loading entire payloads into RAM.
- **Portable & Installed Storage**: Operates in standard OS directories or as a self-contained portable bundle beside a `portable.flag` file.
- **Shared Rust Core**: Both the desktop UI (Slint) and CLI (Clap) share the exact same underlying processing engine.

---

## Prerequisites

To build NETRA from source, ensure you have:

- **Rust Toolchain**: Rust 1.80.0 or later (`cargo`, `rustc`).
- **C Compiler**:
  - **Windows**: MinGW-w64 (`gcc`) or MSVC build tools (for SQLite C bindings).
  - **Linux**: `gcc` or `clang`, `libfontconfig1-dev`, `libpcap-dev`.
  - **macOS**: Xcode command-line tools (`clang`).

---

## Build Instructions

Clone the repository and build the workspace:

```bash
# Clone the repository
git clone https://github.com/netra-project/netra.git
cd netra

# Build all workspace crates and applications (Debug)
cargo build

# Build optimized release binaries
cargo build --release
```

Compiled binaries will be generated under `target/release/` (or `target/debug/`):
- `netra` (or `netra.exe`): Command-line interface.
- `netra-desktop` (or `netra-desktop.exe`): Slint graphical desktop interface.

---

## Quick Start Guide

### 1. Launching NETRA Desktop

Launch the native graphical interface:

```bash
# Using cargo
cargo run -p netra-desktop

# Or directly from the built executable
./target/release/netra-desktop
```

The desktop UI provides:
- **Overview**: Active storage mode, total hosts discovered, and parsed packets count.
- **Packet Analyzer**: Load and inspect PCAP/PCAPNG files with live table display.
- **Network Discovery**: Subnet scanner interface.
- **Settings & Privacy**: Storage path overview, offline guarantees, and license info.

---

### 2. Using NETRA CLI

The `netra` CLI is a standalone binary with intuitive commands:

```bash
# Display system environment and storage details
cargo run -p netra-cli -- info
```

---

## CLI Command Reference & Examples

### System Information & Storage Inspection
```bash
# View storage paths, portable status, and environment
netra info

# Check SQLite database size and stored host records
netra storage

# Display active TOML configuration
netra config
```

### Offline Packet Analysis (PCAP & PCAPNG)
```bash
# Analyze a PCAP capture file
netra analyze --file capture.pcap

# Analyze with a protocol filter (e.g. dns, http, tls, tcp, udp, arp, icmp)
netra analyze --file capture.pcap --filter dns

# Analyze with an IP filter
netra analyze --file capture.pcap --filter "host 192.168.1.50"

# Limit output rows (default is 50)
netra analyze --file capture.pcap --limit 20
```

### Local Subnet Discovery
Scan an authorized local network range to detect active devices:
```bash
# Discover responsive hosts on a /24 subnet
netra discover --subnet 192.168.1.0/24

# Tune concurrency for faster or lower-impact scanning
netra discover --subnet 10.0.0.0/24 --concurrency 50
```

### Port & Service Scanning
Perform controlled TCP port scanning with banner grabbing on a target host:
```bash
# Scan common ports on a host
netra scan --target 192.168.1.1

# Scan custom port list
netra scan --target 192.168.1.10 --ports 22,80,443,3306,8080 --concurrency 100
```

### Exporting Host Inventory & Observations
Export correlated network intelligence records (IP, MAC, open ports, services, timestamps) into structured formats:
```bash
# Export to JSON
netra export --format json --output hosts_inventory.json

# Export to CSV
netra export --format csv --output hosts_inventory.csv
```

### Throughput Benchmarking
Run the built-in packet parsing throughput test:
```bash
netra benchmark
```

---

## Portable Mode Setup

NETRA features zero-configuration portable deployment:

1. Create a file named `portable.flag` in the same directory as `netra.exe` / `netra-desktop.exe`.
2. Run NETRA.
3. All databases, configurations, captures, and logs will be created directly within the portable folder:

```
Portable-Folder/
|-- netra.exe
|-- netra-desktop.exe
|-- portable.flag
|-- config/
|   `-- settings.toml
|-- data/
|   |-- netra.db
|   |-- captures/
|   `-- exports/
`-- logs/
```

*When `portable.flag` is omitted, NETRA automatically uses standard operating system directories (`AppData` on Windows, `~/.local/share` on Linux, `Application Support` on macOS).*

---

## Architecture & Crates

The codebase is structured into modular, independently testable crates:

| Crate | Responsibility |
|---|---|
| `netra-common` | Core domain types (`HostRecord`, `PacketMetadata`, `MacAddress`, `NetraError`) |
| `netra-config` | TOML configuration loader and portable mode path resolver |
| `netra-storage` | SQLite engine with WAL journal mode, transactions, and schema migrations |
| `netra-protocols` | Protocol decoders (ARP, DNS, HTTP, TLS Client Hello SNI) |
| `netra-parser` | Streaming PCAP and PCAPNG readers with bounded memory allocation |
| `netra-filter` | Expression filter engine (protocols, IP addresses, ports) |
| `netra-capture` | Cross-platform capture abstractions and PCAP writer export |
| `netra-scanner` | Asynchronous TCP and UDP port scanner with concurrency control |
| `netra-discovery` | Subnet CIDR calculation and concurrent host discovery sweep |
| `netra-intelligence` | Correlation engine linking hosts, IPs, MACs, ports, services, and traffic |
| `netra-export` | Structured export serializers for JSON and CSV |
| `netra-core` | High-level facade coordinating storage, scanning, parsing, and intelligence |
| `apps/cli` | Command-line interface executable (`netra`) |
| `apps/desktop` | Native desktop graphical interface (`netra-desktop`) |

---

## Running Tests & Benchmarks

Run the full workspace test suite:

```bash
# Run all unit and integration tests
cargo test

# Run a specific integration test
cargo test -p netra-core --test test_pcap_analysis
```

---

## License

This project is licensed under the **Apache License, Version 2.0**.  
See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
