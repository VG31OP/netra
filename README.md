# NETRA
**Cross-Platform Portable Network Intelligence, Packet Analysis & Scanning Platform**

> [!WARNING]
> ### 🚧 UNDER ACTIVE DEVELOPMENT
> NETRA is currently under active development. Core packet parsing, Wireshark-class 3-pane dissection, and Nmap-class network scanning engines are fully operational in both Desktop GUI and CLI.

NETRA is an independent, lightweight, high-performance network intelligence platform implemented in pure Rust. Inspired by the capabilities of **Wireshark** (packet capture, protocol inspection, PCAP/PCAPNG streaming, display filters, hex dump viewer, TCP stream reassembly) and **Nmap** (host discovery, TCP/UDP scanning, service version detection, OS fingerprinting, timing templates), NETRA delivers a single unified binary core optimized for bounded memory and 100% offline execution.

---

## Table of Contents

- [Core Principles](#core-principles)
- [Unified Wireshark + Nmap Capabilities](#unified-wireshark--nmap-capabilities)
  - [Wireshark Capabilities](#wireshark-capabilities)
  - [Nmap Capabilities](#nmap-capabilities)
- [Prerequisites & Building from Source](#prerequisites--building-from-source)
- [Quick Start Guide](#quick-start-guide)
  - [1. Launching NETRA Desktop (Slint GUI)](#1-launching-netra-desktop-slint-gui)
  - [2. Using NETRA CLI (Clap)](#2-using-netra-cli-clap)
- [CLI Command Reference & Examples](#cli-command-reference--examples)
- [Portable Mode Deployment](#portable-mode-deployment)
- [Repository Architecture](#repository-architecture)
- [Running Tests & Benchmarks](#running-tests--benchmarks)
- [License & Authorship](#license--authorship)

---

## Core Principles

- **Zero Telemetry & 100% Offline**: Completely offline operation. No telemetry, background tracking, analytics, or remote vendor network calls.
- **Bounded Memory Streaming**: Large PCAP and PCAPNG capture files process incrementally with bounded memory buffers—never loading large captures into RAM.
- **Portable-First Storage**: Zero-configuration portable operation via `portable.flag` (SQLite WAL journaling) alongside binaries, or automatic system directory fallback.
- **Unified Rust Core**: Both the native Slint Desktop UI and Clap CLI share the exact same underlying processing, scanning, and dissection engines.
- **Pure Independent Implementation**: Clean Apache-2.0 licensed Rust implementation without bundling or wrapping external Wireshark or Nmap binaries.

---

## Unified Wireshark + Nmap Capabilities

### Wireshark Capabilities
- **3-Pane Desktop Interface**:
  1. *Top Pane*: Interactive packet list table with columns `No.`, `Protocol`, `Source`, `Destination`, `Length`, and `Info`.
  2. *Middle Pane*: Hierarchical collapsible packet details tree (Frame, Ethernet II, IPv4/IPv6, TCP/UDP, Application Layer).
  3. *Bottom Pane*: Synchronized Hex & ASCII byte viewer with 16-byte offset rows.
- **Streaming PCAP & PCAPNG Readers**: Incremental block processing supporting standard PCAP and modern PCAPNG formats.
- **Deep Protocol Dissectors**:
  - *Layer 2*: Ethernet II, ARP / RARP
  - *Layer 2*: Ethernet II, ARP / RARP, IEEE 802.1Q VLAN Tagging
  - *Layer 3*: IPv4, IPv6, ICMPv4 (Echo, Unreachable, TTL Exceeded), ICMPv6
  - *Layer 4*: TCP (sequence, acknowledgment, window size, flags), UDP
  - *Layer 7*: HTTP/1.1 (Request/Response headers, status codes), TLS / SSL (ClientHello SNI), DNS (Queries & RR Answers: A, AAAA, CNAME, PTR, MX, TXT), mDNS, DHCP / BOOTP, SSDP, SMBv1/v2/v3, NTP, SSH banner extraction
- **Wireshark Expert Information Engine**:
  - Automatically identifies protocol health issues across 4 severity tiers: *Error*, *Warning*, *Note*, and *Chat*.
  - Detects TCP Zero Window flow control stalls, connection resets (RST), HTTP 4xx/5xx client/server errors, and DNS NXDomain / SERVFAIL anomalies.
- **Wireshark Packet Coloring Rules**:
  - Live color-coding for packet list (Bad TCP in Red, HTTP in Green, TLS in Purple, DNS in Blue, ICMP in Pink, ARP in Yellow).
- **Wireshark Display Filter Engine**:
  - Relational fields: `ip.src`, `ip.dst`, `ip.addr`, `tcp.port`, `udp.port`, `frame.len`, `frame.number`, `http.request.method`, `http.response.code`, `dns.qry.name`, `tls.sni`, `contains`, etc.
  - Boolean operators: `&&`, `and`, `||`, `or`, `!`, `not`.
- **Follow TCP Stream**: Reconstructs complete client and server conversation payloads in chronological sequence.
- **Traffic Statistics**: Protocol hierarchy distribution and IP conversation endpoints matrix.

### Nmap Capabilities
- **Target Specification**:
  - Single IP (e.g. `192.168.1.1`)
  - Subnet CIDR (e.g. `192.168.1.0/24`)
  - IP Range (e.g. `192.168.1.1-50`)
  - Hostnames with DNS resolution (e.g. `scanme.nmap.org`)
- **Scanning Modes**:
  - TCP Connect Scan (`-sT`)
  - UDP Scan (`-sU`) with protocol-specific probes (DNS, NTP, SNMP, SSDP)
- **Service Version Detection (`-sV`)**:
  - Active probe engine interrogating open ports with HTTP, TLS, SSH, FTP, SMTP, MySQL, Redis, and SMB payloads.
  - Automatic extraction of service name, product name, software version, and operating system hints.
- **OS Fingerprinting Engine (`-O`)**:
  - Heuristic analysis based on initial TTL, TCP window sizes, DF flags, and service banner correlations.
  - Identification of Linux, Microsoft Windows, Apple macOS / Darwin, and network embedded devices with confidence scoring.
- **Nmap Hop-by-Hop Traceroute (`--traceroute`)**:
  - Determines network path hops and round-trip latency (RTT) per hop toward target.
- **NETRA Scripting Engine (NSE) / Vulnerability Audit (`-sC`)**:
  - Active security auditing checking for Anonymous FTP login, legacy SMBv1 / EternalBlue exposure, unauthenticated Redis access, and missing HTTP security headers (HSTS, CSP, X-Frame-Options).
- **Port Presets & Custom Expressions**:
  - Fast / Top 100 ports (`-F`)
  - Default Top 1000 ports
  - All 65,535 ports (`-p-`)
  - Custom ranges (`-p 22,80,443,8000-8080`)
- **Nmap Timing Templates**:
  - `T0` (Paranoid), `T1` (Sneaky), `T2` (Polite), `T3` (Normal), `T4` (Aggressive), `T5` (Insane)

---

## Prerequisites & Building from Source

### Prerequisites
- **Rust Toolchain**: Rust 1.80.0 or later (`cargo`, `rustc`).
- **C Compiler**:
  - **Windows**: MinGW-w64 (`gcc`) or MSVC build tools (for SQLite C bindings).
  - **Linux**: `gcc` or `clang`, `libfontconfig1-dev`, `libpcap-dev`.
  - **macOS**: Xcode command-line tools (`clang`).

### Build Commands
```bash
# Clone the repository
git clone https://github.com/VG31OP/netra.git
cd netra

# Build debug binaries
cargo build

# Build optimized release binaries
cargo build --release
```

Compiled executables are located under `target/release/`:
- `netra` (or `netra.exe`): Standalone CLI application.
- `netra-desktop` (or `netra-desktop.exe`): Native graphical Slint interface.

---

## Quick Start Guide

### 1. Launching NETRA Desktop (Slint GUI)
```bash
./target/release/netra-desktop
```
The desktop application provides:
- **Packet Analyzer**: Full 3-pane Wireshark layout. Type a display filter (e.g. `dns || tcp.port == 80`), click any packet to inspect protocol layers and raw hex dump.
- **Nmap Scanner**: Interactive target input, timing template selector, port selection, real-time scan progress, and OS detection card.
- **Network Inventory**: Correlated active hosts, detected operating systems, and open service ports.
- **Traffic Statistics**: Protocol hierarchy statistics and IP conversation endpoints matrix.
- **Settings & Privacy**: Storage path overview, offline guarantees, and license info.

### 2. Using NETRA CLI (Clap)
```bash
# View system status and portable mode detection
netra info

# Run an Nmap-style scan against a target with service and OS detection
netra scan --target 127.0.0.1 --ports top-100 -T 4

# Run a Wireshark-style offline PCAP analysis with display filtering
netra analyze --file sample_capture.pcap --filter "tcp.port == 443"

# Reconstruct a TCP conversation stream (Follow TCP Stream)
netra follow-stream --file sample_capture.pcap --stream-index 0

# Display formatted Hex and ASCII dump of packet #2
netra hexdump --file sample_capture.pcap --index 2

# Display protocol hierarchy and conversation statistics
netra pcap-stats --file sample_capture.pcap
```

---

## CLI Command Reference & Examples

### Nmap Scanning & Discovery
```bash
# Scan top 100 ports with service version detection (-sV) and OS detection (-O)
netra scan --target 192.168.1.1 --ports top-100 -T 3

# Scan all 65,535 ports on an aggressive timing template (T4)
netra scan --target 192.168.1.10 --ports -p- -T 4

# Perform a UDP scan (-sU)
netra scan --target 192.168.1.1 --ports 53,123,161 --sU

# Discover active devices across a local CIDR subnet or IP range
netra discover --target 192.168.1.0/24
netra discover --target 192.168.1.1-50

# Run dedicated OS fingerprinting probe
netra os-detect --target 192.168.1.1

# Run hop-by-hop network path traceroute
netra traceroute --target 8.8.8.8 --max-hops 20

# Launch NETRA Scripting Engine (NSE) vulnerability & security audit
netra audit --target 192.168.1.1 --ports 21,80,443,445,6379,8080
```

### Wireshark Packet Inspection & Forensics
```bash
# Analyze PCAP capture with protocol filter
netra analyze --file capture.pcap --filter "http || dns"

# Run Wireshark Expert Information analysis (errors, warnings, TCP zero window, resets)
netra expert --file capture.pcap

# Filter by source IP and destination port
netra analyze --file capture.pcap --filter "ip.src == 192.168.1.50 && tcp.port == 443"

# Follow TCP stream conversation
netra follow-stream --file capture.pcap --stream-index 0

# Format packet #1 in Wireshark Hex+ASCII layout
netra hexdump --file capture.pcap --index 1

# Generate protocol hierarchy and IP conversation matrix
netra pcap-stats --file capture.pcap
```

### Export & Inventory
```bash
# Export discovered hosts and service inventory to JSON
netra export --format json --output hosts_inventory.json

# Export to CSV
netra export --format csv --output hosts_inventory.csv
```

### Benchmark
```bash
# Run packet parsing throughput benchmark
netra benchmark
```
*Measured performance: ~1.86 million packets/second (~535 ns/packet).*

---

## Portable Mode Deployment

NETRA features zero-configuration portable deployment:

1. Create a file named `portable.flag` in the same directory as `netra.exe` / `netra-desktop.exe`.
2. Run NETRA.
3. All databases, configurations, captures, and logs will be created directly within the portable folder:

```
Portable-Folder/
|-- netra.exe
|-- netra-desktop.exe
|-- portable.flag
|-- sample_capture.pcap
|-- config/
|   `-- settings.toml
|-- data/
|   |-- netra.db (SQLite WAL)
|   |-- captures/
|   `-- exports/
`-- logs/
```

---

## Repository Architecture

```
netra/
|-- apps/
|   |-- desktop/          # Slint graphical desktop interface (3-pane layout)
|   `-- cli/              # Clap command-line interface
|-- crates/
|   |-- netra-common/     # Core domain types (HostRecord, PacketMetadata, MacAddress)
|   |-- netra-config/     # TOML configuration and portable mode path resolver
|   |-- netra-storage/    # SQLite engine with WAL journal and schema migrations
|   |-- netra-protocols/  # Dissectors (ARP, DHCP, DNS, HTTP, ICMP, SMB, NTP, SSH, SSDP, TCP, TLS)
|   |-- netra-parser/     # Streaming PCAP/PCAPNG, PacketTree, HexDumpViewer, StreamReassembler
|   |-- netra-filter/     # Wireshark-style recursive display filter engine
|   |-- netra-capture/    # Cross-platform capture abstraction and PCAP writer export
|   |-- netra-scanner/    # Nmap port scanner, UDP scanner, Service probe engine, OS fingerprinter
|   |-- netra-discovery/  # Subnet CIDR / range parser and concurrent host sweep
|   |-- netra-intelligence/ # Unified correlation linking hosts, IPs, MACs, ports, services, and traffic
|   |-- netra-export/     # Structured JSON and CSV export engine
|   `-- netra-core/       # Engine coordinator facade
|-- dist/
|   `-- portable/         # Ready-to-run portable distribution bundle
|-- Cargo.toml
|-- LICENSE
|-- NOTICE
`-- README.md
```

---

## Running Tests & Benchmarks

Run the complete test suite across all 12 crates:

```bash
cargo test --workspace
```

---

## License & Authorship

- **Author & Maintainer**: VG31OP
- **License**: Apache License 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE) for details).
