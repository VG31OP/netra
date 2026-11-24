# NETRA

NETRA is an independent, lightweight, cross-platform network intelligence and packet inspection platform written in Rust.

## Architecture

NETRA uses a modular Cargo workspace separating core processing, network parsing, protocol dissectors, scanning, storage, intelligence correlation, and interfaces:

- `crates/netra-common`: Core domain types, errors, timestamps, network identifiers.
- `crates/netra-config`: TOML configuration loader and portable mode path resolver.
- `crates/netra-storage`: SQLite storage engine with WAL journaling and schema migrations.
- `crates/netra-protocols`: Protocol decoders for ARP, DNS, HTTP, and TLS SNI.
- `crates/netra-parser`: Streaming PCAP and PCAPNG readers with bounded memory.
- `crates/netra-filter`: Expression matching engine for protocols, addresses, and ports.
- `crates/netra-capture`: Capture adapter abstractions and PCAP export facilities.
- `crates/netra-scanner`: Asynchronous TCP and UDP port scanner with concurrency control.
- `crates/netra-discovery`: Subnet CIDR calculation and responsive host discovery.
- `crates/netra-intelligence`: Unified host, service, observation, and traffic correlation.
- `crates/netra-export`: Structured export utilities for JSON and CSV.
- `crates/netra-core`: High-level engine coordinator.
- `apps/cli`: Standalone command-line interface executable (`netra`).
- `apps/desktop`: Native graphical desktop application shell (`netra-desktop`).

## Core Principles

- **Offline-First & Zero Telemetry**: Operates completely disconnected from the Internet with zero tracking.
- **Portable & Installed Storage**: Automatically switches between local folder mode (via `portable.flag`) and standard operating system directories.
- **Bounded Memory**: Streaming packet reader architecture prevents out-of-memory errors on large capture files.
- **Independent Rust Implementation**: Built with clean, safe Rust libraries.
