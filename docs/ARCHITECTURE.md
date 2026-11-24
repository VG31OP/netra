# NETRA Architecture

## Modular Workspace Design

NETRA is structured as a layered Rust workspace:

```
+-----------------------------------------------------------+
|                   Applications Layer                      |
|       netra-cli (CLI)       |     netra-desktop (Slint)   |
+-----------------------------------------------------------+
                             |
                             v
+-----------------------------------------------------------+
|                     netra-core                            |
|             Unified Orchestration Facade                  |
+-----------------------------------------------------------+
    |           |            |             |           |
    v           v            v             v           v
+---------+ +---------+ +----------+ +----------+ +---------+
| Capture | | Parser  | | Scanner  | | Discovery| | Export  |
+---------+ +---------+ +----------+ +----------+ +---------+
    |           |            |             |           |
    |           +------------+-------------+           |
    |                        |                         |
    v                        v                         v
+---------+            +------------+             +---------+
|Protocols|            |Intelligence|             | Storage |
+---------+            +------------+             +---------+
    \                        |                        /
     \                       v                       /
      +----------------> netra-common <---------------+
                             ^
                             |
                       netra-config
```

## Storage & Portability

- **Installed Mode**: Stores configuration in system config directories and databases under standard application data directories.
- **Portable Mode**: When `portable.flag` exists in the executable directory, all state is isolated to `data/`, `config/`, and `logs/` inside the portable bundle.

## Memory Bounding

- Packets are streamed using chunked iterations over PCAP/PCAPNG blocks.
- Metadata is decoupled from raw payload bytes to minimize allocation overhead during large file analyses.
