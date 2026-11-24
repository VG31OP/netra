# Performance & Benchmarks

## Measurements (x86_64 Windows)

- **Packet Parsing Throughput**: ~748,949 packets per second (~1.33 us per packet) in unoptimized debug build.
- **SQLite Database Overhead**: Initial schema size ~44 KB using WAL journal mode.
- **Memory Footprint**: Under 30 MB base memory during streaming file parsing.

## Verification

To run the built-in packet throughput benchmark:

```powershell
netra benchmark
```
