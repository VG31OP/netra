# Security Architecture

## Principles

1. **Defensive Parsing**: All network packet decoders perform strict bounds checking on sliced buffers. Malformed or truncated packets are safely handled without panics.
2. **Safe Database Access**: Parameterized SQL queries prevent SQL injection.
3. **Resource Bounds**: Scanners use bounded concurrency semaphores to avoid socket exhaustion.
4. **Authorization Warnings**: Scanning functions operate only on explicitly provided subnets or IP targets.
