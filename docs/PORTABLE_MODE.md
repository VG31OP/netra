# Portable Mode Specification

## Detection Rule

NETRA checks for the presence of a marker file named `portable.flag` in the same directory as the executable.

- **If `portable.flag` is present**: Portable mode is active.
- **If `portable.flag` is absent**: Installed mode is active.

## Directory Structure in Portable Mode

```
NETRA/
|-- netra.exe
|-- netra-desktop.exe
|-- portable.flag
|
|-- config/
|   `-- settings.toml
|
|-- data/
|   |-- netra.db
|   |-- captures/
|   `-- exports/
|
`-- logs/
```

## Invariants

1. All state remains inside the portable folder root.
2. No Windows Registry keys are created.
3. No fallback to user profiles occurs when portable mode is active.
4. Database uses SQLite WAL journal mode with automatic transaction safety.
