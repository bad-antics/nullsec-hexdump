# NullSec HexDump

> **Binary Analysis & Hex Viewer**

[![Zig](https://img.shields.io/badge/zig-0.11+-orange.svg)](https://ziglang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289da.svg)](https://discord.gg/killers)

Binary hex viewer written in Zig demonstrating compile-time safety and explicit error handling.

## Build

```bash
zig build-exe hexdump.zig -O ReleaseFast
```

## Usage

```bash
./hexdump binary.exe
./hexdump -c 32 firmware.bin          # 32 bytes per line
./hexdump -s 0x100 -n 256 file.dat    # Skip 256, read 256
./hexdump --stats malware.bin         # Show statistics
```

## Features

- Color-coded byte classification
- Configurable columns
- Offset skipping
- Length limiting
- Statistics mode
- ASCII representation

## Community

- **Discord**: [discord.gg/killers](https://discord.gg/killers)
- **GitHub**: [bad-antics](https://github.com/bad-antics)
