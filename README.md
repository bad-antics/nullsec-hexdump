# NullSec HexDump

> **Binary Analysis & Hex Viewer**

[![Zig](https://img.shields.io/badge/zig-0.11+-orange.svg)](https://ziglang.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![X/Twitter](https://img.shields.io/badge/Twitter-Follow-1DA1F2.svg)](https://x.com/AnonAntics)

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

- **Twitter**: [x.com/AnonAntics](https://x.com/AnonAntics)
- **GitHub**: [bad-antics](https://github.com/bad-antics)
