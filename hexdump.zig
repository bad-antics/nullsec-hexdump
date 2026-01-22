// NullSec HexDump - Binary Analysis & Hex Viewer
// Zig security tool demonstrating:
//   - Compile-time safety
//   - No hidden control flow
//   - Optional types
//   - Explicit error handling
//   - Manual memory management
//
// Author: bad-antics
// License: MIT

const std = @import("std");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const fmt = std.fmt;

const VERSION = "1.0.0";

// Configuration
const Config = struct {
    bytes_per_line: usize = 16,
    show_ascii: bool = true,
    show_offset: bool = true,
    uppercase: bool = false,
    color: bool = true,
    start_offset: usize = 0,
    length: ?usize = null,
};

// ANSI colors
const Color = struct {
    const reset = "\x1b[0m";
    const gray = "\x1b[90m";
    const cyan = "\x1b[36m";
    const yellow = "\x1b[33m";
    const green = "\x1b[32m";
    const red = "\x1b[31m";
    const magenta = "\x1b[35m";
};

// Byte classification for coloring
const ByteClass = enum {
    null,
    printable,
    whitespace,
    high,
    control,
};

fn classifyByte(byte: u8) ByteClass {
    if (byte == 0) return .null;
    if (byte >= 0x20 and byte < 0x7f) return .printable;
    if (byte == 0x09 or byte == 0x0a or byte == 0x0d) return .whitespace;
    if (byte >= 0x80) return .high;
    return .control;
}

fn getByteColor(class: ByteClass) []const u8 {
    return switch (class) {
        .null => Color.gray,
        .printable => Color.green,
        .whitespace => Color.cyan,
        .high => Color.yellow,
        .control => Color.red,
    };
}

// Hex dump a single line
fn dumpLine(
    writer: anytype,
    offset: usize,
    data: []const u8,
    config: Config,
) !void {
    // Print offset
    if (config.show_offset) {
        if (config.color) {
            try writer.print("{s}{x:0>8}{s}  ", .{ Color.cyan, offset, Color.reset });
        } else {
            try writer.print("{x:0>8}  ", .{offset});
        }
    }

    // Print hex bytes
    for (data, 0..) |byte, i| {
        const class = classifyByte(byte);
        
        if (config.color) {
            const color = getByteColor(class);
            if (config.uppercase) {
                try writer.print("{s}{X:0>2}{s} ", .{ color, byte, Color.reset });
            } else {
                try writer.print("{s}{x:0>2}{s} ", .{ color, byte, Color.reset });
            }
        } else {
            if (config.uppercase) {
                try writer.print("{X:0>2} ", .{byte});
            } else {
                try writer.print("{x:0>2} ", .{byte});
            }
        }

        // Add extra space at midpoint
        if (i == 7) {
            try writer.writeAll(" ");
        }
    }

    // Pad if line is short
    if (data.len < config.bytes_per_line) {
        const missing = config.bytes_per_line - data.len;
        for (0..missing) |i| {
            try writer.writeAll("   ");
            if (data.len + i == 7) {
                try writer.writeAll(" ");
            }
        }
    }

    // Print ASCII representation
    if (config.show_ascii) {
        try writer.writeAll(" |");
        for (data) |byte| {
            const class = classifyByte(byte);
            const char: u8 = if (class == .printable) byte else '.';
            
            if (config.color) {
                const color = getByteColor(class);
                try writer.print("{s}{c}{s}", .{ color, char, Color.reset });
            } else {
                try writer.print("{c}", .{char});
            }
        }
        
        // Pad ASCII if short
        if (data.len < config.bytes_per_line) {
            for (0..(config.bytes_per_line - data.len)) |_| {
                try writer.writeAll(" ");
            }
        }
        try writer.writeAll("|");
    }

    try writer.writeAll("\n");
}

// Statistics
const Stats = struct {
    total_bytes: usize = 0,
    null_bytes: usize = 0,
    printable_bytes: usize = 0,
    high_bytes: usize = 0,
    control_bytes: usize = 0,
    unique_bytes: [256]bool = [_]bool{false} ** 256,

    fn update(self: *Stats, byte: u8) void {
        self.total_bytes += 1;
        self.unique_bytes[byte] = true;
        
        switch (classifyByte(byte)) {
            .null => self.null_bytes += 1,
            .printable => self.printable_bytes += 1,
            .whitespace => self.printable_bytes += 1,
            .high => self.high_bytes += 1,
            .control => self.control_bytes += 1,
        }
    }

    fn uniqueCount(self: *const Stats) usize {
        var count: usize = 0;
        for (self.unique_bytes) |present| {
            if (present) count += 1;
        }
        return count;
    }

    fn entropy(self: *const Stats) f64 {
        if (self.total_bytes == 0) return 0.0;
        
        var byte_counts = [_]usize{0} ** 256;
        _ = byte_counts; // Would need actual counts for real entropy
        
        // Simplified entropy estimate based on unique bytes
        const unique = @as(f64, @floatFromInt(self.uniqueCount()));
        const total = @as(f64, @floatFromInt(self.total_bytes));
        return unique / 256.0 * 8.0; // Rough estimate
    }
};

fn printStats(writer: anytype, stats: *const Stats, config: Config) !void {
    if (config.color) {
        try writer.print("\n{s}═══════════════════════════════════════════{s}\n", .{ Color.gray, Color.reset });
    } else {
        try writer.writeAll("\n═══════════════════════════════════════════\n");
    }
    
    try writer.print("Total bytes:     {d}\n", .{stats.total_bytes});
    try writer.print("Unique bytes:    {d}/256\n", .{stats.uniqueCount()});
    try writer.print("Null bytes:      {d} ({d:.1}%)\n", .{
        stats.null_bytes,
        if (stats.total_bytes > 0) @as(f64, @floatFromInt(stats.null_bytes)) / @as(f64, @floatFromInt(stats.total_bytes)) * 100.0 else 0.0,
    });
    try writer.print("Printable:       {d} ({d:.1}%)\n", .{
        stats.printable_bytes,
        if (stats.total_bytes > 0) @as(f64, @floatFromInt(stats.printable_bytes)) / @as(f64, @floatFromInt(stats.total_bytes)) * 100.0 else 0.0,
    });
    try writer.print("High bytes:      {d} ({d:.1}%)\n", .{
        stats.high_bytes,
        if (stats.total_bytes > 0) @as(f64, @floatFromInt(stats.high_bytes)) / @as(f64, @floatFromInt(stats.total_bytes)) * 100.0 else 0.0,
    });
}

fn printBanner(writer: anytype) !void {
    try writer.writeAll(
        \\
        \\╔══════════════════════════════════════════════════════════════════╗
        \\║            NullSec HexDump - Binary Analysis Tool                ║
        \\╚══════════════════════════════════════════════════════════════════╝
        \\
    );
}

fn printHelp(writer: anytype) !void {
    try printBanner(writer);
    try writer.writeAll(
        \\
        \\USAGE:
        \\    hexdump [OPTIONS] <FILE>
        \\
        \\OPTIONS:
        \\    -h, --help          Show this help
        \\    -c, --columns N     Bytes per line (default: 16)
        \\    -s, --skip N        Skip N bytes from start
        \\    -n, --length N      Read only N bytes
        \\    -u, --uppercase     Uppercase hex
        \\    -A, --no-ascii      Hide ASCII column
        \\    -O, --no-offset     Hide offset column
        \\    --no-color          Disable colors
        \\    --stats             Show statistics
        \\
        \\EXAMPLES:
        \\    hexdump binary.exe
        \\    hexdump -c 32 firmware.bin
        \\    hexdump -s 0x100 -n 256 file.dat
        \\    hexdump --stats malware.bin
        \\
    );
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = io.getStdOut().writer();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var config = Config{};
    var filename: ?[]const u8 = null;
    var show_stats = false;

    // Parse arguments
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            try printHelp(stdout);
            return;
        } else if (mem.eql(u8, arg, "-c") or mem.eql(u8, arg, "--columns")) {
            i += 1;
            if (i >= args.len) {
                try stdout.writeAll("Error: -c requires a value\n");
                return;
            }
            config.bytes_per_line = try fmt.parseInt(usize, args[i], 10);
        } else if (mem.eql(u8, arg, "-s") or mem.eql(u8, arg, "--skip")) {
            i += 1;
            if (i >= args.len) {
                try stdout.writeAll("Error: -s requires a value\n");
                return;
            }
            config.start_offset = try parseNumber(args[i]);
        } else if (mem.eql(u8, arg, "-n") or mem.eql(u8, arg, "--length")) {
            i += 1;
            if (i >= args.len) {
                try stdout.writeAll("Error: -n requires a value\n");
                return;
            }
            config.length = try parseNumber(args[i]);
        } else if (mem.eql(u8, arg, "-u") or mem.eql(u8, arg, "--uppercase")) {
            config.uppercase = true;
        } else if (mem.eql(u8, arg, "-A") or mem.eql(u8, arg, "--no-ascii")) {
            config.show_ascii = false;
        } else if (mem.eql(u8, arg, "-O") or mem.eql(u8, arg, "--no-offset")) {
            config.show_offset = false;
        } else if (mem.eql(u8, arg, "--no-color")) {
            config.color = false;
        } else if (mem.eql(u8, arg, "--stats")) {
            show_stats = true;
        } else if (arg[0] != '-') {
            filename = arg;
        }
    }

    if (filename == null) {
        try printHelp(stdout);
        return;
    }

    // Open file
    const file = fs.cwd().openFile(filename.?, .{}) catch |err| {
        try stdout.print("Error opening file: {}\n", .{err});
        return;
    };
    defer file.close();

    // Skip bytes if requested
    if (config.start_offset > 0) {
        file.seekTo(config.start_offset) catch |err| {
            try stdout.print("Error seeking: {}\n", .{err});
            return;
        };
    }

    try printBanner(stdout);
    try stdout.print("File: {s}\n\n", .{filename.?});

    // Read and dump
    var buffer: [4096]u8 = undefined;
    var offset = config.start_offset;
    var bytes_read: usize = 0;
    var stats = Stats{};
    const max_bytes = config.length orelse std.math.maxInt(usize);

    while (bytes_read < max_bytes) {
        const to_read = @min(buffer.len, max_bytes - bytes_read);
        const n = file.read(buffer[0..to_read]) catch |err| {
            try stdout.print("Error reading: {}\n", .{err});
            return;
        };
        
        if (n == 0) break;

        // Process in lines
        var line_start: usize = 0;
        while (line_start < n) {
            const line_end = @min(line_start + config.bytes_per_line, n);
            const line_data = buffer[line_start..line_end];
            
            try dumpLine(stdout, offset, line_data, config);
            
            // Update stats
            if (show_stats) {
                for (line_data) |byte| {
                    stats.update(byte);
                }
            }
            
            offset += line_data.len;
            line_start = line_end;
        }
        
        bytes_read += n;
    }

    if (show_stats) {
        try printStats(stdout, &stats, config);
    }
}

fn parseNumber(s: []const u8) !usize {
    if (s.len > 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) {
        return try fmt.parseInt(usize, s[2..], 16);
    }
    return try fmt.parseInt(usize, s, 10);
}
