const std = @import("std");

const Payload = extern struct {
    seed: u64,
    scale: u64,
};

extern fn zig_protected_component(payload: Payload) u64;

fn benchIters(init: std.process.Init) u64 {
    const text = init.environ_map.get("OBF_BENCH_ITERS") orelse return 0;
    return std.fmt.parseInt(u64, text, 10) catch 0;
}

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000000000 + @as(u64, @intCast(ts.nsec));
}

fn foldValue(value: u64) u64 {
    return std.math.rotl(u64, value ^ 0xa5a55a5ac3c39696, 11);
}

fn runOnce(seed: u64, scale: u64) u64 {
    return foldValue(zig_protected_component(.{ .seed = seed, .scale = scale }));
}

pub fn main(init: std.process.Init) !void {
    const iters = benchIters(init);
    if (iters > 0) {
        var sink: u64 = 0;
        var warmup: u64 = 0;
        while (warmup < 2048) : (warmup += 1) {
            sink ^= runOnce(17 +% warmup, 7 +% (warmup & 3));
        }

        const start_ns = nowNs();
        var iter: u64 = 0;
        while (iter < iters) : (iter += 1) {
            sink ^= runOnce(17 +% iter, 7 +% (iter & 3));
        }
        const total_ns = nowNs() - start_ns;
        const ns_per_iter = total_ns / iters;
        var bench_buf: [128]u8 = undefined;
        const bench_line = try std.fmt.bufPrint(&bench_buf, "BENCH zig_demo ns/op={} sink={}\n", .{ ns_per_iter, sink });
        try std.Io.File.stdout().writeStreamingAll(init.io, bench_line);
        return;
    }

    const value = runOnce(17, 7);
    var output_buf: [64]u8 = undefined;
    const output_line = try std.fmt.bufPrint(&output_buf, "zig={}\n", .{value});
    try std.Io.File.stdout().writeStreamingAll(init.io, output_line);
}
