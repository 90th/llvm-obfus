const std = @import("std");

const Payload = extern struct {
    seed: u32,
    scale: u32,
};

extern fn zig_protected_component(payload: Payload) u32;

pub fn main(init: std.process.Init) !void {
    const payload = Payload{ .seed = 17, .scale = 7 };
    if (zig_protected_component(payload) != 7209) return error.UnexpectedDigest;
    try std.Io.File.stdout().writeStreamingAll(init.io, "digest=7209\n");
}
