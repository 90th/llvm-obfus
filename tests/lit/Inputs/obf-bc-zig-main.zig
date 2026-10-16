const std = @import("std");

const Payload = extern struct {
    seed: u32,
    scale: u32,
};

extern fn zig_protected_component(payload: Payload) u32;
extern fn zig_vm_target(value: u64) u64;
extern fn zig_vm_override(value: u64) u64;

pub fn main(init: std.process.Init) !void {
    const payload = Payload{ .seed = 17, .scale = 7 };
    if (zig_protected_component(payload) != 7209) return error.UnexpectedDigest;
    const Case = struct { value: u64, target: u64, override: u64 };
    const cases = [_]Case{
        .{ .value = 0, .target = 0x0000000000000e80, .override = 0x7000000000000000 },
        .{ .value = 1, .target = 0x0000000000001700, .override = 0x8000000000000000 },
        .{ .value = 0xffffffffffffffff, .target = 0x0000000000000600, .override = 0x6000000000000000 },
        .{ .value = 0x8000000000000000, .target = 0x0000000000000ec0, .override = 0x7800000000000000 },
    };
    for (cases) |case| {
        if (zig_vm_target(case.value) != case.target) return error.UnexpectedVMTarget;
        if (zig_vm_override(case.value) != case.override) return error.UnexpectedVMOverride;
    }
    try std.Io.File.stdout().writeStreamingAll(init.io, "digest=7209\n");
}
