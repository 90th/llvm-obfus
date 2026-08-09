const std = @import("std");

pub const Payload = extern struct {
    seed: u64,
    scale: u64,
};

export fn zig_protected_component(payload: Payload) u64 {
    const secret = "zig-bench-visible-secret";
    var state = payload.seed *% (payload.scale +% 7);
    var index: usize = 0;
    while (index < secret.len) : (index += 1) {
        const shift: u6 = @intCast((index & 7) * 8);
        const lane = (@as(u64, secret[index]) << shift) ^ (@as(u64, @intCast(index + 1)) *% 0x9e37);
        if (((state ^ lane) & 1) == 0) {
            state = std.math.rotl(u64, state +% lane, 9);
        } else {
            state = std.math.rotr(u64, state ^ lane, 5) +% (@as(u64, @intCast(index)) *% 13);
        }
    }
    return state ^ 0x510e527fade682d1;
}
