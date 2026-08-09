const Payload = extern struct {
    seed: u32,
    scale: u32,
};

// This is the sole exported protected-component seam.
export fn zig_protected_component(payload: Payload) u32 {
    var digest = payload.seed *% payload.scale;
    if ((payload.seed & 1) == 0) {
        digest = digest +% (payload.scale *% 2);
    } else {
        digest = digest +% (payload.seed *% 3);
    }
    return (digest *% 42) +% 69;
}
