const Payload = extern struct {
    seed: u32,
    scale: u32,
};

export fn zig_protected_component(payload: Payload) u32 {
    var digest = payload.seed *% payload.scale;
    if ((payload.seed & 1) == 0) {
        digest = digest +% (payload.scale *% 2);
    } else {
        digest = digest +% (payload.seed *% 3);
    }
    return (digest *% 42) +% 69;
}

export fn zig_vm_target(value: u64) u64 {
    const mixed = (value *% 17) +% 29;
    return (mixed << 7) | (mixed >> 57);
}

export fn zig_vm_override(value: u64) u64 {
    const mixed = value +% 7;
    return (mixed >> 4) | (mixed << 60);
}
