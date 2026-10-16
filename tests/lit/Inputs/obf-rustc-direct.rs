#[no_mangle]
#[inline(never)]
pub extern "C" fn rust_direct_target(value: i32) -> i32 {
    let secret = b"rust-direct-visible-secret\0";
    let index = (value as usize) % (secret.len() - 1);
    let mixed = value.wrapping_mul(17).wrapping_add(secret[index] as i32);
    mixed ^ 0x5a5a
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn rust_direct_vm_target(value: u64) -> u64 {
    value.wrapping_mul(17).wrapping_add(29).rotate_left(7)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn rust_direct_vm_override(value: u64) -> u64 {
    value.wrapping_add(7).rotate_right(4)
}

fn main() {
    println!("direct={}", rust_direct_target(41));
    let cases = [
        (0, 0x0000_0000_0000_0e80, 0x7000_0000_0000_0000),
        (1, 0x0000_0000_0000_1700, 0x8000_0000_0000_0000),
        (u64::MAX, 0x0000_0000_0000_0600, 0x6000_0000_0000_0000),
        (1 << 63, 0x0000_0000_0000_0ec0, 0x7800_0000_0000_0000),
    ];
    for (value, expected_target, expected_override) in cases {
        let value = std::hint::black_box(value);
        assert_eq!(rust_direct_vm_target(value), expected_target);
        assert_eq!(rust_direct_vm_override(value), expected_override);
    }
    println!(
        "direct-vm={:016x}:{:016x}",
        rust_direct_vm_target(std::hint::black_box(1 << 63)),
        rust_direct_vm_override(std::hint::black_box(1 << 63))
    );
}
