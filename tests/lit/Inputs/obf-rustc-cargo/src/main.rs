#[no_mangle]
#[inline(never)]
pub extern "C" fn cargo_selected_target(value: i32) -> i32 {
    let secret = b"cargo-selected-visible-secret\0";
    let index = (value as usize) % (secret.len() - 1);
    value
        .wrapping_add(same_name::library_value())
        .wrapping_add(secret[index] as i32)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn cargo_vm_target(value: u64) -> u64 {
    value.wrapping_mul(9).wrapping_add(5).rotate_left(3)
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn cargo_vm_override(value: u64) -> u64 {
    value.wrapping_sub(3).rotate_right(2)
}

fn main() {
    println!("cargo={}", cargo_selected_target(25));
    let cases = [
        (0, 0x0000_0000_0000_0028, 0x7fff_ffff_ffff_ffff),
        (1, 0x0000_0000_0000_0070, 0xbfff_ffff_ffff_ffff),
        (u64::MAX, 0xffff_ffff_ffff_ffe7, 0x3fff_ffff_ffff_ffff),
        (1 << 63, 0x0000_0000_0000_002c, 0x5fff_ffff_ffff_ffff),
    ];
    for (value, expected_target, expected_override) in cases {
        let value = std::hint::black_box(value);
        assert_eq!(cargo_vm_target(value), expected_target);
        assert_eq!(cargo_vm_override(value), expected_override);
    }
    println!(
        "cargo-vm={:016x}:{:016x}",
        cargo_vm_target(std::hint::black_box(1 << 63)),
        cargo_vm_override(std::hint::black_box(1 << 63))
    );
}
