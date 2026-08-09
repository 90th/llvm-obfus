#[no_mangle]
#[inline(never)]
pub extern "C" fn rust_direct_target(value: i32) -> i32 {
    let secret = b"rust-direct-visible-secret\0";
    let index = (value as usize) % (secret.len() - 1);
    let mixed = value.wrapping_mul(17).wrapping_add(secret[index] as i32);
    mixed ^ 0x5a5a
}

fn main() {
    println!("direct={}", rust_direct_target(41));
}
