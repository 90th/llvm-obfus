#[no_mangle]
#[inline(never)]
pub extern "C" fn cargo_selected_target(value: i32) -> i32 {
    let secret = b"cargo-selected-visible-secret\0";
    let index = (value as usize) % (secret.len() - 1);
    value
        .wrapping_add(same_name::library_value())
        .wrapping_add(secret[index] as i32)
}

fn main() {
    println!("cargo={}", cargo_selected_target(25));
}
