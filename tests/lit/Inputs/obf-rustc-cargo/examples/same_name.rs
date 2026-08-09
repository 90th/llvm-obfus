#[no_mangle]
#[inline(never)]
pub extern "C" fn cargo_example_unselected(value: i32) -> i32 {
    value + same_name::library_value()
}

fn main() {
    println!("example={}", cargo_example_unselected(3));
}
