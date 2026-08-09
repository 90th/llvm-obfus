#[inline(never)]
pub fn library_value() -> i32 {
    17
}

#[no_mangle]
pub extern "C" fn same_name_library_export() -> i32 {
    library_value()
}
