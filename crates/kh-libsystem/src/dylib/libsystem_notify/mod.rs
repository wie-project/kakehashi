//! notify soft stubs.

#![allow(unused_imports, dead_code)]

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::bool_to_int_with_if,
    clippy::manual_c_str_literals,
    clippy::manual_is_ascii_check,
    clippy::many_single_char_names,
    clippy::used_underscore_binding
)]

use core::ffi::{c_char, c_int, c_void};

const ENOSYS: i32 = 78;

/// Darwin `notify_cancel` → 0.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn notify_cancel(_token: c_int) -> u32 {
    0
}

/// Darwin `notify_register_file_descriptor` → soft success token 1.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn notify_register_file_descriptor(
    _name: *const c_char,
    _notify_fd: *mut c_int,
    _flags: c_int,
    _out_token: *mut c_int,
) -> u32 {
    if !_out_token.is_null() {
        unsafe {
            _out_token.write(1);
        }
    }
    0
}

