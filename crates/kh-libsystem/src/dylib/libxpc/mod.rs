//! XPC soft stubs.

#![allow(
    static_mut_refs,
    non_snake_case,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::manual_c_str_literals,
    clippy::many_single_char_names,
    clippy::missing_safety_doc,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::too_many_arguments,
    clippy::used_underscore_binding
)]

use core::ffi::{c_char, c_void};

macro_rules! soft_null {
    ($name:ident $(, $arg:ident : $ty:ty)*) => {
        #[unsafe(no_mangle)]
        pub(crate) unsafe extern "C" fn $name($($arg : $ty),*) -> *mut c_void {
            $(let _ = $arg;)*
            core::ptr::null_mut()
        }
    };
}

soft_null!(xpc_dictionary_create, _k: *const *const c_char, _v: *const *mut c_void, _c: usize);

/// `xpc_dictionary_set_bool` — soft no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xpc_dictionary_set_bool(
    _xdict: *mut c_void,
    _key: *const c_char,
    _value: u8,
) {
}

/// `xpc_dictionary_set_int64` — soft no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xpc_dictionary_set_int64(
    _xdict: *mut c_void,
    _key: *const c_char,
    _value: i64,
) {
}

/// `xpc_dictionary_set_string` — soft no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xpc_dictionary_set_string(
    _xdict: *mut c_void,
    _key: *const c_char,
    _value: *const c_char,
) {
}

