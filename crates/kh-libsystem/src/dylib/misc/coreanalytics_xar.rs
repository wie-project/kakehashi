//! CoreAnalytics + libxar soft stubs (ld / bitcode paths).

#![allow(unused_imports)]

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

use core::ffi::{c_char, c_int, c_void};

use crate::kh_core::heap::malloc;

// ── CoreAnalytics soft ──────────────────────────────────────────────────────

/// `_analytics_send_event_lazy` → soft success.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn analytics_send_event_lazy(
    _name: *const c_char,
    _block: *mut c_void,
) -> c_int {
    0
}

// ── libxar soft (bitcode / static archive paths; plain .o link may skip) ────

macro_rules! soft_null {
    ($name:ident $(, $arg:ident : $ty:ty)*) => {
        #[unsafe(no_mangle)]
        pub(crate) unsafe extern "C" fn $name($($arg : $ty),*) -> *mut c_void {
            $(let _ = $arg;)*
            core::ptr::null_mut()
        }
    };
}

macro_rules! soft_int {
    ($name:ident $(, $arg:ident : $ty:ty)* => $ret:expr) => {
        #[unsafe(no_mangle)]
        pub(crate) unsafe extern "C" fn $name($($arg : $ty),*) -> c_int {
            $(let _ = $arg;)*
            $ret
        }
    };
}

soft_null!(xar_open, _path: *const c_char, _flags: c_int);
soft_int!(xar_close, _x: *mut c_void => 0);
soft_null!(xar_iter_new);
soft_int!(xar_iter_free, _i: *mut c_void => 0);
soft_null!(xar_file_first, _x: *mut c_void, _i: *mut c_void);
soft_null!(xar_file_next, _x: *mut c_void, _i: *mut c_void);
soft_null!(xar_prop_first, _f: *mut c_void, _i: *mut c_void);
soft_null!(xar_prop_next, _f: *mut c_void, _i: *mut c_void);
soft_int!(xar_prop_get, _f: *mut c_void, _k: *const c_char, _v: *mut *const c_char => -1);
soft_int!(xar_prop_set, _f: *mut c_void, _k: *const c_char, _v: *const c_char => -1);
soft_int!(xar_prop_unset, _f: *mut c_void, _k: *const c_char => -1);
soft_null!(xar_prop_create, _f: *mut c_void, _k: *const c_char);
soft_int!(xar_opt_set, _x: *mut c_void, _opt: *const c_char, _val: *const c_char => 0);
soft_int!(
    xar_add_frombuffer,
    _x: *mut c_void,
    _parent: *mut c_void,
    _name: *const c_char,
    _buf: *mut c_void,
    _len: usize
    => -1
);
soft_int!(
    xar_extract_tobuffersz,
    _x: *mut c_void,
    _f: *mut c_void,
    _buf: *mut *mut c_void,
    _size: *mut usize
    => -1
);
soft_null!(xar_subdoc_first, _x: *mut c_void);
soft_null!(xar_subdoc_next, _s: *mut c_void);
soft_null!(xar_subdoc_new, _x: *mut c_void, _name: *const c_char);

/// `xar_subdoc_name` → null.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xar_subdoc_name(_s: *mut c_void) -> *const c_char {
    core::ptr::null()
}

