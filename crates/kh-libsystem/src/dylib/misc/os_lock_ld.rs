//! Extra os_unfair_lock soft symbols from ld surface (if not in libobjc).

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

use core::ffi::c_void;

/// `__os_lock_type_unfair` data (opaque lock type table).
#[unsafe(no_mangle)]
#[used]
pub(crate) static mut _os_lock_type_unfair: [usize; 4] = [0; 4];

/// `os_lock_lock` — soft no-op (single-threaded linker path).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_lock_lock(_lock: *mut c_void) {}

/// `os_lock_unlock` — soft no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_lock_unlock(_lock: *mut c_void) {}
