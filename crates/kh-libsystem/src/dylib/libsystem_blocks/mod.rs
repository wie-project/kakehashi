//! Blocks runtime soft surface.

#![allow(
    dead_code,
    
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

use core::ffi::{c_int, c_void};

// ── Blocks runtime (soft) ───────────────────────────────────────────────────

/// Data isa for global blocks (`_NSConcreteGlobalBlock`).
#[unsafe(no_mangle)]
#[used]
pub(crate) static mut _NSConcreteGlobalBlock: [usize; 4] = [0; 4];

/// Data isa for stack blocks (`_NSConcreteStackBlock`).
#[unsafe(no_mangle)]
#[used]
pub(crate) static mut _NSConcreteStackBlock: [usize; 4] = [0; 4];

/// `_Block_copy` — soft: return the same pointer (no heap promote).
#[unsafe(export_name = "_Block_copy")]
pub(crate) unsafe extern "C" fn block_copy(a_block: *const c_void) -> *mut c_void {
    a_block.cast_mut()
}

/// `_Block_release` — soft no-op.
#[unsafe(export_name = "_Block_release")]
pub(crate) unsafe extern "C" fn block_release(_a_block: *const c_void) {}

/// `_Block_object_assign` — soft no-op.
#[unsafe(export_name = "_Block_object_assign")]
pub(crate) unsafe extern "C" fn block_object_assign(
    _dest: *mut c_void,
    _object: *const c_void,
    _flags: c_int,
) {
}

/// `_Block_object_dispose` — soft no-op.
#[unsafe(export_name = "_Block_object_dispose")]
pub(crate) unsafe extern "C" fn block_object_dispose(_object: *const c_void, _flags: c_int) {}

