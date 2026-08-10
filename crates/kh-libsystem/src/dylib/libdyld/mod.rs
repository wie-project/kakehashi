//! dyld image query soft surface.

#![allow(unused_imports)]

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

//
// Apple nlists use a leading underscore already in the C spelling (`_dyld_*`).
// Export with that exact Mach-O name (rustc adds one more `_` for normal
// no_mangle, so use export_name).

/// Soft: report 0 images (no dyld shared-cache walk under kh).
#[unsafe(export_name = "_dyld_image_count")]
pub(crate) unsafe extern "C" fn dyld_image_count() -> u32 {
    0
}

#[unsafe(export_name = "dyld_image_count")]
pub(crate) unsafe extern "C" fn dyld_image_count_plain() -> u32 {
    0
}

/// Soft: null name.
#[unsafe(export_name = "_dyld_get_image_name")]
pub(crate) unsafe extern "C" fn dyld_get_image_name(_image_index: u32) -> *const c_char {
    core::ptr::null()
}

#[unsafe(export_name = "dyld_get_image_name")]
pub(crate) unsafe extern "C" fn dyld_get_image_name_plain(_image_index: u32) -> *const c_char {
    core::ptr::null()
}

/// Soft: null header.
#[unsafe(export_name = "_dyld_get_image_header")]
pub(crate) unsafe extern "C" fn dyld_get_image_header(_image_index: u32) -> *const c_void {
    core::ptr::null()
}

