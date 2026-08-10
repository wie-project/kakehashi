//! CoreServices FSEvents soft surface.

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

use crate::kh_core::heap::malloc;

//
// `git` LC_LOAD_DYLIB CoreServices and two-level-binds these. Bottle has no
// CoreServices.framework; soft no-ops here so flat resolve binds to libSystem
// instead of failing load (`unresolved symbol _FSEventStreamCreate`) or
// aborting via missing trampoline when watch paths run after commit.

/// `FSEventStreamCreate` → null stream (watcher unavailable).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamCreate(
    _allocator: *mut c_void,
    _callback: *mut c_void,
    _context: *mut c_void,
    _paths: *mut c_void,
    _since: u64,
    _latency: f64,
    _flags: u32,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `FSEventStreamStart` → false (Boolean).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamStart(_stream: *mut c_void) -> u8 {
    0
}

/// `FSEventStreamStop`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamStop(_stream: *mut c_void) {}

/// `FSEventStreamInvalidate`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamInvalidate(_stream: *mut c_void) {}

/// `FSEventStreamRelease`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamRelease(_stream: *mut c_void) {}

/// `FSEventStreamSetDispatchQueue`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn FSEventStreamSetDispatchQueue(
    _stream: *mut c_void,
    _queue: *mut c_void,
) {
}

