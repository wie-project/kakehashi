//! `std::random_device` soft (Apple arm64 sizeof = 4).

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

use core::ffi::c_void;

//
// libLTO imports ctor(string), dtor, operator(). Host sizeof is 4 — soft as a
// single u32 LCG state (no /dev/urandom). Enough for unique temp path digits.

/// Soft LCG state when the 4-byte object is treated as seed storage.
#[inline]
unsafe fn rd_state(this: *mut c_void) -> *mut u32 {
    this.cast::<u32>()
}

/// `random_device::random_device(string const&)` C1.
///
/// nlist `_ZNSt3__113random_deviceC1ERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE`
#[unsafe(export_name = "_ZNSt3__113random_deviceC1ERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE")]
pub(crate) unsafe extern "C" fn random_device_ctor_string(
    this: *mut c_void,
    _token: *const c_void,
) {
    if this.is_null() {
        return;
    }
    // Seed from a mix of address + fixed constant (deterministic-ish, non-zero).
    let seed = (this.addr() as u32)
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add(0xA5A5_5A5A)
        .max(1);
    unsafe {
        rd_state(this).write(seed);
    }
}

/// `random_device::~random_device()` D1.
#[unsafe(export_name = "_ZNSt3__113random_deviceD1Ev")]
pub(crate) unsafe extern "C" fn random_device_dtor(this: *mut c_void) {
    if this.is_null() {
        return;
    }
    unsafe {
        rd_state(this).write(0);
    }
}

/// `random_device::operator()()` → `unsigned int`.
#[unsafe(export_name = "_ZNSt3__113random_deviceclEv")]
pub(crate) unsafe extern "C" fn random_device_call(this: *mut c_void) -> u32 {
    if this.is_null() {
        return 0xC0FF_EE00;
    }
    // xorshift32-ish LCG (Numerical Recipes constants).
    let p = unsafe { rd_state(this) };
    let mut x = unsafe { p.read() };
    if x == 0 {
        x = 0xDEAD_BEEF;
    }
    x = x
        .wrapping_mul(1_664_525)
        .wrapping_add(1_013_904_223);
    unsafe {
        p.write(x);
    }
    x
}
