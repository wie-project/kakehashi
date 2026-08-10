//! Soft libm used by ld / tapi.

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

use core::ffi::{c_int, c_void};

/// C `log2` → soft via frexp-ish bit hack (positive only).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn log2(x: f64) -> f64 {
    if x <= 0.0 {
        return f64::NEG_INFINITY;
    }
    // ilogb-style: exponent of IEEE754 double.
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i32;
    if exp == 0 {
        return f64::NEG_INFINITY;
    }
    if exp == 0x7ff {
        return x; // inf/nan
    }
    f64::from(exp - 1023)
}

/// C `log10` → soft `log2(x) * log10(2)`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn log10(x: f64) -> f64 {
    unsafe { log2(x) * core::f64::consts::LOG10_2 }
}

/// C `modf` → nlist `_modf` (split integer / fractional parts).
///
/// Observed: Apple `libtapi` (G4).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn modf(x: f64, iptr: *mut f64) -> f64 {
    if x.is_nan() {
        if !iptr.is_null() {
            unsafe {
                iptr.write(x);
            }
        }
        return x;
    }
    if x.is_infinite() {
        if !iptr.is_null() {
            unsafe {
                iptr.write(x);
            }
        }
        return if x.is_sign_positive() { 0.0 } else { -0.0 };
    }
    // Truncate toward zero using bit ops when finite.
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i32 - 1023;
    let integ = if exp < 0 {
        0.0_f64.copysign(x)
    } else if exp >= 52 {
        x
    } else {
        let mask = !((1_u64 << (52 - exp as u32)) - 1);
        f64::from_bits(bits & mask)
    };
    if !iptr.is_null() {
        unsafe {
            iptr.write(integ);
        }
    }
    x - integ
}

/// C `posix_madvise` → nlist `_posix_madvise` (soft success).
///
/// Observed: Apple `libtapi` (G4).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_madvise(
    _addr: *mut c_void,
    _len: usize,
    _advice: c_int,
) -> c_int {
    0
}
