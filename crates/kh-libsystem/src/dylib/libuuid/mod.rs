//! uuid soft surface.

#![allow(unused_imports, dead_code)]

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
use crate::dylib::libsystem_c::stdio::{memcpy, strlen};

const EINVAL: i32 = 22;

/// `uuid_generate_random` — deterministic non-zero soft UUID.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn uuid_generate_random(out: *mut u8) {
    if out.is_null() {
        return;
    }
    // SAFETY: 16-byte UUID buffer.
    unsafe {
        let mut i = 0_usize;
        while i < 16 {
            out.add(i).write(u8::try_from(0xA0 + i).unwrap_or(0xA0));
            i = i.saturating_add(1);
        }
        // RFC 4122 variant / version bits (version 4-ish).
        out.add(6).write((out.add(6).read() & 0x0f) | 0x40);
        out.add(8).write((out.add(8).read() & 0x3f) | 0x80);
    }
}

fn uuid_nibble(b: u8) -> u8 {
    if b < 10 {
        b'0'.wrapping_add(b)
    } else {
        b'a'.wrapping_add(b.wrapping_sub(10))
    }
}

fn uuid_nibble_upper(b: u8) -> u8 {
    if b < 10 {
        b'0'.wrapping_add(b)
    } else {
        b'A'.wrapping_add(b.wrapping_sub(10))
    }
}

unsafe fn uuid_unparse_impl(uu: *const u8, out: *mut u8, upper: bool) {
    if uu.is_null() || out.is_null() {
        return;
    }
    // 8-4-4-4-12 + NUL
    let groups: [usize; 5] = [4, 2, 2, 2, 6];
    let mut src = 0_usize;
    let mut dst = 0_usize;
    let mut g = 0_usize;
    while g < groups.len() {
        if g > 0 {
            unsafe {
                out.add(dst).write(b'-');
            }
            dst = dst.saturating_add(1);
        }
        let mut n = 0_usize;
        while n < groups[g] {
            let b = unsafe { uu.add(src).read() };
            src = src.saturating_add(1);
            let hi = b >> 4;
            let lo = b & 0x0f;
            let (ch_hi, ch_lo) = if upper {
                (uuid_nibble_upper(hi), uuid_nibble_upper(lo))
            } else {
                (uuid_nibble(hi), uuid_nibble(lo))
            };
            unsafe {
                out.add(dst).write(ch_hi);
                out.add(dst + 1).write(ch_lo);
            }
            dst = dst.saturating_add(2);
            n = n.saturating_add(1);
        }
        g = g.saturating_add(1);
    }
    unsafe {
        out.add(dst).write(0);
    }
}

/// `uuid_unparse`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn uuid_unparse(uu: *const u8, out: *mut c_char) {
    unsafe {
        uuid_unparse_impl(uu, out.cast(), false);
    }
}

/// `uuid_unparse_upper`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn uuid_unparse_upper(uu: *const u8, out: *mut c_char) {
    unsafe {
        uuid_unparse_impl(uu, out.cast(), true);
    }
}

