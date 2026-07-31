//! Minimal Darwin locale / rune surface for guests that link `_DefaultRuneLocale`.
//!
//! Driven by curl probe G1: `unresolved symbol __DefaultRuneLocale` before any
//! BSD syscall. ASCII-only; enough for ctype macros and `setlocale("C")` guests.

use core::ffi::c_int;

/// Cached rune table width (`_CACHED_RUNES` in Darwin `runetype.h`).
const CACHED_RUNES: usize = 256;

// Darwin ctype bits (subset used by is* macros).
const CTYPE_A: u32 = 0x0000_0100; // alpha
const CTYPE_C: u32 = 0x0000_0200; // control
const CTYPE_D: u32 = 0x0000_0400; // digit
const CTYPE_G: u32 = 0x0000_0800; // graph
const CTYPE_L: u32 = 0x0000_1000; // lower
const CTYPE_P: u32 = 0x0000_2000; // punct
const CTYPE_S: u32 = 0x0000_4000; // space
const CTYPE_U: u32 = 0x0000_8000; // upper
const CTYPE_X: u32 = 0x0001_0000; // xdigit
const CTYPE_B: u32 = 0x0002_0000; // blank
const CTYPE_R: u32 = 0x0004_0000; // print

/// Build ASCII `_CTYPE_*` flags for byte `b`.
const fn ascii_runetype(b: u8) -> u32 {
    let mut f = 0_u32;
    if b < 0x20 || b == 0x7f {
        f |= CTYPE_C;
    }
    if b == b' ' || (b >= 0x09 && b <= 0x0d) {
        f |= CTYPE_S;
    }
    if b == b' ' || b == b'\t' {
        f |= CTYPE_B;
    }
    if b >= b'0' && b <= b'9' {
        f |= CTYPE_D | CTYPE_X | CTYPE_G | CTYPE_R;
    }
    if (b >= b'a' && b <= b'f') || (b >= b'A' && b <= b'F') {
        f |= CTYPE_X;
    }
    if b >= b'a' && b <= b'z' {
        f |= CTYPE_L | CTYPE_A | CTYPE_G | CTYPE_R;
    }
    if b >= b'A' && b <= b'Z' {
        f |= CTYPE_U | CTYPE_A | CTYPE_G | CTYPE_R;
    }
    if b >= 0x21 && b <= 0x7e {
        f |= CTYPE_R;
        let alnum =
            (b >= b'0' && b <= b'9') || (b >= b'a' && b <= b'z') || (b >= b'A' && b <= b'Z');
        if !alnum {
            f |= CTYPE_P | CTYPE_G;
        }
    }
    f
}

// Const table fill: fixed 0..255 loop; clippy const limits make get_mut / try_from
// awkward, so allow the closed-range casts once for the three builders.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
const fn build_runetype() -> [u32; CACHED_RUNES] {
    let mut t = [0_u32; CACHED_RUNES];
    let mut i = 0_usize;
    while i < CACHED_RUNES {
        t[i] = ascii_runetype(i as u8);
        i += 1;
    }
    t
}

#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
const fn build_maplower() -> [i32; CACHED_RUNES] {
    let mut t = [0_i32; CACHED_RUNES];
    let mut i = 0_usize;
    while i < CACHED_RUNES {
        let b = i as u8;
        t[i] = if b >= b'A' && b <= b'Z' {
            b.wrapping_add(32) as i32
        } else {
            i as i32
        };
        i += 1;
    }
    t
}

#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
const fn build_mapupper() -> [i32; CACHED_RUNES] {
    let mut t = [0_i32; CACHED_RUNES];
    let mut i = 0_usize;
    while i < CACHED_RUNES {
        let b = i as u8;
        t[i] = if b >= b'a' && b <= b'z' {
            b.wrapping_sub(32) as i32
        } else {
            i as i32
        };
        i += 1;
    }
    t
}

/// Darwin `_RuneRange` (arm64: 4 + 4 pad + 8).
#[repr(C)]
struct RuneRange {
    nranges: i32,
    _pad: i32,
    ranges: *mut core::ffi::c_void,
}

// SAFETY: null ranges pointer; never written at runtime for "C" locale.
unsafe impl Sync for RuneRange {}

/// Darwin `_RuneLocale` layout used by ctype macros (LP64 arm64).
///
/// Size must match guest expectations when code indexes `__runetype[c]`.
#[repr(C)]
struct RuneLocale {
    magic: [u8; 8],
    encoding: [u8; 32],
    sgetrune: *mut core::ffi::c_void,
    sputrune: *mut core::ffi::c_void,
    invalid_rune: i32,
    _pad0: i32,
    runetype: [u32; CACHED_RUNES],
    maplower: [i32; CACHED_RUNES],
    mapupper: [i32; CACHED_RUNES],
    runetype_ext: RuneRange,
    maplower_ext: RuneRange,
    mapupper_ext: RuneRange,
    variable: *mut core::ffi::c_void,
    variable_len: i32,
    _pad1: i32,
}

// SAFETY: only const data + null fn ptrs; guests read the tables.
unsafe impl Sync for RuneLocale {}

const RUNE_MAGIC: [u8; 8] = *b"RuneMagi";

const fn encoding_c() -> [u8; 32] {
    let mut e = [0_u8; 32];
    e[0] = b'N';
    e[1] = b'O';
    e[2] = b'N';
    e[3] = b'E';
    e
}

/// C `_DefaultRuneLocale` → nlist `__DefaultRuneLocale`.
#[unsafe(export_name = "_DefaultRuneLocale")]
#[used]
static DEFAULT_RUNE_LOCALE: RuneLocale = RuneLocale {
    magic: RUNE_MAGIC,
    encoding: encoding_c(),
    sgetrune: core::ptr::null_mut(),
    sputrune: core::ptr::null_mut(),
    invalid_rune: -1,
    _pad0: 0,
    runetype: build_runetype(),
    maplower: build_maplower(),
    mapupper: build_mapupper(),
    runetype_ext: RuneRange {
        nranges: 0,
        _pad: 0,
        ranges: core::ptr::null_mut(),
    },
    maplower_ext: RuneRange {
        nranges: 0,
        _pad: 0,
        ranges: core::ptr::null_mut(),
    },
    mapupper_ext: RuneRange {
        nranges: 0,
        _pad: 0,
        ranges: core::ptr::null_mut(),
    },
    variable: core::ptr::null_mut(),
    variable_len: 0,
    _pad1: 0,
};

/// Darwin `___maskrune` → nlist `___maskrune` (ctype backend).
#[unsafe(export_name = "__maskrune")]
pub(crate) unsafe extern "C" fn __maskrune(c: c_int, f: usize) -> c_int {
    if c < 0 {
        return 0;
    }
    let idx = usize::try_from(c.cast_unsigned()).unwrap_or(usize::MAX);
    let Some(bits_u32) = DEFAULT_RUNE_LOCALE.runetype.get(idx).copied() else {
        return 0;
    };
    let bits = usize::try_from(bits_u32).unwrap_or(0);
    c_int::from((bits & f) != 0)
}

/// Darwin `___mb_cur_max_l` → nlist `____mb_cur_max_l` (always 1 for "C").
#[unsafe(export_name = "___mb_cur_max_l")]
pub(crate) unsafe extern "C" fn ___mb_cur_max_l(_locale: *mut core::ffi::c_void) -> c_int {
    1
}
