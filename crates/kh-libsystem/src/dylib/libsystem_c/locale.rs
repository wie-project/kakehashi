//! Minimal Darwin locale / rune surface for guests that link `_DefaultRuneLocale`.
//!
//! Driven by curl probe G1: `unresolved symbol __DefaultRuneLocale` before any
//! BSD syscall. ASCII-only; enough for ctype macros and `setlocale("C")` guests.

use core::ffi::{c_char, c_int, c_void};

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
/// Field offsets must match CLT `runetype.h` / `_DefaultRuneLocale`:
/// `__runetype` is at **0x3c** (after `invalid_rune` **without** pad). Observed:
/// modern `ld` `-flto` scans version digits via
/// `*(uint32_t*)(locale + 0x3c + c*4)` and bit 10 (`_CTYPE_D`). Our old
/// `_pad0` after `invalid_rune` shifted the table to 0x40 → bit tests read
/// the wrong words → version string became `N.0.\x18\x03`.
///
/// Host `sizeof(_RuneLocale) == 3208` on arm64.
#[repr(C)]
struct RuneLocale {
    magic: [u8; 8],
    encoding: [u8; 32],
    sgetrune: *mut core::ffi::c_void,
    sputrune: *mut core::ffi::c_void,
    /// Offset 56; next field `__runetype` at 60 (0x3c) — **no** padding.
    invalid_rune: i32,
    runetype: [u32; CACHED_RUNES],
    maplower: [i32; CACHED_RUNES],
    mapupper: [i32; CACHED_RUNES],
    /// Pad to 8-byte align for `_RuneRange` (host: mapupper ends 3132, ext @ 3136).
    _pad_before_ext: i32,
    runetype_ext: RuneRange,
    maplower_ext: RuneRange,
    mapupper_ext: RuneRange,
    variable: *mut core::ffi::c_void,
    variable_len: i32,
    /// Trailing pad to host `sizeof(_RuneLocale) == 3208`.
    _pad_end: [u8; 12],
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
    runetype: build_runetype(),
    maplower: build_maplower(),
    mapupper: build_mapupper(),
    _pad_before_ext: 0,
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
    _pad_end: [0; 12],
};

// Compile-time layout gate (CLT arm64 host: sizeof 3208, __runetype @ 0x3c).
const _: () = assert!(core::mem::size_of::<RuneLocale>() == 3208);
const _: () = assert!(core::mem::offset_of!(RuneLocale, invalid_rune) == 56);
const _: () = assert!(core::mem::offset_of!(RuneLocale, runetype) == 0x3c);
const _: () = assert!(core::mem::offset_of!(RuneLocale, maplower) == 1084);
const _: () = assert!(core::mem::offset_of!(RuneLocale, runetype_ext) == 3136);

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

/// Darwin `__mb_cur_max` → nlist `___mb_cur_max` (**data**).
///
/// Apple bash 3.2 does `MB_CUR_MAX` as `ldr` from this int, then `alloca`.
/// Exporting a function here made it load the first insn as the size and
/// drop SP into unmapped memory (`$*` / `main "$@"` → SIGSEGV).
#[unsafe(no_mangle)]
#[used]
#[allow(non_upper_case_globals)]
pub(crate) static mut __mb_cur_max: c_int = 1;

/// Darwin `___mb_cur_max_l` → nlist `____mb_cur_max_l` (always 1 for "C").
#[unsafe(export_name = "___mb_cur_max_l")]
pub(crate) unsafe extern "C" fn ___mb_cur_max_l(_locale: *mut core::ffi::c_void) -> c_int {
    1
}

/// Darwin `___mb_cur_max` → nlist `____mb_cur_max` (callers that use a fn).
#[unsafe(export_name = "___mb_cur_max")]
pub(crate) unsafe extern "C" fn ___mb_cur_max() -> c_int {
    1
}

/// C `mblen` → nlist `_mblen` ("C" locale: one byte per character).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mblen(s: *const c_char, n: usize) -> c_int {
    if s.is_null() {
        return 0;
    }
    if n == 0 {
        return -1;
    }
    // SAFETY: caller provided at least one readable byte when n > 0.
    i32::from(unsafe { s.read() } != 0)
}

/// Darwin `wchar_t` for locale conversion (32-bit).
type Wchar = i32;

/// C `mbrtowc` → nlist `_mbrtowc` ("C" locale).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mbrtowc(
    pwc: *mut Wchar,
    s: *const c_char,
    n: usize,
    _ps: *mut c_void,
) -> usize {
    if s.is_null() {
        return 0;
    }
    if n == 0 {
        return usize::MAX;
    }
    let b = unsafe { s.read() };
    if !pwc.is_null() {
        unsafe {
            pwc.write(i32::from(b.cast_unsigned()));
        }
    }
    usize::from(b != 0)
}

/// C `mbrlen` → nlist `_mbrlen`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mbrlen(s: *const c_char, n: usize, ps: *mut c_void) -> usize {
    unsafe { mbrtowc(core::ptr::null_mut(), s, n, ps) }
}

/// C `mbsinit` → nlist `_mbsinit` (initial `mbstate_t` or null).
///
/// Darwin `__mbstate_t` is a 128-byte union; the live conversion state lives in
/// the first 8 bytes. Bash word-splits `"$@"` through this (empty `"$@"` as a
/// function argument used to jump an unbound stub → host SIGSEGV).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mbsinit(ps: *const c_void) -> c_int {
    if ps.is_null() {
        return 1;
    }
    // SAFETY: caller passed a real `mbstate_t` (or null, handled above).
    let word = unsafe { ps.cast::<u64>().read() };
    i32::from(word == 0)
}

/// C `btowc` → nlist `_btowc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn btowc(c: c_int) -> Wchar {
    if c == -1 || !(0..=255).contains(&c) {
        return -1;
    }
    c
}

/// C `wctob` → nlist `_wctob`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wctob(c: Wchar) -> c_int {
    if (0..=127).contains(&c) {
        c
    } else {
        -1
    }
}

/// C `wcrtomb` → nlist `_wcrtomb` ("C" locale).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wcrtomb(s: *mut c_char, wc: Wchar, _ps: *mut c_void) -> usize {
    if s.is_null() {
        return 1;
    }
    let Some(b) = u8::try_from(wc).ok() else {
        return usize::MAX;
    };
    unsafe {
        s.write(b.cast_signed());
    }
    1
}

/// C `mbsrtowcs` → nlist `_mbsrtowcs`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mbsrtowcs(
    dst: *mut Wchar,
    src: *mut *const c_char,
    len: usize,
    _ps: *mut c_void,
) -> usize {
    if src.is_null() {
        return usize::MAX;
    }
    let s = unsafe { src.read() };
    if s.is_null() {
        return 0;
    }
    let n = unsafe { super::string::mbstowcs(dst, s, len) };
    if !dst.is_null() && n < len {
        unsafe {
            src.write(core::ptr::null());
        }
    }
    n
}

// Darwin `nl_item` values from public `<langinfo.h>` / `<_langinfo.h>`.
const CODESET: c_int = 0;
const D_T_FMT: c_int = 1;
const D_FMT: c_int = 2;
const T_FMT: c_int = 3;
const T_FMT_AMPM: c_int = 4;
const AM_STR: c_int = 5;
const PM_STR: c_int = 6;
const DAY_1: c_int = 7;
const ABDAY_1: c_int = 14;
const MON_1: c_int = 21;
const ABMON_1: c_int = 33;
const ERA: c_int = 45;
const ERA_D_FMT: c_int = 46;
const ERA_D_T_FMT: c_int = 47;
const ERA_T_FMT: c_int = 48;
const ALT_DIGITS: c_int = 49;
const RADIXCHAR: c_int = 50;
const THOUSEP: c_int = 51;
const YESEXPR: c_int = 52;
const NOEXPR: c_int = 53;
const YESSTR: c_int = 54;
const NOSTR: c_int = 55;
const CRNCYSTR: c_int = 56;
const D_MD_ORDER: c_int = 57;

const EMPTY: &[u8] = b"\0";
const CODESET_C: &[u8] = b"US-ASCII\0";
const DT_FMT: &[u8] = b"%a %b %e %H:%M:%S %Y\0";
const DATE_FMT: &[u8] = b"%m/%d/%y\0";
const TIME_FMT: &[u8] = b"%H:%M:%S\0";
const TIME_AMPM_FMT: &[u8] = b"%I:%M:%S %p\0";
const AM: &[u8] = b"AM\0";
const PM: &[u8] = b"PM\0";
const RADIX: &[u8] = b".\0";
const THOU: &[u8] = b"\0";
const YES_EXPR: &[u8] = b"^[yY]\0";
const NO_EXPR: &[u8] = b"^[nN]\0";
const YES_STR: &[u8] = b"yes\0";
const NO_STR: &[u8] = b"no\0";
const CURRENCY: &[u8] = b"\0";
const MD_ORDER: &[u8] = b"md\0";

const DAYS: [&[u8]; 7] = [
    b"Sunday\0",
    b"Monday\0",
    b"Tuesday\0",
    b"Wednesday\0",
    b"Thursday\0",
    b"Friday\0",
    b"Saturday\0",
];
const ABDAYS: [&[u8]; 7] = [
    b"Sun\0", b"Mon\0", b"Tue\0", b"Wed\0", b"Thu\0", b"Fri\0", b"Sat\0",
];
const MONTHS: [&[u8]; 12] = [
    b"January\0",
    b"February\0",
    b"March\0",
    b"April\0",
    b"May\0",
    b"June\0",
    b"July\0",
    b"August\0",
    b"September\0",
    b"October\0",
    b"November\0",
    b"December\0",
];
const ABMONTHS: [&[u8]; 12] = [
    b"Jan\0", b"Feb\0", b"Mar\0", b"Apr\0", b"May\0", b"Jun\0", b"Jul\0", b"Aug\0", b"Sep\0",
    b"Oct\0", b"Nov\0", b"Dec\0",
];

fn c_locale_nl(item: c_int) -> &'static [u8] {
    if item == CODESET {
        return CODESET_C;
    }
    if item == D_T_FMT {
        return DT_FMT;
    }
    if item == D_FMT {
        return DATE_FMT;
    }
    if item == T_FMT {
        return TIME_FMT;
    }
    if item == T_FMT_AMPM {
        return TIME_AMPM_FMT;
    }
    if item == AM_STR {
        return AM;
    }
    if item == PM_STR {
        return PM;
    }
    if (DAY_1..DAY_1 + 7).contains(&item) {
        let idx = usize::try_from(item.wrapping_sub(DAY_1)).unwrap_or(0);
        return DAYS.get(idx).copied().unwrap_or(EMPTY);
    }
    if (ABDAY_1..ABDAY_1 + 7).contains(&item) {
        let idx = usize::try_from(item.wrapping_sub(ABDAY_1)).unwrap_or(0);
        return ABDAYS.get(idx).copied().unwrap_or(EMPTY);
    }
    if (MON_1..MON_1 + 12).contains(&item) {
        let idx = usize::try_from(item.wrapping_sub(MON_1)).unwrap_or(0);
        return MONTHS.get(idx).copied().unwrap_or(EMPTY);
    }
    if (ABMON_1..ABMON_1 + 12).contains(&item) {
        let idx = usize::try_from(item.wrapping_sub(ABMON_1)).unwrap_or(0);
        return ABMONTHS.get(idx).copied().unwrap_or(EMPTY);
    }
    if item == ERA || item == ERA_D_FMT || item == ERA_D_T_FMT || item == ERA_T_FMT || item == ALT_DIGITS
    {
        return EMPTY;
    }
    if item == RADIXCHAR {
        return RADIX;
    }
    if item == THOUSEP {
        return THOU;
    }
    if item == YESEXPR {
        return YES_EXPR;
    }
    if item == NOEXPR {
        return NO_EXPR;
    }
    if item == YESSTR {
        return YES_STR;
    }
    if item == NOSTR {
        return NO_STR;
    }
    if item == CRNCYSTR {
        return CURRENCY;
    }
    if item == D_MD_ORDER {
        return MD_ORDER;
    }
    EMPTY
}

/// C `nl_langinfo` → nlist `_nl_langinfo` ("C" locale static strings).
///
/// curl hits this after the first network poll (codeset / date formats).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn nl_langinfo(item: c_int) -> *mut c_char {
    c_locale_nl(item).as_ptr().cast_mut().cast()
}

/// C `nl_langinfo_l` → nlist `_nl_langinfo_l` (ignore locale; same as "C").
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn nl_langinfo_l(
    item: c_int,
    _locale: *mut core::ffi::c_void,
) -> *mut c_char {
    unsafe { nl_langinfo(item) }
}
