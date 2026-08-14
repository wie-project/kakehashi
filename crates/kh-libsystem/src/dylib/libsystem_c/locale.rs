//! Darwin locale / rune surface (`_DefaultRuneLocale`, `mbrtowc`, `nl_langinfo`).
//!
//! Default encoding is **UTF-8** (macOS interactive default). ASCII-only "C"
//! made Apple `zsh`/`zle` treat Cyrillic bytes as non-print (`?<xx>`) and
//! scramble column width / spaces.

use core::ffi::{c_char, c_int, c_void};

use super::utf8;

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

const fn encoding_utf8() -> [u8; 32] {
    let mut e = [0_u8; 32];
    e[0] = b'U';
    e[1] = b'T';
    e[2] = b'F';
    e[3] = b'-';
    e[4] = b'8';
    e
}

/// C `_DefaultRuneLocale` → nlist `__DefaultRuneLocale`.
#[unsafe(export_name = "_DefaultRuneLocale")]
#[used]
static DEFAULT_RUNE_LOCALE: RuneLocale = RuneLocale {
    magic: RUNE_MAGIC,
    encoding: encoding_utf8(),
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

fn rune_bits(c: c_int) -> u32 {
    if c < 0 {
        return 0;
    }
    let idx = usize::try_from(c.cast_unsigned()).unwrap_or(usize::MAX);
    if let Some(bits) = DEFAULT_RUNE_LOCALE.runetype.get(idx).copied() {
        return bits;
    }
    let mut f = 0_u32;
    if utf8::is_print(c) {
        f |= CTYPE_R | CTYPE_G;
    }
    if utf8::is_alpha(c) {
        f |= CTYPE_A;
        if utf8::to_lower(c) != c {
            f |= CTYPE_U;
        }
        if utf8::to_upper(c) != c {
            f |= CTYPE_L;
        }
    }
    if utf8::is_digit(c) {
        f |= CTYPE_D | CTYPE_X;
    }
    f
}

/// Darwin `___maskrune` → nlist `___maskrune` (ctype backend).
#[unsafe(export_name = "__maskrune")]
pub(crate) unsafe extern "C" fn __maskrune(c: c_int, f: usize) -> c_int {
    let bits = usize::try_from(rune_bits(c)).unwrap_or(0);
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
pub(crate) static mut __mb_cur_max: c_int = 6;

/// Darwin `___mb_cur_max_l` → nlist `____mb_cur_max_l`.
#[unsafe(export_name = "___mb_cur_max_l")]
pub(crate) unsafe extern "C" fn ___mb_cur_max_l(_locale: *mut core::ffi::c_void) -> c_int {
    6
}

/// Darwin `___mb_cur_max` → nlist `____mb_cur_max` (callers that use a fn).
#[unsafe(export_name = "___mb_cur_max")]
pub(crate) unsafe extern "C" fn ___mb_cur_max() -> c_int {
    6
}

/// C `mblen` → nlist `_mblen`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mblen(s: *const c_char, n: usize) -> c_int {
    unsafe { mbtowc(core::ptr::null_mut(), s, n) }
}

/// C `mbtowc` → nlist `_mbtowc` (UTF-8, non-restartable).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mbtowc(pwc: *mut i32, s: *const c_char, n: usize) -> c_int {
    if s.is_null() {
        return 0;
    }
    let r = unsafe { mbrtowc(pwc, s, n, core::ptr::null_mut()) };
    if r == utf8::MB_ILLEGAL || r == utf8::MB_INCOMPLETE {
        return -1;
    }
    c_int::try_from(r).unwrap_or(-1)
}

/// C `wctomb` → nlist `_wctomb` (UTF-8).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wctomb(s: *mut c_char, wc: i32) -> c_int {
    if s.is_null() {
        return 0;
    }
    let n = unsafe { wcrtomb(s, wc, core::ptr::null_mut()) };
    if n == utf8::MB_ILLEGAL {
        return -1;
    }
    c_int::try_from(n).unwrap_or(-1)
}

/// Darwin `wchar_t` for locale conversion (32-bit).
type Wchar = i32;

/// C `mbrtowc` → nlist `_mbrtowc` (UTF-8, restartable).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mbrtowc(
    pwc: *mut Wchar,
    s: *const c_char,
    n: usize,
    ps: *mut c_void,
) -> usize {
    if s.is_null() {
        utf8::MbState::initial().store(ps);
        return 0;
    }
    let mut st = utf8::MbState::load(ps);
    // SAFETY: caller guarantees `n` readable bytes at `s`.
    let bytes = unsafe { core::slice::from_raw_parts(s.cast::<u8>(), n) };
    let (r, wc) = utf8::mbrtowc(bytes, &mut st);
    st.store(ps);
    if let Some(w) = wc
        && !pwc.is_null()
    {
        unsafe {
            pwc.write(w);
        }
    }
    r
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

/// C `btowc` → nlist `_btowc` (UTF-8: only 0..=127).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn btowc(c: c_int) -> Wchar {
    if (0..=127).contains(&c) { c } else { -1 }
}

/// C `wctob` → nlist `_wctob`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wctob(c: Wchar) -> c_int {
    if (0..=127).contains(&c) { c } else { -1 }
}

/// C `wcrtomb` → nlist `_wcrtomb` (UTF-8).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wcrtomb(s: *mut c_char, wc: Wchar, ps: *mut c_void) -> usize {
    utf8::MbState::initial().store(ps);
    if s.is_null() {
        return 1;
    }
    let mut buf = [0_u8; 4];
    let Some(n) = utf8::encode(wc, &mut buf) else {
        return utf8::MB_ILLEGAL;
    };
    unsafe {
        for i in 0..n {
            if let Some(&b) = buf.get(i) {
                s.add(i).write(b.cast_signed());
            }
        }
    }
    n
}

/// C `mbsrtowcs` → nlist `_mbsrtowcs`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mbsrtowcs(
    dst: *mut Wchar,
    src: *mut *const c_char,
    len: usize,
    ps: *mut c_void,
) -> usize {
    if src.is_null() {
        return utf8::MB_ILLEGAL;
    }
    let mut s = unsafe { src.read() };
    if s.is_null() {
        return 0;
    }
    let mut out = 0_usize;
    loop {
        if !dst.is_null() && out >= len {
            unsafe {
                src.write(s);
            }
            return out;
        }
        let mut wc: Wchar = 0;
        let avail = unsafe { cstr_avail(s) };
        let n = unsafe { mbrtowc(core::ptr::from_mut(&mut wc), s, avail, ps) };
        if n == utf8::MB_ILLEGAL || n == utf8::MB_INCOMPLETE {
            unsafe {
                src.write(s);
            }
            return utf8::MB_ILLEGAL;
        }
        if n == 0 {
            if !dst.is_null() && out < len {
                unsafe {
                    dst.add(out).write(0);
                }
            }
            unsafe {
                src.write(core::ptr::null());
            }
            return out;
        }
        if !dst.is_null() {
            unsafe {
                dst.add(out).write(wc);
            }
        }
        s = unsafe { s.add(n) };
        out = out.saturating_add(1);
    }
}

unsafe fn cstr_avail(s: *const c_char) -> usize {
    let mut n = 0_usize;
    loop {
        let b = unsafe { s.add(n).read() };
        n = n.saturating_add(1);
        if b == 0 || n == usize::MAX {
            return n;
        }
    }
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
const CODESET_UTF8: &[u8] = b"UTF-8\0";
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
        return CODESET_UTF8;
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
    if item == ERA
        || item == ERA_D_FMT
        || item == ERA_D_T_FMT
        || item == ERA_T_FMT
        || item == ALT_DIGITS
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

/// C `nl_langinfo` → nlist `_nl_langinfo` (UTF-8 codeset + POSIX date strings).
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

/// Darwin `wctype_t` is 32-bit (`__darwin_wctype_t`).
type Wctype = u32;

const WCTRANS_TOLOWER: usize = 1;
const WCTRANS_TOUPPER: usize = 2;

fn cstr_eq_bytes(p: *const c_char, s: &[u8]) -> bool {
    if p.is_null() {
        return false;
    }
    for (i, &b) in s.iter().enumerate() {
        // SAFETY: `p` is a guest C string; `s` is a short ASCII name.
        if unsafe { p.add(i).read() }.cast_unsigned() != b {
            return false;
        }
    }
    unsafe { p.add(s.len()).read() == 0 }
}

/// C `wctype` → nlist `_wctype` (class name → `_CTYPE_*` mask).
///
/// Apple `/usr/bin/cd` runs `tr [:upper:] [:lower:]`, which looks up classes
/// here. "C" locale only.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wctype(property: *const c_char) -> Wctype {
    if cstr_eq_bytes(property, b"alnum") {
        return CTYPE_A | CTYPE_D;
    }
    if cstr_eq_bytes(property, b"alpha") {
        return CTYPE_A;
    }
    if cstr_eq_bytes(property, b"blank") {
        return CTYPE_B;
    }
    if cstr_eq_bytes(property, b"cntrl") {
        return CTYPE_C;
    }
    if cstr_eq_bytes(property, b"digit") {
        return CTYPE_D;
    }
    if cstr_eq_bytes(property, b"graph") {
        return CTYPE_G;
    }
    if cstr_eq_bytes(property, b"lower") {
        return CTYPE_L;
    }
    if cstr_eq_bytes(property, b"print") {
        return CTYPE_R;
    }
    if cstr_eq_bytes(property, b"punct") {
        return CTYPE_P;
    }
    if cstr_eq_bytes(property, b"space") {
        return CTYPE_S;
    }
    if cstr_eq_bytes(property, b"upper") {
        return CTYPE_U;
    }
    if cstr_eq_bytes(property, b"xdigit") {
        return CTYPE_X;
    }
    0
}

/// C `iswctype` → nlist `_iswctype`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswctype(wc: Wchar, charclass: Wctype) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(charclass).unwrap_or(0)) }
}

/// C `iswalnum` → nlist `_iswalnum`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswalnum(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_A | CTYPE_D).unwrap_or(0)) }
}

/// C `iswalpha` → nlist `_iswalpha`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswalpha(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_A).unwrap_or(0)) }
}

/// C `iswblank` → nlist `_iswblank`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswblank(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_B).unwrap_or(0)) }
}

/// C `iswcntrl` → nlist `_iswcntrl`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswcntrl(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_C).unwrap_or(0)) }
}

/// C `iswdigit` → nlist `_iswdigit`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswdigit(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_D).unwrap_or(0)) }
}

/// C `iswgraph` → nlist `_iswgraph`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswgraph(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_G).unwrap_or(0)) }
}

/// C `iswlower` → nlist `_iswlower`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswlower(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_L).unwrap_or(0)) }
}

/// C `iswprint` → nlist `_iswprint`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswprint(wc: Wchar) -> c_int {
    c_int::from(utf8::is_print(wc))
}

/// C `iswpunct` → nlist `_iswpunct`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswpunct(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_P).unwrap_or(0)) }
}

/// C `iswspace` → nlist `_iswspace`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswspace(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_S).unwrap_or(0)) }
}

/// C `iswupper` → nlist `_iswupper`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswupper(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_U).unwrap_or(0)) }
}

/// C `iswxdigit` → nlist `_iswxdigit`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn iswxdigit(wc: Wchar) -> c_int {
    unsafe { __maskrune(wc, usize::try_from(CTYPE_X).unwrap_or(0)) }
}

/// C `towlower` → nlist `_towlower`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn towlower(wc: Wchar) -> Wchar {
    utf8::to_lower(wc)
}

/// C `towupper` → nlist `_towupper`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn towupper(wc: Wchar) -> Wchar {
    utf8::to_upper(wc)
}

/// C `wctrans` → nlist `_wctrans`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wctrans(property: *const c_char) -> usize {
    if cstr_eq_bytes(property, b"tolower") {
        WCTRANS_TOLOWER
    } else if cstr_eq_bytes(property, b"toupper") {
        WCTRANS_TOUPPER
    } else {
        0
    }
}

/// C `getwchar` → nlist `_getwchar` ("C" locale: one byte from stdin).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getwchar() -> Wchar {
    let mut b = 0_u8;
    let n = unsafe {
        crate::kh_core::sys::syscall3(
            crate::kh_core::sys::SYS_READ,
            0,
            u64::try_from(core::ptr::from_mut(&mut b).addr()).unwrap_or(0),
            1,
        )
    };
    if n <= 0 {
        -1
    } else {
        i32::from(b)
    }
}

/// C `putwchar` → nlist `_putwchar`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn putwchar(wc: Wchar) -> Wchar {
    let mut buf = [0_u8; 4];
    let Some(len) = utf8::encode(wc, &mut buf) else {
        return -1;
    };
    let n = unsafe {
        crate::kh_core::sys::syscall3(
            crate::kh_core::sys::SYS_WRITE,
            1,
            u64::try_from(core::ptr::from_ref(&buf).addr()).unwrap_or(0),
            u64::try_from(len).unwrap_or(0),
        )
    };
    if n <= 0 { -1 } else { wc }
}

/// C `getwc` → nlist `_getwc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getwc(stream: *mut c_void) -> Wchar {
    let c = unsafe { crate::dylib::libsystem_c::stdio::fgetc(stream) };
    if c < 0 { -1 } else { c }
}

/// C `putwc` → nlist `_putwc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn putwc(wc: Wchar, stream: *mut c_void) -> Wchar {
    let c = unsafe { crate::dylib::libsystem_c::stdio::fputc(wc, stream) };
    if c < 0 { -1 } else { wc }
}

/// C `fgetwc` → nlist `_fgetwc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fgetwc(stream: *mut c_void) -> Wchar {
    unsafe { getwc(stream) }
}

/// C `fputwc` → nlist `_fputwc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fputwc(wc: Wchar, stream: *mut c_void) -> Wchar {
    unsafe { putwc(wc, stream) }
}

/// C `ungetwc` → nlist `_ungetwc`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ungetwc(wc: Wchar, stream: *mut c_void) -> Wchar {
    let c = unsafe { crate::dylib::libsystem_c::stdio::ungetc(wc, stream) };
    if c < 0 { -1 } else { wc }
}

/// C `wcwidth` → nlist `_wcwidth`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wcwidth(wc: Wchar) -> c_int {
    utf8::width(wc)
}

/// C `wcswidth` → nlist `_wcswidth`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wcswidth(pwcs: *const Wchar, n: usize) -> c_int {
    if pwcs.is_null() {
        return -1;
    }
    let mut w = 0_i32;
    let mut i = 0_usize;
    while i < n {
        let c = unsafe { pwcs.add(i).read() };
        if c == 0 {
            break;
        }
        let cw = unsafe { wcwidth(c) };
        if cw < 0 {
            return -1;
        }
        w = w.saturating_add(cw);
        i = i.saturating_add(1);
    }
    w
}

/// C `nextwctype` → nlist `_nextwctype` (next rune in `charclass`, or −1).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn nextwctype(wc: Wchar, charclass: Wctype) -> Wchar {
    if charclass == 0 {
        return -1;
    }
    let start = if wc < 0 { 0 } else { wc.saturating_add(1) };
    let mut c = start;
    while c <= 255 {
        if unsafe { iswctype(c, charclass) } != 0 {
            return c;
        }
        c = c.saturating_add(1);
    }
    -1
}

/// C `towctrans` → nlist `_towctrans`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn towctrans(wc: Wchar, desc: usize) -> Wchar {
    if desc == WCTRANS_TOLOWER {
        unsafe { towlower(wc) }
    } else if desc == WCTRANS_TOUPPER {
        unsafe { towupper(wc) }
    } else {
        wc
    }
}
