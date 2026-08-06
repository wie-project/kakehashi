//! Freestanding `std::basic_string<char>` (+ `__next_prime`) for Apple arm64 libc++.
//!
//! Verified against host `sizeof`/byte dumps (CLT): 24-byte SSO, alternate
//! layout (`_LIBCPP_ABI_ALTERNATE_STRING_LAYOUT`):
//!
//! * **Short** (≤22): chars at offset 0; size in **last byte** (`rep[23]`);
//!   `is_long` = bit 7 of last byte clear.
//! * **Long**: `data*` @0, `size` @8, `cap | (1<<63)` @16 (`is_long` = MSB).
//!
//! Spec sources: public layout observation + libc++ docs (not a paste of
//! libc++ sources). Trace-first methods only.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::ptr_as_ptr
)]

use core::ffi::{c_char, c_void};
use core::ptr;

use crate::heap::{free, malloc};
use crate::trace;

const REP_SIZE: usize = 24;
/// Max payload chars in short mode (room for NUL in 23-byte buffer).
const SSO_CAP: usize = 22;
/// Long-mode flag: high bit of capacity word (Apple LE alternate layout).
const LONG_FLAG: usize = 1_usize << 63;

#[inline]
fn bytes(this: *const c_void) -> *const u8 {
    this.cast()
}

#[inline]
fn bytes_mut(this: *mut c_void) -> *mut u8 {
    this.cast()
}

#[inline]
fn is_long(this: *const c_void) -> bool {
    // Last byte high bit set ⇔ long (cap's MSB in LE).
    unsafe { *bytes(this).add(23) & 0x80 != 0 }
}

#[inline]
fn short_size(this: *const c_void) -> usize {
    usize::from(unsafe { *bytes(this).add(23) } & 0x7f)
}

#[inline]
fn long_size(this: *const c_void) -> usize {
    unsafe { this.cast::<usize>().add(1).read() }
}

#[inline]
fn long_data(this: *const c_void) -> *mut u8 {
    unsafe { this.cast::<*mut u8>().read() }
}

#[inline]
fn long_cap(this: *const c_void) -> usize {
    unsafe { this.cast::<usize>().add(2).read() & !LONG_FLAG }
}

fn zero_rep(this: *mut c_void) {
    unsafe {
        ptr::write_bytes(bytes_mut(this), 0, REP_SIZE);
    }
}

fn set_empty_short(this: *mut c_void) {
    zero_rep(this);
}

fn set_short(this: *mut c_void, s: *const u8, len: usize) {
    let len = len.min(SSO_CAP);
    zero_rep(this);
    unsafe {
        if len > 0 && !s.is_null() {
            ptr::copy_nonoverlapping(s, bytes_mut(this), len);
        }
        // NUL after payload (inline buffer is 23 bytes: 0..22).
        bytes_mut(this).add(len).write(0);
        bytes_mut(this)
            .add(23)
            .write(u8::try_from(len).unwrap_or(0));
    }
}

fn set_long(this: *mut c_void, s: *const u8, len: usize) {
    let need = len.saturating_add(1);
    // Even capacity ≥ need (classic libc++ parity habit; not required for flag).
    let mut cap = need.max(2);
    if cap % 2 == 1 {
        cap = cap.saturating_add(1);
    }
    let p = unsafe { malloc(cap) }.cast::<u8>();
    if p.is_null() {
        trace::force_note(b"[kh-libsystem] basic_string OOM\n");
        unsafe {
            crate::process::exit_now(1);
        }
    }
    unsafe {
        if len > 0 && !s.is_null() {
            ptr::copy_nonoverlapping(s, p, len);
        }
        p.add(len).write(0);
        this.cast::<*mut u8>().write(p);
        this.cast::<usize>().add(1).write(len);
        this.cast::<usize>().add(2).write(cap | LONG_FLAG);
    }
}

fn dispose(this: *mut c_void) {
    if this.is_null() {
        return;
    }
    if is_long(this) {
        let p = long_data(this);
        if !p.is_null() {
            unsafe {
                free(p.cast());
            }
        }
    }
    set_empty_short(this);
}

fn current_len(this: *const c_void) -> usize {
    if is_long(this) {
        long_size(this)
    } else {
        short_size(this)
    }
}

fn current_data(this: *const c_void) -> *const u8 {
    if is_long(this) {
        long_data(this).cast_const()
    } else {
        bytes(this)
    }
}

fn assign_bytes(this: *mut c_void, s: *const u8, len: usize) {
    if this.is_null() {
        return;
    }
    dispose(this);
    if len <= SSO_CAP {
        set_short(this, s, len);
    } else {
        set_long(this, s, len);
    }
}

fn cstr_len(s: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0_usize;
    unsafe {
        while *s.add(n) != 0 {
            n = n.saturating_add(1);
            if n > 1 << 28 {
                break;
            }
        }
    }
    n
}

// ── exports ─────────────────────────────────────────────────────────────────

/// `assign(char const*, size_t)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKcm")]
pub(crate) unsafe extern "C" fn string_assign_ptr_len(
    this: *mut c_void,
    s: *const c_char,
    n: usize,
) -> *mut c_void {
    assign_bytes(this, s.cast(), n);
    this
}

/// `assign(char const*)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc")]
pub(crate) unsafe extern "C" fn string_assign_cstr(
    this: *mut c_void,
    s: *const c_char,
) -> *mut c_void {
    assign_bytes(this, s.cast(), cstr_len(s));
    this
}

/// destructor
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev")]
pub(crate) unsafe extern "C" fn string_dtor(this: *mut c_void) {
    dispose(this);
}

/// `append(char const*, size_t)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm")]
pub(crate) unsafe extern "C" fn string_append_ptr_len(
    this: *mut c_void,
    s: *const c_char,
    n: usize,
) -> *mut c_void {
    if this.is_null() || n == 0 {
        return this;
    }
    let old = current_len(this);
    let new_len = old.saturating_add(n);
    let tmp = unsafe { malloc(new_len.saturating_add(1)) }.cast::<u8>();
    if tmp.is_null() {
        trace::force_note(b"[kh-libsystem] string append OOM\n");
        unsafe {
            crate::process::exit_now(1);
        }
    }
    unsafe {
        if old > 0 {
            ptr::copy_nonoverlapping(current_data(this), tmp, old);
        }
        if !s.is_null() {
            ptr::copy_nonoverlapping(s.cast::<u8>(), tmp.add(old), n);
        }
        tmp.add(new_len).write(0);
    }
    assign_bytes(this, tmp, new_len);
    unsafe {
        free(tmp.cast());
    }
    this
}

/// `append(char const*)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc")]
pub(crate) unsafe extern "C" fn string_append_cstr(
    this: *mut c_void,
    s: *const c_char,
) -> *mut c_void {
    unsafe { string_append_ptr_len(this, s, cstr_len(s)) }
}

/// `append(size_t, char)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEmc")]
pub(crate) unsafe extern "C" fn string_append_n_char(
    this: *mut c_void,
    n: usize,
    ch: c_char,
) -> *mut c_void {
    let n = n.min(1 << 20);
    if n == 0 {
        return this;
    }
    let fill = unsafe { malloc(n) }.cast::<u8>();
    if fill.is_null() {
        return this;
    }
    unsafe {
        ptr::write_bytes(fill, ch as u8, n);
        let _ = string_append_ptr_len(this, fill.cast(), n);
        free(fill.cast());
    }
    this
}

/// `push_back(char)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9push_backEc")]
pub(crate) unsafe extern "C" fn string_push_back(this: *mut c_void, ch: c_char) {
    let b = [ch as u8];
    unsafe {
        let _ = string_append_ptr_len(this, b.as_ptr().cast(), 1);
    }
}

/// `operator=(char)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSEc")]
pub(crate) unsafe extern "C" fn string_assign_char(this: *mut c_void, ch: c_char) -> *mut c_void {
    let b = [ch as u8];
    assign_bytes(this, b.as_ptr(), 1);
    this
}

/// `operator=(basic_string const&)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_")]
pub(crate) unsafe extern "C" fn string_copy_assign(
    this: *mut c_void,
    other: *const c_void,
) -> *mut c_void {
    if this.is_null() || other.is_null() || core::ptr::eq(this, other.cast_mut()) {
        return this;
    }
    let len = current_len(other);
    assign_bytes(this, current_data(other), len);
    this
}

/// `reserve(size_t)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7reserveEm")]
pub(crate) unsafe extern "C" fn string_reserve(this: *mut c_void, res: usize) {
    if this.is_null() {
        return;
    }
    let len = current_len(this);
    if res <= SSO_CAP && !is_long(this) {
        return;
    }
    if is_long(this) && long_cap(this).saturating_sub(1) >= res {
        return;
    }
    let need = res.max(len);
    let tmp = unsafe { malloc(len.saturating_add(1)) }.cast::<u8>();
    if tmp.is_null() {
        return;
    }
    unsafe {
        if len > 0 {
            ptr::copy_nonoverlapping(current_data(this), tmp, len);
        }
    }
    dispose(this);
    if need > SSO_CAP {
        set_long(this, tmp, len);
        // Ensure capacity ≥ res+1.
        if is_long(this) && long_cap(this) < res.saturating_add(1) {
            // re-set with larger
            let s = long_data(this);
            let old_len = long_size(this);
            let mut cap = res.saturating_add(1).max(2);
            if cap % 2 == 1 {
                cap = cap.saturating_add(1);
            }
            let p = unsafe { malloc(cap) }.cast::<u8>();
            if !p.is_null() {
                unsafe {
                    if old_len > 0 {
                        ptr::copy_nonoverlapping(s, p, old_len);
                    }
                    p.add(old_len).write(0);
                    free(s.cast());
                    this.cast::<*mut u8>().write(p);
                    this.cast::<usize>().add(1).write(old_len);
                    this.cast::<usize>().add(2).write(cap | LONG_FLAG);
                }
            }
        }
    } else {
        set_short(this, tmp, len);
    }
    unsafe {
        free(tmp.cast());
    }
}

/// `__grow_by`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9__grow_byEmmmmmm")]
pub(crate) unsafe extern "C" fn string_grow_by(
    this: *mut c_void,
    _old_cap: usize,
    delta_cap: usize,
    old_sz: usize,
    n_copy: usize,
    n_del: usize,
    n_add: usize,
) {
    let new_sz = old_sz.saturating_sub(n_del).saturating_add(n_add);
    let want = old_sz
        .saturating_add(delta_cap)
        .max(new_sz)
        .max(n_copy.saturating_add(n_add));
    unsafe {
        string_reserve(this, want);
    }
}

/// `resize(size_t, char)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6resizeEmc")]
pub(crate) unsafe extern "C" fn string_resize(this: *mut c_void, n: usize, ch: c_char) {
    if this.is_null() {
        return;
    }
    let old = current_len(this);
    if n == old {
        return;
    }
    if n < old {
        let tmp = unsafe { malloc(n.saturating_add(1)) }.cast::<u8>();
        if tmp.is_null() {
            return;
        }
        unsafe {
            if n > 0 {
                ptr::copy_nonoverlapping(current_data(this), tmp, n);
            }
        }
        assign_bytes(this, tmp, n);
        unsafe {
            free(tmp.cast());
        }
        return;
    }
    let add = n.saturating_sub(old).min(1 << 20);
    if add == 0 {
        return;
    }
    let fill = unsafe { malloc(add) }.cast::<u8>();
    if fill.is_null() {
        return;
    }
    unsafe {
        ptr::write_bytes(fill, ch as u8, add);
        let _ = string_append_ptr_len(this, fill.cast(), add);
        free(fill.cast());
    }
}

/// `at(size_t)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE2atEm")]
pub(crate) unsafe extern "C" fn string_at(this: *mut c_void, pos: usize) -> *mut c_char {
    if this.is_null() {
        return core::ptr::null_mut();
    }
    let len = current_len(this);
    if pos >= len {
        trace::force_note(b"[kh-libsystem] basic_string::at OOB\n");
        unsafe {
            crate::process::exit_now(1);
        }
    }
    unsafe { current_data(this).add(pos).cast_mut().cast() }
}

/// const `at`
#[unsafe(export_name = "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE2atEm")]
pub(crate) unsafe extern "C" fn string_at_const(this: *const c_void, pos: usize) -> *const c_char {
    unsafe { string_at(this.cast_mut(), pos) }.cast_const()
}

/// `basic_string(string const&, pos, n, allocator)` — substring ctor (C2).
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_mmRKS4_")]
pub(crate) unsafe extern "C" fn string_ctor_substr(
    this: *mut c_void,
    other: *const c_void,
    pos: usize,
    n: usize,
    _alloc: *const c_void,
) {
    if this.is_null() {
        return;
    }
    zero_rep(this);
    if other.is_null() {
        return;
    }
    let olen = current_len(other);
    if pos >= olen {
        return;
    }
    let take = n.min(olen.saturating_sub(pos));
    let src = unsafe { current_data(other).add(pos) };
    assign_bytes(this, src, take);
}

/// Same substring ctor, complete-object C1 alias (some TUs).
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_mmRKS4_")]
pub(crate) unsafe extern "C" fn string_ctor_substr_c1(
    this: *mut c_void,
    other: *const c_void,
    pos: usize,
    n: usize,
    alloc: *const c_void,
) {
    unsafe {
        string_ctor_substr(this, other, pos, n, alloc);
    }
}

/// `insert(size_t, char const*, size_t)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm")]
pub(crate) unsafe extern "C" fn string_insert_ptr_len(
    this: *mut c_void,
    pos: usize,
    s: *const c_char,
    n: usize,
) -> *mut c_void {
    if this.is_null() {
        return this;
    }
    let old = current_len(this);
    let pos = pos.min(old);
    let new_len = old.saturating_add(n);
    let tmp = unsafe { malloc(new_len.saturating_add(1)) }.cast::<u8>();
    if tmp.is_null() {
        return this;
    }
    unsafe {
        if pos > 0 {
            ptr::copy_nonoverlapping(current_data(this), tmp, pos);
        }
        if n > 0 && !s.is_null() {
            ptr::copy_nonoverlapping(s.cast::<u8>(), tmp.add(pos), n);
        }
        if old > pos {
            ptr::copy_nonoverlapping(
                current_data(this).add(pos),
                tmp.add(pos.saturating_add(n)),
                old.saturating_sub(pos),
            );
        }
        tmp.add(new_len).write(0);
    }
    assign_bytes(this, tmp, new_len);
    unsafe {
        free(tmp.cast());
    }
    this
}

/// `insert(size_t, char const*)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKc")]
pub(crate) unsafe extern "C" fn string_insert_cstr(
    this: *mut c_void,
    pos: usize,
    s: *const c_char,
) -> *mut c_void {
    unsafe { string_insert_ptr_len(this, pos, s, cstr_len(s)) }
}

/// `insert(size_t, size_t, char)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmmc")]
pub(crate) unsafe extern "C" fn string_insert_n_char(
    this: *mut c_void,
    pos: usize,
    n: usize,
    ch: c_char,
) -> *mut c_void {
    let n = n.min(1 << 20);
    if n == 0 {
        return this;
    }
    let fill = unsafe { malloc(n) }.cast::<u8>();
    if fill.is_null() {
        return this;
    }
    unsafe {
        ptr::write_bytes(fill, ch as u8, n);
        let _ = string_insert_ptr_len(this, pos, fill.cast(), n);
        free(fill.cast());
    }
    this
}

/// `insert(__wrap_iter<char const*>, char)` → returns iterator (pointer).
///
/// Observed: libtapi / `ld-classic` TBD parse (G4). `__wrap_iter` is a
/// pointer-sized iterator over the string buffer.
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertENS_11__wrap_iterIPKcEEc")]
pub(crate) unsafe extern "C" fn string_insert_iter_char(
    this: *mut c_void,
    pos_it: *const c_char,
    ch: c_char,
) -> *mut c_char {
    if this.is_null() {
        return core::ptr::null_mut();
    }
    let data = current_data(this);
    let len = current_len(this);
    let pos = if pos_it.is_null() || data.is_null() {
        len
    } else {
        let off = pos_it.addr().saturating_sub(data.addr());
        off.min(len)
    };
    let one = [ch as u8];
    unsafe {
        let _ = string_insert_ptr_len(this, pos, one.as_ptr().cast(), 1);
    }
    // Return iterator to inserted char.
    let new_data = current_data(this);
    if new_data.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { new_data.add(pos).cast_mut().cast() }
}

/// `erase(size_t, size_t)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5eraseEmm")]
pub(crate) unsafe extern "C" fn string_erase(
    this: *mut c_void,
    pos: usize,
    n: usize,
) -> *mut c_void {
    if this.is_null() {
        return this;
    }
    let old = current_len(this);
    if pos >= old || n == 0 {
        return this;
    }
    let end = pos.saturating_add(n).min(old);
    let keep_tail = old.saturating_sub(end);
    let new_len = pos.saturating_add(keep_tail);
    let tmp = unsafe { malloc(new_len.saturating_add(1)) }.cast::<u8>();
    if tmp.is_null() {
        return this;
    }
    unsafe {
        if pos > 0 {
            ptr::copy_nonoverlapping(current_data(this), tmp, pos);
        }
        if keep_tail > 0 {
            ptr::copy_nonoverlapping(current_data(this).add(end), tmp.add(pos), keep_tail);
        }
        tmp.add(new_len).write(0);
    }
    assign_bytes(this, tmp, new_len);
    unsafe {
        free(tmp.cast());
    }
    this
}

/// `replace(size_t, size_t, char const*, size_t)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7replaceEmmPKcm")]
pub(crate) unsafe extern "C" fn string_replace_ptr_len(
    this: *mut c_void,
    pos: usize,
    n1: usize,
    s: *const c_char,
    n2: usize,
) -> *mut c_void {
    unsafe {
        let _ = string_erase(this, pos, n1);
        string_insert_ptr_len(this, pos, s, n2)
    }
}

/// `replace(size_t, size_t, char const*)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7replaceEmmPKc")]
pub(crate) unsafe extern "C" fn string_replace_cstr(
    this: *mut c_void,
    pos: usize,
    n1: usize,
    s: *const c_char,
) -> *mut c_void {
    unsafe { string_replace_ptr_len(this, pos, n1, s, cstr_len(s)) }
}

/// `append(string const&, pos, n)`
#[unsafe(export_name = "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendERKS5_mm")]
pub(crate) unsafe extern "C" fn string_append_substr(
    this: *mut c_void,
    other: *const c_void,
    pos: usize,
    n: usize,
) -> *mut c_void {
    if other.is_null() {
        return this;
    }
    let olen = current_len(other);
    if pos >= olen {
        return this;
    }
    let take = n.min(olen.saturating_sub(pos));
    let src = unsafe { current_data(other).add(pos) };
    unsafe { string_append_ptr_len(this, src.cast(), take) }
}

/// 24-byte `basic_string` blob returned by value (AArch64 C ABI → sret in `x8`).
///
/// Must **not** take the result pointer as a normal argument: callers pass the
/// C-string in `x0`; treating `x0` as sret wrote into RO string literals (SIGSEGV).
#[repr(C)]
pub(crate) struct StringRep {
    bytes: [u8; REP_SIZE],
}

impl StringRep {
    /// Empty short string (all zeros under Apple alternate layout).
    #[inline]
    pub(crate) const fn empty() -> Self {
        Self {
            bytes: [0_u8; REP_SIZE],
        }
    }
}

/// `operator+` free: `string operator+(char const*, string const&)`
#[unsafe(export_name = "_ZNSt3__1plIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_12basic_stringIT_T0_T1_EEPKS6_RKS9_")]
pub(crate) unsafe extern "C" fn string_op_add_cstr_string(
    lhs: *const c_char,
    rhs: *const c_void,
) -> StringRep {
    let mut out = StringRep {
        bytes: [0_u8; REP_SIZE],
    };
    let p = out.bytes.as_mut_ptr().cast::<c_void>();
    zero_rep(p);
    let ln = cstr_len(lhs);
    assign_bytes(p, lhs.cast(), ln);
    if !rhs.is_null() {
        let rn = current_len(rhs);
        unsafe {
            let _ = string_append_ptr_len(p, current_data(rhs).cast(), rn);
        }
    }
    out
}

/// Format decimal into `buf` (NUL-terminated); returns length without NUL.
fn fmt_u64_dec(mut v: u64, buf: &mut [u8]) -> usize {
    // Max u64 decimal digits = 20 + NUL.
    if buf.len() < 2 {
        return 0;
    }
    let mut tmp = [0_u8; 20];
    let mut n = 0_usize;
    if v == 0 {
        tmp[0] = b'0';
        n = 1;
    } else {
        while v > 0 && n < tmp.len() {
            let d = (v % 10) as u8;
            tmp[n] = b'0' + d;
            n = n.saturating_add(1);
            v /= 10;
        }
        // reverse digits in place
        let mut i = 0;
        let mut j = n.saturating_sub(1);
        while i < j {
            tmp.swap(i, j);
            i = i.saturating_add(1);
            j = j.saturating_sub(1);
        }
    }
    let cap = buf.len().saturating_sub(1).min(n);
    if cap > 0 {
        buf[..cap].copy_from_slice(&tmp[..cap]);
    }
    if let Some(slot) = buf.get_mut(cap) {
        *slot = 0;
    }
    cap
}

fn string_from_u64(v: u64) -> StringRep {
    let mut out = StringRep {
        bytes: [0_u8; REP_SIZE],
    };
    let mut digs = [0_u8; 24];
    let n = fmt_u64_dec(v, &mut digs);
    let p = out.bytes.as_mut_ptr().cast::<c_void>();
    assign_bytes(p, digs.as_ptr(), n);
    out
}

fn string_from_i64(v: i64) -> StringRep {
    if v >= 0 {
        return string_from_u64(v as u64);
    }
    // Negative: '-' + abs (careful with i64::MIN)
    let mut out = StringRep {
        bytes: [0_u8; REP_SIZE],
    };
    let mut digs = [0_u8; 24];
    digs[0] = b'-';
    let mag = v.unsigned_abs();
    let n = fmt_u64_dec(mag, &mut digs[1..]).saturating_add(1);
    let p = out.bytes.as_mut_ptr().cast::<c_void>();
    assign_bytes(p, digs.as_ptr(), n);
    out
}

/// `std::to_string(unsigned int)` — observed Apple clang -cc1.
#[unsafe(export_name = "_ZNSt3__19to_stringEj")]
pub(crate) unsafe extern "C" fn to_string_uint(v: u32) -> StringRep {
    string_from_u64(u64::from(v))
}

/// `std::to_string(int)`
#[unsafe(export_name = "_ZNSt3__19to_stringEi")]
pub(crate) unsafe extern "C" fn to_string_int(v: i32) -> StringRep {
    string_from_i64(i64::from(v))
}

/// `std::to_string(unsigned long)` (LP64 = u64)
#[unsafe(export_name = "_ZNSt3__19to_stringEm")]
pub(crate) unsafe extern "C" fn to_string_ulong(v: u64) -> StringRep {
    string_from_u64(v)
}

/// `std::to_string(long)`
#[unsafe(export_name = "_ZNSt3__19to_stringEl")]
pub(crate) unsafe extern "C" fn to_string_long(v: i64) -> StringRep {
    string_from_i64(v)
}

/// `std::to_string(unsigned long long)`
#[unsafe(export_name = "_ZNSt3__19to_stringEy")]
pub(crate) unsafe extern "C" fn to_string_ull(v: u64) -> StringRep {
    string_from_u64(v)
}

/// `std::to_string(long long)`
#[unsafe(export_name = "_ZNSt3__19to_stringEx")]
pub(crate) unsafe extern "C" fn to_string_ll(v: i64) -> StringRep {
    string_from_i64(v)
}

/// `std::stoi(string const&, size_t* idx, int base)` — Apple `ld-classic` (G4).
///
/// Mangled: `_ZNSt3__14stoiERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPmi`
#[unsafe(export_name = "_ZNSt3__14stoiERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEPmi")]
pub(crate) unsafe extern "C" fn stoi_string(
    s: *const c_void,
    idx: *mut usize,
    base: i32,
) -> i32 {
    if s.is_null() {
        return 0;
    }
    let data = current_data(s);
    let len = current_len(s);
    let (val, consumed) = parse_i32_prefix(data, len, base);
    if !idx.is_null() {
        unsafe {
            idx.write(consumed);
        }
    }
    val
}

/// Parse a C++ `stoi`-style integer prefix from `data[0..len]`.
fn parse_i32_prefix(data: *const u8, len: usize, base: i32) -> (i32, usize) {
    if data.is_null() || len == 0 {
        return (0, 0);
    }
    let mut i = 0_usize;
    // skip whitespace
    while i < len {
        let b = unsafe { data.add(i).read() };
        if !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c') {
            break;
        }
        i = i.saturating_add(1);
    }
    let start = i;
    let mut neg = false;
    if i < len {
        let b = unsafe { data.add(i).read() };
        if b == b'+' || b == b'-' {
            neg = b == b'-';
            i = i.saturating_add(1);
        }
    }
    let mut base_u = base;
    if base_u == 0 {
        if i < len && unsafe { data.add(i).read() } == b'0' {
            if i + 1 < len {
                let n = unsafe { data.add(i + 1).read() };
                if n == b'x' || n == b'X' {
                    base_u = 16;
                    i = i.saturating_add(2);
                } else {
                    base_u = 8;
                }
            } else {
                base_u = 8;
            }
        } else {
            base_u = 10;
        }
    } else if base_u == 16
        && i + 1 < len
        && unsafe { data.add(i).read() } == b'0'
        && matches!(unsafe { data.add(i + 1).read() }, b'x' | b'X')
    {
        i = i.saturating_add(2);
    }
    if !(2..=36).contains(&base_u) {
        return (0, start);
    }
    let radix = base_u as u32;
    let mut acc: i64 = 0;
    let mut any = false;
    while i < len {
        let b = unsafe { data.add(i).read() };
        let digit = match b {
            b'0'..=b'9' => u32::from(b - b'0'),
            b'a'..=b'z' => u32::from(b - b'a') + 10,
            b'A'..=b'Z' => u32::from(b - b'A') + 10,
            _ => break,
        };
        if digit >= radix {
            break;
        }
        any = true;
        acc = acc
            .saturating_mul(i64::from(radix))
            .saturating_add(i64::from(digit));
        i = i.saturating_add(1);
    }
    if !any {
        return (0, start);
    }
    if neg {
        acc = -acc;
    }
    let clamped = acc.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
    (clamped, i)
}

/// `std::__1::__next_prime(size_t)` — bucket count helper for unordered_* .
/// nlist `__ZNSt3__112__next_primeEm`
#[unsafe(export_name = "_ZNSt3__112__next_primeEm")]
pub(crate) unsafe extern "C" fn next_prime(n: usize) -> usize {
    if n <= 2 {
        return 2;
    }
    let mut x = n | 1; // odd
    loop {
        if is_prime(x) {
            return x;
        }
        x = x.saturating_add(2);
        if x < n {
            // overflow wrap — fall back
            return n.max(2);
        }
    }
}

fn is_prime(n: usize) -> bool {
    if n < 2 {
        return false;
    }
    if n.is_multiple_of(2) {
        return n == 2;
    }
    let mut d = 3_usize;
    while d.saturating_mul(d) <= n {
        if n.is_multiple_of(d) {
            return false;
        }
        d = d.saturating_add(2);
    }
    true
}
