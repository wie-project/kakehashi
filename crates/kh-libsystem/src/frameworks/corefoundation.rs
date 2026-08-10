//! CoreFoundation soft surface (clean-room; flat-lookup from bottle).
//!
//! CF objects use freestanding heap tags for curl's AppleSecTrust path.

#![allow(unused_imports)]

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::kh_core::heap::{free, malloc};
use crate::kh_core::sys;
use crate::kh_core::trace;

/// Opaque object magic.
pub(crate) const CF_MAGIC: usize = 0x4346_5f4b_4801; // "CF_KH\1"

pub(crate) const KIND_DATA: u32 = 1;
pub(crate) const KIND_STR: u32 = 2;
pub(crate) const KIND_ARR: u32 = 3;
pub(crate) const KIND_CERT: u32 = 4;
pub(crate) const KIND_POLICY: u32 = 5;
pub(crate) const KIND_TRUST: u32 = 6;

pub(crate) const HDR_WORDS: usize = 2; // magic + (kind:u32 | len:u32) packed in usize on 64-bit
pub(crate) const MAX_ARR: usize = 16;
pub(crate) const MAX_VERIFY_BUF: usize = 256 * 1024;

#[inline]
pub(crate) fn hdr_kind_len(kind: u32, len: u32) -> usize {
    usize::try_from(u64::from(kind) | (u64::from(len) << 32)).unwrap_or(0)
}

#[inline]
pub(crate) fn kind_of(word: usize) -> u32 {
    u32::try_from(word & 0xFFFF_FFFF).unwrap_or(0)
}

#[inline]
pub(crate) fn len_of(word: usize) -> u32 {
    // High 32 bits of the packed kind|len word (64-bit guest).
    u32::try_from(word.checked_shr(32).unwrap_or(0)).unwrap_or(0)
}

pub(crate) fn alloc_raw(bytes: usize) -> *mut c_void {
    let p = unsafe { malloc(bytes) };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    // Zero payload so unused array slots are null.
    unsafe {
        core::ptr::write_bytes(p.cast::<u8>(), 0, bytes);
    }
    p
}

pub(crate) fn obj_write_hdr(p: *mut c_void, kind: u32, len: u32) {
    unsafe {
        p.cast::<usize>().write(CF_MAGIC);
        p.cast::<usize>().add(1).write(hdr_kind_len(kind, len));
    }
}

pub(crate) fn is_obj(p: *mut c_void) -> bool {
    if p.is_null() {
        return false;
    }
    unsafe { p.cast::<usize>().read() == CF_MAGIC }
}

pub(crate) fn obj_kind(p: *mut c_void) -> Option<u32> {
    if !is_obj(p) {
        return None;
    }
    Some(kind_of(unsafe { p.cast::<usize>().add(1).read() }))
}

pub(crate) fn obj_len(p: *mut c_void) -> u32 {
    if !is_obj(p) {
        return 0;
    }
    len_of(unsafe { p.cast::<usize>().add(1).read() })
}

/// Byte payload after the 2-word header (aligned to `usize`).
pub(crate) fn payload_bytes(p: *mut c_void) -> *mut u8 {
    // SAFETY: header is 2 usizes; result is still usize-aligned.
    unsafe { p.cast::<usize>().add(HDR_WORDS).cast::<u8>() }
}

/// Word-sized payload slots after the header (CFArray / Sec* pointers).
pub(crate) fn payload_words(p: *mut c_void) -> *mut usize {
    // SAFETY: header is 2 usizes; remainder is usize-aligned storage.
    unsafe { p.cast::<usize>().add(HDR_WORDS) }
}

// ── CoreFoundation (data) ───────────────────────────────────────────────────

/// `kCFTypeArrayCallBacks` — opaque table; never read if CF paths unused.
#[unsafe(export_name = "kCFTypeArrayCallBacks")]
#[used]
static K_CF_TYPE_ARRAY_CALLBACKS: [usize; 8] = [0; 8];

// ── CoreFoundation (functions) ──────────────────────────────────────────────

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFArrayAppendValue(arr: *mut c_void, value: *const c_void) {
    if obj_kind(arr) != Some(KIND_ARR) {
        return;
    }
    let n = usize::try_from(obj_len(arr)).unwrap_or(0);
    if n >= MAX_ARR {
        return;
    }
    let slots = payload_words(arr);
    unsafe {
        slots.add(n).write(value.addr());
        // bump len in header
        arr.cast::<usize>()
            .add(1)
            .write(hdr_kind_len(KIND_ARR, u32::try_from(n.saturating_add(1)).unwrap_or(0)));
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFArrayCreateMutable(
    _alloc: *mut c_void,
    _cap: isize,
    _cbs: *const c_void,
) -> *mut c_void {
    let bytes = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(MAX_ARR.saturating_mul(core::mem::size_of::<usize>()));
    let p = alloc_raw(bytes);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_ARR, 0);
    p
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFDataCreate(
    _alloc: *mut c_void,
    bytes: *const u8,
    len: isize,
) -> *mut c_void {
    if bytes.is_null() || len <= 0 {
        // Empty CFData still used as a tag by some callers.
        let p = alloc_raw(HDR_WORDS.saturating_mul(core::mem::size_of::<usize>()));
        if p.is_null() {
            return core::ptr::null_mut();
        }
        obj_write_hdr(p, KIND_DATA, 0);
        return p;
    }
    let n = usize::try_from(len).unwrap_or(0);
    let bytes_total = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(n);
    let p = alloc_raw(bytes_total);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_DATA, u32::try_from(n).unwrap_or(0));
    unsafe {
        core::ptr::copy_nonoverlapping(bytes, payload_bytes(p), n);
    }
    p
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFErrorCopyDescription(_err: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFErrorGetCode(_err: *mut c_void) -> isize {
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFRelease(cf: *mut c_void) {
    if is_obj(cf) {
        unsafe {
            free(cf);
        }
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringCreateWithCString(
    _alloc: *mut c_void,
    c_str: *const c_char,
    _encoding: u32,
) -> *mut c_void {
    if c_str.is_null() {
        let p = alloc_raw(HDR_WORDS.saturating_mul(core::mem::size_of::<usize>()).saturating_add(1));
        if p.is_null() {
            return core::ptr::null_mut();
        }
        obj_write_hdr(p, KIND_STR, 0);
        unsafe {
            payload_bytes(p).write(0);
        }
        return p;
    }
    // strlen
    let mut n = 0_usize;
    while unsafe { c_str.add(n).read() } != 0 {
        n = n.saturating_add(1);
        if n > 1024 {
            break;
        }
    }
    let bytes_total = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(n)
        .saturating_add(1);
    let p = alloc_raw(bytes_total);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_STR, u32::try_from(n).unwrap_or(0));
    unsafe {
        core::ptr::copy_nonoverlapping(c_str.cast::<u8>(), payload_bytes(p), n);
        payload_bytes(p).add(n).write(0);
    }
    p
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringGetCString(
    s: *mut c_void,
    buf: *mut c_char,
    buf_size: isize,
    _encoding: u32,
) -> u8 {
    if s.is_null() || buf.is_null() || buf_size <= 0 {
        return 0;
    }
    let max = usize::try_from(buf_size).unwrap_or(0).saturating_sub(1);
    if obj_kind(s) == Some(KIND_STR) {
        let n = usize::try_from(obj_len(s)).unwrap_or(0);
        let copy = n.min(max);
        unsafe {
            core::ptr::copy_nonoverlapping(payload_bytes(s), buf.cast::<u8>(), copy);
            buf.add(copy).write(0);
        }
        return 1;
    }
    unsafe {
        buf.write(0);
    }
    1
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringGetLength(s: *mut c_void) -> isize {
    if obj_kind(s) == Some(KIND_STR) {
        isize::try_from(obj_len(s)).unwrap_or(0)
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringGetMaximumSizeForEncoding(
    len: isize,
    _encoding: u32,
) -> isize {
    len.saturating_mul(4).saturating_add(1)
}

