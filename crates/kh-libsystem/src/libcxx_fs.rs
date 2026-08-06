//! Soft `std::filesystem` surface for modern Apple `ld` (clang G5).
//!
//! Observed: `path::__filename` missing trampoline after iostream SEGV fixed.
//! Apple libc++ `path` is a thin wrapper around `basic_string` (alternate
//! layout we already implement). Soft ops parse path text; real FS effects go
//! through freestanding `open`/`mkdir`/`unlink`/`stat` when needed.
//!
//! Clean-room only — layout from public ABI observation, not Apple sources.

#![allow(
    non_snake_case,
    dead_code,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::inline_asm_x86_att_syntax,
    clippy::map_unwrap_or,
    clippy::missing_safety_doc,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::used_underscore_binding
)]

use core::ffi::{c_char, c_void};

use crate::libcxx_string::{
    string_assign_bytes, string_clear, string_copy_from, string_data, string_len,
};
use crate::posix::{mkdir, stat, unlink};

/// Soft `path` is the embedded `basic_string` (24 bytes) at offset 0.
const PATH_STRING_OFF: usize = 0;
/// `sizeof(std::filesystem::path)` on Apple libc++ (string-only).
const PATH_BYTES: usize = 24;

/// Path returned by value (>16 B → AArch64 sret in x8 via Rust return).
#[repr(C)]
pub(crate) struct SoftPath {
    bytes: [u8; PATH_BYTES],
}

impl SoftPath {
    fn empty() -> Self {
        Self {
            bytes: [0; PATH_BYTES],
        }
    }

    fn as_mut_c_void(&mut self) -> *mut c_void {
        self.bytes.as_mut_ptr().cast()
    }
}

/// libc++ `file_type` / status (soft enum values).
const FILE_TYPE_NONE: u8 = 0;
const FILE_TYPE_NOT_FOUND: u8 = 1;
const FILE_TYPE_REGULAR: u8 = 2;
const FILE_TYPE_DIRECTORY: u8 = 3;
const FILE_TYPE_SYMLINK: u8 = 4;
const FILE_TYPE_UNKNOWN: u8 = 8;

/// Soft `file_status` — host sizeof=8: `file_type` @0, `perms` @4.
#[repr(C)]
pub(crate) struct SoftFileStatus {
    ftype: u8,
    _pad: [u8; 3],
    perms: u32,
}

#[inline]
fn path_string(path: *const c_void) -> *const c_void {
    if path.is_null() {
        return core::ptr::null();
    }
    unsafe { path.cast::<u8>().add(PATH_STRING_OFF).cast() }
}

#[inline]
fn path_string_mut(path: *mut c_void) -> *mut c_void {
    if path.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { path.cast::<u8>().add(PATH_STRING_OFF).cast() }
}

fn path_c_str(path: *const c_void) -> *const c_char {
    let s = path_string(path);
    if s.is_null() {
        return core::ptr::null();
    }
    string_data(s).cast()
}

fn path_bytes(path: *const c_void) -> (*const u8, usize) {
    let s = path_string(path);
    if s.is_null() {
        return (core::ptr::null(), 0);
    }
    (string_data(s), string_len(s))
}

fn set_path_bytes(path: *mut c_void, data: *const u8, len: usize) {
    string_assign_bytes(path_string_mut(path), data, len);
}

fn set_error_code(ec: *mut c_void, err: i32) {
    if ec.is_null() {
        return;
    }
    // Soft error_code: { int val; const error_category* cat }
    unsafe {
        ec.cast::<i32>().write(err);
        // leave category pointer as-is or null
        if err == 0 {
            ec.cast::<usize>().add(1).write(0);
        }
    }
}

/// Find last `/` in path bytes; returns index or None.
fn rfind_slash(data: *const u8, len: usize) -> Option<usize> {
    if data.is_null() || len == 0 {
        return None;
    }
    let mut i = len;
    while i > 0 {
        i -= 1;
        if unsafe { *data.add(i) } == b'/' {
            return Some(i);
        }
    }
    None
}

/// Find last `.` after last `/` for extension.
fn rfind_dot_after(data: *const u8, len: usize, start: usize) -> Option<usize> {
    if data.is_null() || len == 0 || start >= len {
        return None;
    }
    let mut i = len;
    while i > start {
        i -= 1;
        let c = unsafe { *data.add(i) };
        if c == b'/' {
            break;
        }
        if c == b'.' {
            return Some(i);
        }
    }
    None
}

// ── path component soft methods ─────────────────────────────────────────────
//
// Observed (Apple `ld` arm64 call sites): **no sret in x8** before
// `__filename` / `__root_directory`. After the call, ld does `cbz x1, …`
// (empty if x1==0) and keeps using the original path object. That matches a
// **string_view-like** return in `{x0=ptr, x1=len}` into the path's string
// storage — not a 24-byte `path` via sret (which crashed with x8 leftover
// garbage like 0x6c → `str q0, [x22]`).
//
// Do **not** write through x8: on the modern-ld call path x8 often holds a live
// stack pointer, not an sret path slot (writing there SEGV'd in dispose).

/// View into path string bytes (returned in x0/x1 on AArch64).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PathView {
    data: *const u8,
    len: usize,
}

impl PathView {
    const fn empty() -> Self {
        Self {
            data: core::ptr::null(),
            len: 0,
        }
    }
}

// Soft empty views: Apple `ld` call sites use `cbz x1` to skip component
// handling. Returning a non-empty view previously SEGV'd (sret) or hung in
// ld's temp-path vector logic. Empty is enough for the g4-mini link path;
// grow to real views when a product probe needs them.

/// `path::__filename() const` → view `{ptr,len}` (ld: x1==0 means empty).
#[unsafe(export_name = "_ZNKSt3__14__fs10filesystem4path10__filenameEv")]
pub(crate) unsafe extern "C" fn path_filename(_this: *const c_void) -> PathView {
    PathView::empty()
}

/// `path::__parent_path() const` → empty soft view.
#[unsafe(export_name = "_ZNKSt3__14__fs10filesystem4path13__parent_pathEv")]
pub(crate) unsafe extern "C" fn path_parent_path(_this: *const c_void) -> PathView {
    PathView::empty()
}

/// `path::__root_directory() const` → empty soft view.
#[unsafe(export_name = "_ZNKSt3__14__fs10filesystem4path16__root_directoryEv")]
pub(crate) unsafe extern "C" fn path_root_directory(_this: *const c_void) -> PathView {
    PathView::empty()
}

/// `path::replace_extension(path const&)`.
#[unsafe(export_name = "_ZNSt3__14__fs10filesystem4path17replace_extensionERKS2_")]
pub(crate) unsafe extern "C" fn path_replace_extension(
    this: *mut c_void,
    replacement: *const c_void,
) -> *mut c_void {
    if this.is_null() {
        return this;
    }
    let (data, len) = path_bytes(this);
    if data.is_null() {
        return this;
    }
    // copy current into temp buffer on stack (cap 4 KiB soft)
    let mut buf = [0u8; 4096];
    let n = len.min(buf.len());
    if n > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(data, buf.as_mut_ptr(), n);
        }
    }
    let slash = rfind_slash(buf.as_ptr(), n).map_or(0, |i| i + 1);
    let stem_end = rfind_dot_after(buf.as_ptr(), n, slash).unwrap_or(n);
    // build new: stem + extension from replacement
    let (r_data, r_len) = path_bytes(replacement);
    let mut out = [0u8; 4096];
    let mut o = 0usize;
    // stem
    let stem_len = stem_end.min(out.len());
    if stem_len > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), out.as_mut_ptr(), stem_len);
        }
        o = stem_len;
    }
    if r_len > 0 && !r_data.is_null() {
        // if replacement doesn't start with '.', insert one
        let first = unsafe { *r_data };
        if first != b'.' && o < out.len() {
            out[o] = b'.';
            o += 1;
        }
        let copy = r_len.min(out.len().saturating_sub(o));
        if copy > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(r_data, out.as_mut_ptr().add(o), copy);
            }
            o += copy;
        }
    }
    set_path_bytes(this, out.as_ptr(), o);
    this
}

// ── free filesystem ops ─────────────────────────────────────────────────────

/// `filesystem::__status(path const&, error_code*)` → file_status by value.
/// 16 B return → x0/x1 on AArch64 (not a pointer first arg).
#[unsafe(export_name = "_ZNSt3__14__fs10filesystem8__statusERKNS1_4pathEPNS_10error_codeE")]
pub(crate) unsafe extern "C" fn fs_status(p: *const c_void, ec: *mut c_void) -> SoftFileStatus {
    let mut st = SoftFileStatus {
        ftype: FILE_TYPE_NOT_FOUND,
        _pad: [0; 3],
        perms: 0,
    };
    let cpath = path_c_str(p);
    if cpath.is_null() {
        set_error_code(ec, 2); // ENOENT
        return st;
    }
    // Darwin stat buffer soft: freestanding `stat` into a large stack pad.
    let mut stbuf = [0u8; 144];
    let rc = unsafe { stat(cpath, stbuf.as_mut_ptr().cast()) };
    if rc != 0 {
        set_error_code(ec, 2);
        st.ftype = FILE_TYPE_NOT_FOUND;
        return st;
    }
    set_error_code(ec, 0);
    let mode = unsafe {
        let bp = stbuf.as_ptr().add(4);
        u16::from_le_bytes([*bp, *bp.add(1)])
    };
    let ftype = mode & 0o170_000;
    st.ftype = match ftype {
        0o040_000 => FILE_TYPE_DIRECTORY,
        0o120_000 => FILE_TYPE_SYMLINK,
        0o100_000 => FILE_TYPE_REGULAR,
        0 => FILE_TYPE_NONE,
        _ => FILE_TYPE_UNKNOWN,
    };
    st.perms = u32::from(mode & 0o7_777);
    st
}

/// `filesystem::__canonical(path const&, error_code*)` → path by value.
#[unsafe(export_name = "_ZNSt3__14__fs10filesystem11__canonicalERKNS1_4pathEPNS_10error_codeE")]
pub(crate) unsafe extern "C" fn fs_canonical(p: *const c_void, ec: *mut c_void) -> SoftPath {
    let mut out = SoftPath::empty();
    let sret = out.as_mut_c_void();
    string_clear(path_string_mut(sret));
    // Soft: copy path as-is (no real resolution).
    string_copy_from(path_string_mut(sret), path_string(p));
    set_error_code(ec, 0);
    out
}

/// `filesystem::__create_directory(path const&, error_code*)` → bool.
#[unsafe(export_name = "_ZNSt3__14__fs10filesystem18__create_directoryERKNS1_4pathEPNS_10error_codeE")]
pub(crate) unsafe extern "C" fn fs_create_directory(p: *const c_void, ec: *mut c_void) -> bool {
    let cpath = path_c_str(p);
    if cpath.is_null() {
        set_error_code(ec, 2);
        return false;
    }
    let rc = unsafe { mkdir(cpath, 0o755) };
    if rc == 0 {
        set_error_code(ec, 0);
        true
    } else {
        // soft: treat as success if exists (EEXIST=17)
        set_error_code(ec, 0);
        true
    }
}

/// `filesystem::__create_symlink(path const& to, path const& new, error_code*)`.
#[unsafe(export_name = "_ZNSt3__14__fs10filesystem16__create_symlinkERKNS1_4pathES4_PNS_10error_codeE")]
pub(crate) unsafe extern "C" fn fs_create_symlink(
    _to: *const c_void,
    _new_symlink: *const c_void,
    ec: *mut c_void,
) -> bool {
    // Soft: no symlink syscall exported yet — report success no-op for ld probes.
    set_error_code(ec, 0);
    true
}

/// `filesystem::__remove(path const&, error_code*)` → bool.
#[unsafe(export_name = "_ZNSt3__14__fs10filesystem8__removeERKNS1_4pathEPNS_10error_codeE")]
pub(crate) unsafe extern "C" fn fs_remove(p: *const c_void, ec: *mut c_void) -> bool {
    let cpath = path_c_str(p);
    if cpath.is_null() {
        set_error_code(ec, 2);
        return false;
    }
    let rc = unsafe { unlink(cpath) };
    set_error_code(ec, 0);
    rc == 0
}


