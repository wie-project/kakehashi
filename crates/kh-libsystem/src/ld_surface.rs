//! Soft surface for Apple `ld-classic` / linker path (clang G4).
//!
//! The modern `ld` pulls Foundation/ObjC; we steer G4 at `ld-classic`, which
//! still needs Blocks, GCD soft, libxar soft, CoreAnalytics soft, uuid, etc.
//! Bodies are clean-room; no Apple code.

// Scaffolding: soft stubs + digit/path loops; same allowances as extra_stubs.
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
use core::sync::atomic::{AtomicI32, Ordering};

use crate::errno;
use crate::heap::malloc;
use crate::stdio::{memcpy, strlen};

const EINVAL: i32 = 22;

/// Block invoke for `dispatch_apply` (block, index).
type DispatchApplyFn = Option<unsafe extern "C" fn(*mut c_void, usize)>;

// ── Blocks runtime (soft) ───────────────────────────────────────────────────

/// Data isa for global blocks (`_NSConcreteGlobalBlock`).
#[unsafe(no_mangle)]
#[used]
pub(crate) static mut _NSConcreteGlobalBlock: [usize; 4] = [0; 4];

/// Data isa for stack blocks (`_NSConcreteStackBlock`).
#[unsafe(no_mangle)]
#[used]
pub(crate) static mut _NSConcreteStackBlock: [usize; 4] = [0; 4];

/// `_Block_copy` — soft: return the same pointer (no heap promote).
#[unsafe(export_name = "_Block_copy")]
pub(crate) unsafe extern "C" fn block_copy(a_block: *const c_void) -> *mut c_void {
    a_block.cast_mut()
}

/// `_Block_release` — soft no-op.
#[unsafe(export_name = "_Block_release")]
pub(crate) unsafe extern "C" fn block_release(_a_block: *const c_void) {}

/// `_Block_object_assign` — soft no-op.
#[unsafe(export_name = "_Block_object_assign")]
pub(crate) unsafe extern "C" fn block_object_assign(
    _dest: *mut c_void,
    _object: *const c_void,
    _flags: c_int,
) {
}

/// `_Block_object_dispose` — soft no-op.
#[unsafe(export_name = "_Block_object_dispose")]
pub(crate) unsafe extern "C" fn block_object_dispose(_object: *const c_void, _flags: c_int) {}

// ── GCD soft (run blocks on the calling thread) ─────────────────────────────

type DispatchFn = Option<unsafe extern "C" fn(*mut c_void)>;

/// Opaque queue / group tokens (non-null unique soft pointers).
static DISPATCH_MAIN_Q: AtomicI32 = AtomicI32::new(1);
static DISPATCH_GROUP_TOKEN: AtomicI32 = AtomicI32::new(1);

#[inline]
fn soft_token(counter: &AtomicI32) -> *mut c_void {
    let n = counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    // Non-null fake pointer in PAGEZERO-ish high half of low 32-bit? Prefer
    // high bit set so ptr_usable checks that need PAGEZERO still pass if used.
    ((0x1_0000_0000_usize).wrapping_add(n as usize)) as *mut c_void
}

/// `dispatch_get_global_queue` → soft queue token.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_get_global_queue(
    _identifier: isize,
    _flags: usize,
) -> *mut c_void {
    soft_token(&DISPATCH_MAIN_Q)
}

/// `dispatch_queue_create` → soft queue token.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_queue_create(
    _label: *const c_char,
    _attr: *const c_void,
) -> *mut c_void {
    soft_token(&DISPATCH_MAIN_Q)
}

/// `dispatch_release` — soft no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_release(_object: *mut c_void) {}

/// `dispatch_sync` — run block immediately.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_sync(queue: *mut c_void, block: *mut c_void) {
    let _ = queue;
    // Block layout: invoke function pointer at +16 on Darwin arm64 ABI-ish;
    // we only support direct function pointers passed as the block body via
    // clang's block literal: call through a known soft path.
    // Prefer treating `block` as a function pointer taking no args (common
    // for pure C blocks after invoke slot). If null, no-op.
    if block.is_null() {
        return;
    }
    // SAFETY: soft — guest block invoke. Clang block layout: `invoke` at +16.
    unsafe {
        let invoke = block_invoke_ptr(block);
        if !invoke.is_null() {
            let f: DispatchFn = core::mem::transmute(invoke);
            if let Some(func) = f {
                func(block);
            }
        }
    }
}

/// Read the `invoke` function pointer from a Darwin block object (+16).
#[inline]
unsafe fn block_invoke_ptr(block: *mut c_void) -> *mut c_void {
    // SAFETY: soft layout; unaligned-safe read of pointer-sized field.
    unsafe {
        let slot = block.cast::<u8>().add(16);
        let mut raw = [0_u8; 8];
        core::ptr::copy_nonoverlapping(slot, raw.as_mut_ptr(), 8);
        usize::from_ne_bytes(raw) as *mut c_void
    }
}

/// `dispatch_once` — classic once flag.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_once(predicate: *mut isize, block: *mut c_void) {
    if predicate.is_null() {
        return;
    }
    // SAFETY: guest once flag.
    let done = unsafe { predicate.read() };
    if done != 0 {
        return;
    }
    unsafe {
        dispatch_sync(core::ptr::null_mut(), block);
        predicate.write(!0);
    }
}

/// `dispatch_group_create` → soft group token.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_group_create() -> *mut c_void {
    soft_token(&DISPATCH_GROUP_TOKEN)
}

/// `dispatch_group_async` — run block immediately (soft).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_group_async(
    group: *mut c_void,
    queue: *mut c_void,
    block: *mut c_void,
) {
    let _ = group;
    unsafe {
        dispatch_sync(queue, block);
    }
}

/// `dispatch_group_wait` → 0 (done).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_group_wait(group: *mut c_void, _timeout: u64) -> isize {
    let _ = group;
    0
}

/// `dispatch_apply` — run serially `iterations` times.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_apply(
    iterations: usize,
    queue: *mut c_void,
    block: *mut c_void,
) {
    let _ = queue;
    if block.is_null() {
        return;
    }
    // Block invoke for apply takes (block, index).
    unsafe {
        let invoke = block_invoke_ptr(block);
        if invoke.is_null() {
            return;
        }
        let f: DispatchApplyFn = core::mem::transmute(invoke);
        if let Some(func) = f {
            let mut idx = 0_usize;
            while idx < iterations {
                func(block, idx);
                idx = idx.saturating_add(1);
            }
        }
    }
}

// ── CoreAnalytics soft ──────────────────────────────────────────────────────

/// `_analytics_send_event_lazy` → soft success.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn analytics_send_event_lazy(
    _name: *const c_char,
    _block: *mut c_void,
) -> c_int {
    0
}

// ── libxar soft (bitcode / static archive paths; plain .o link may skip) ────

macro_rules! soft_null {
    ($name:ident $(, $arg:ident : $ty:ty)*) => {
        #[unsafe(no_mangle)]
        pub(crate) unsafe extern "C" fn $name($($arg : $ty),*) -> *mut c_void {
            $(let _ = $arg;)*
            core::ptr::null_mut()
        }
    };
}

macro_rules! soft_int {
    ($name:ident $(, $arg:ident : $ty:ty)* => $ret:expr) => {
        #[unsafe(no_mangle)]
        pub(crate) unsafe extern "C" fn $name($($arg : $ty),*) -> c_int {
            $(let _ = $arg;)*
            $ret
        }
    };
}

soft_null!(xar_open, _path: *const c_char, _flags: c_int);
soft_int!(xar_close, _x: *mut c_void => 0);
soft_null!(xar_iter_new);
soft_int!(xar_iter_free, _i: *mut c_void => 0);
soft_null!(xar_file_first, _x: *mut c_void, _i: *mut c_void);
soft_null!(xar_file_next, _x: *mut c_void, _i: *mut c_void);
soft_null!(xar_prop_first, _f: *mut c_void, _i: *mut c_void);
soft_null!(xar_prop_next, _f: *mut c_void, _i: *mut c_void);
soft_int!(xar_prop_get, _f: *mut c_void, _k: *const c_char, _v: *mut *const c_char => -1);
soft_int!(xar_prop_set, _f: *mut c_void, _k: *const c_char, _v: *const c_char => -1);
soft_int!(xar_prop_unset, _f: *mut c_void, _k: *const c_char => -1);
soft_null!(xar_prop_create, _f: *mut c_void, _k: *const c_char);
soft_int!(xar_opt_set, _x: *mut c_void, _opt: *const c_char, _val: *const c_char => 0);
soft_int!(
    xar_add_frombuffer,
    _x: *mut c_void,
    _parent: *mut c_void,
    _name: *const c_char,
    _buf: *mut c_void,
    _len: usize
    => -1
);
soft_int!(
    xar_extract_tobuffersz,
    _x: *mut c_void,
    _f: *mut c_void,
    _buf: *mut *mut c_void,
    _size: *mut usize
    => -1
);
soft_null!(xar_subdoc_first, _x: *mut c_void);
soft_null!(xar_subdoc_next, _s: *mut c_void);
soft_null!(xar_subdoc_new, _x: *mut c_void, _name: *const c_char);

/// `xar_subdoc_name` → null.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xar_subdoc_name(_s: *mut c_void) -> *const c_char {
    core::ptr::null()
}

// ── XPC soft ────────────────────────────────────────────────────────────────

soft_null!(xpc_dictionary_create, _k: *const *const c_char, _v: *const *mut c_void, _c: usize);

/// `xpc_dictionary_set_bool` — soft no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xpc_dictionary_set_bool(
    _xdict: *mut c_void,
    _key: *const c_char,
    _value: u8,
) {
}

/// `xpc_dictionary_set_int64` — soft no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xpc_dictionary_set_int64(
    _xdict: *mut c_void,
    _key: *const c_char,
    _value: i64,
) {
}

/// `xpc_dictionary_set_string` — soft no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn xpc_dictionary_set_string(
    _xdict: *mut c_void,
    _key: *const c_char,
    _value: *const c_char,
) {
}

// ── os_unfair_lock soft ─────────────────────────────────────────────────────

/// `__os_lock_type_unfair` data (opaque lock type table).
#[unsafe(no_mangle)]
#[used]
pub(crate) static mut _os_lock_type_unfair: [usize; 4] = [0; 4];

/// `os_lock_lock` — soft no-op (single-threaded linker path).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_lock_lock(_lock: *mut c_void) {}

/// `os_lock_unlock` — soft no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_lock_unlock(_lock: *mut c_void) {}

// ── uuid soft ───────────────────────────────────────────────────────────────

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

// ── string / path extras ────────────────────────────────────────────────────

/// C `strlcat`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strlcat(
    dst: *mut c_char,
    src: *const c_char,
    size: usize,
) -> usize {
    if dst.is_null() || src.is_null() {
        return 0;
    }
    let dlen = if size == 0 {
        0
    } else {
        // Find current length limited by size-1.
        let mut n = 0_usize;
        unsafe {
            while n + 1 < size && dst.add(n).read() != 0 {
                n = n.saturating_add(1);
            }
        }
        n
    };
    let slen = unsafe { strlen(src) };
    if size == 0 {
        return slen.saturating_add(dlen);
    }
    let room = size.saturating_sub(dlen).saturating_sub(1);
    let mut i = 0_usize;
    unsafe {
        while i < room && src.add(i).read() != 0 {
            dst.add(dlen + i).write(src.add(i).read());
            i = i.saturating_add(1);
        }
        if dlen < size {
            dst.add(dlen + i).write(0);
        }
    }
    dlen.saturating_add(slen)
}

/// C `strndup`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strndup(s: *const c_char, n: usize) -> *mut c_char {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let len = unsafe { strlen(s) }.min(n);
    let p = unsafe { malloc(len.saturating_add(1)).cast::<c_char>() };
    if p.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let _ = memcpy(p.cast(), s.cast(), len);
        p.add(len).write(0);
    }
    p
}

/// C `strtok` — classic static delimiter walk (not thread-safe).
///
/// # Safety (caller)
/// Same contract as libc: `s` (or the prior continuation) is a live mutable
/// NUL-terminated C string for the whole tokenize sequence; `delim` is a live
/// NUL-terminated delimiter set. This implementation never forms Rust `&T` /
/// `&mut T` over that buffer — only raw `read`/`write` after address checks.
///
/// Defensive guest guards (beyond libc): reject null and Darwin PAGEZERO
/// addresses, and hard-cap the walk so a missing terminator cannot run forever.
static mut STRTOK_SAVE: *mut c_char = core::ptr::null_mut();

/// Max bytes walked in one `strtok` call (same order as freestanding `strlen`).
const STRTOK_WALK_MAX: usize = 1 << 20;

/// Live guest C-string pointer: non-null and outside Darwin PAGEZERO.
///
/// Same barrier shape as `curl::easy_from` (explicit `is_null` + PAGEZERO) so
/// CodeQL `rust/access-invalid-pointer` sees a NotNullCheckBarrier at each use.
#[inline]
fn strtok_addr_ok(p: *const c_char) -> bool {
    !p.is_null() && p.addr() >= crate::stdio::PAGEZERO_END
}

/// Load one byte from a guest C-string address without forming a Rust reference.
///
/// Uses `copy_nonoverlapping` into a stack local (not `as_ref` / `*p`) so we never
/// create `&T` over an untrusted C buffer, and the null/PAGEZERO checks sit in
/// the same function as the access (CodeQL barrier).
///
/// # Safety
/// After the address checks pass, `p` must point into a live allocation for at
/// least one `c_char` (libc `strtok` NUL-terminated buffer contract).
#[inline]
unsafe fn strtok_load(p: *const c_char) -> Option<c_char> {
    // NotNullCheckBarrier: keep both checks inline (do not fold through a helper
    // alone at the deref site — CodeQL does not always track that).
    if p.is_null() || p.addr() < crate::stdio::PAGEZERO_END {
        return None;
    }
    let mut b: c_char = 0;
    // SAFETY: null + PAGEZERO rejected; one-byte copy from caller's live C string.
    unsafe {
        core::ptr::copy_nonoverlapping(p, core::ptr::addr_of_mut!(b), 1);
    }
    Some(b)
}

/// Store one byte at a guest C-string address without forming a Rust reference.
///
/// # Safety
/// Same as [`strtok_load`], plus the location must be mutable.
#[inline]
unsafe fn strtok_store(p: *mut c_char, v: c_char) -> bool {
    if p.is_null() || p.addr() < crate::stdio::PAGEZERO_END {
        return false;
    }
    let b = v;
    // SAFETY: null + PAGEZERO rejected; one-byte copy into caller's live buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(core::ptr::addr_of!(b), p, 1);
    }
    true
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strtok(s: *mut c_char, delim: *const c_char) -> *mut c_char {
    if !strtok_addr_ok(delim) {
        return core::ptr::null_mut();
    }

    let mut p = if s.is_null() {
        // SAFETY: prior continuation; re-validated before any load/store.
        unsafe { STRTOK_SAVE }
    } else {
        s
    };
    if !strtok_addr_ok(p) {
        unsafe {
            STRTOK_SAVE = core::ptr::null_mut();
        }
        return core::ptr::null_mut();
    }

    // SAFETY: `p`/`delim` address-ok; each step re-validates before load/store.
    // Advances only after a successful non-NUL load so `STRTOK_SAVE` never
    // steps from an unobserved address (no OOB continuation invent).
    unsafe {
        let mut walked = 0_usize;

        // Skip leading delimiters.
        loop {
            if walked > STRTOK_WALK_MAX {
                STRTOK_SAVE = core::ptr::null_mut();
                return core::ptr::null_mut();
            }
            let Some(c) = strtok_load(p) else {
                STRTOK_SAVE = core::ptr::null_mut();
                return core::ptr::null_mut();
            };
            if c == 0 {
                STRTOK_SAVE = core::ptr::null_mut();
                return core::ptr::null_mut();
            }
            if !is_delim(c, delim) {
                break;
            }
            // Observed a live non-NUL byte at `p` → one-byte step stays on the
            // object while the string remains NUL-terminated (libc contract).
            p = p.add(1);
            walked = walked.saturating_add(1);
        }

        let start = p;
        loop {
            if walked > STRTOK_WALK_MAX {
                // Missing terminator: return what we have; do not invent a save.
                STRTOK_SAVE = core::ptr::null_mut();
                return start;
            }
            let Some(c) = strtok_load(p) else {
                STRTOK_SAVE = core::ptr::null_mut();
                return start;
            };
            if c == 0 {
                STRTOK_SAVE = core::ptr::null_mut();
                return start;
            }
            if is_delim(c, delim) {
                // Classic strtok: splice token with in-place NUL at delimiter.
                if !strtok_store(p, 0) {
                    STRTOK_SAVE = core::ptr::null_mut();
                    return start;
                }
                // Continuation is the byte after the delimiter we just wrote.
                // That address is only retained if it itself passes addr checks
                // (rejects PAGEZERO/null); next call loads it or clears.
                let next = p.add(1);
                STRTOK_SAVE = if strtok_addr_ok(next) {
                    next
                } else {
                    core::ptr::null_mut()
                };
                return start;
            }
            p = p.add(1);
            walked = walked.saturating_add(1);
        }
    }
}

unsafe fn is_delim(c: c_char, delim: *const c_char) -> bool {
    if !strtok_addr_ok(delim) {
        return false;
    }
    let mut d = delim;
    let mut n = 0_usize;
    // SAFETY: `delim` address-ok; each byte re-checked; hard cap on set length.
    unsafe {
        loop {
            if n > 256 {
                return false;
            }
            let Some(x) = strtok_load(d) else {
                return false;
            };
            if x == 0 {
                return false;
            }
            if x == c {
                return true;
            }
            d = d.add(1);
            n = n.saturating_add(1);
        }
    }
}

/// C `strtoull`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strtoull(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> u64 {
    if nptr.is_null() {
        return 0;
    }
    let mut p = nptr;
    let mut acc = 0_u64;
    let mut base_u = base;
    unsafe {
        // skip spaces
        while matches!(p.read().cast_unsigned(), b' ' | b'\t' | b'\n' | b'\r') {
            p = p.add(1);
        }
        let mut neg = false;
        let c0 = p.read().cast_unsigned();
        if c0 == b'+' || c0 == b'-' {
            neg = c0 == b'-';
            p = p.add(1);
        }
        if base_u == 0 {
            if p.read().cast_unsigned() == b'0' {
                let n = p.add(1).read().cast_unsigned();
                if n == b'x' || n == b'X' {
                    base_u = 16;
                    p = p.add(2);
                } else {
                    base_u = 8;
                }
            } else {
                base_u = 10;
            }
        } else if base_u == 16
            && p.read().cast_unsigned() == b'0'
            && matches!(p.add(1).read().cast_unsigned(), b'x' | b'X')
        {
            p = p.add(2);
        }
        if !(2..=36).contains(&base_u) {
            if !endptr.is_null() {
                endptr.write(nptr.cast_mut());
            }
            return 0;
        }
        let b = base_u as u64;
        loop {
            let c = p.read().cast_unsigned();
            let digit = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'z' => c - b'a' + 10,
                b'A'..=b'Z' => c - b'A' + 10,
                _ => break,
            };
            if c_int::from(digit) >= base_u {
                break;
            }
            acc = acc.saturating_mul(b).saturating_add(u64::from(digit));
            p = p.add(1);
        }
        if !endptr.is_null() {
            endptr.write(p.cast_mut());
        }
        if neg {
            acc = 0u64.wrapping_sub(acc);
        }
    }
    acc
}

/// C `dirname` — mutates path (POSIX).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dirname(path: *mut c_char) -> *mut c_char {
    static mut DOT: [c_char; 2] = [b'.'.cast_signed(), 0];
    if path.is_null() {
        return core::ptr::addr_of_mut!(DOT).cast();
    }
    unsafe {
        let len = strlen(path);
        if len == 0 {
            return core::ptr::addr_of_mut!(DOT).cast();
        }
        // strip trailing slashes
        let mut end = len;
        while end > 1 && path.add(end - 1).read().cast_unsigned() == b'/' {
            end = end.saturating_sub(1);
        }
        // find last slash
        let mut slash_at = end;
        while slash_at > 0 {
            if path.add(slash_at - 1).read().cast_unsigned() == b'/' {
                break;
            }
            slash_at = slash_at.saturating_sub(1);
        }
        if slash_at == 0 {
            // no slash
            DOT[0] = b'.'.cast_signed();
            DOT[1] = 0;
            return core::ptr::addr_of_mut!(DOT).cast();
        }
        // keep root "/"
        let mut keep = slash_at;
        while keep > 1 && path.add(keep - 1).read().cast_unsigned() == b'/' {
            keep = keep.saturating_sub(1);
        }
        path.add(keep).write(0);
        path
    }
}

// ── misc ────────────────────────────────────────────────────────────────────

/// C `sleep` → nlist `_sleep` (seconds).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sleep(seconds: u32) -> u32 {
    // nanosleep soft via usleep loop if available.
    let mut left = seconds;
    while left > 0 {
        // usleep max ~1s chunks
        let _ = unsafe { crate::posix::usleep(1_000_000) };
        left = left.saturating_sub(1);
    }
    0
}

/// C `truncate`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn truncate(path: *const c_char, length: i64) -> c_int {
    // open + ftruncate soft path: use open then ftruncate if we have them.
    if path.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let _ = length;
    // Soft success for linker temp-file sizing; real truncate not required for G4.
    0
}

/// `mkdtemp` — fill trailing `XXXXXX`, create the directory (0700), return path.
///
/// Observed: modern `ld` `-lto_library` uses `/tmp/ld-support-XXXXXX` then
/// joins `libLTO.dylib`. The old soft path only rewrote X's and **never
/// mkdir'd**, so later path joins saw a non-directory and wedged on
/// access/stat of glued names like `/tmpld-support-…libLTO.dylib`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mkdtemp(template: *mut c_char) -> *mut c_char {
    if template.is_null() {
        return core::ptr::null_mut();
    }
    let len = unsafe { strlen(template) };
    if len < 6 {
        errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    let xs = unsafe { template.add(len.saturating_sub(6)) };
    for i in 0..6 {
        if unsafe { xs.add(i).read() }.cast_unsigned() != b'X' {
            errno::set_errno(EINVAL);
            return core::ptr::null_mut();
        }
    }
    // Same alphabet / LCG shape as freestanding `mkstemp`.
    const ALPH: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut state = template.addr().wrapping_mul(0x9E37_79B9).wrapping_add(len);
    for _attempt in 0..256 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let mut s = state;
        for i in 0..6 {
            let idx = s % 62;
            let ch = ALPH.get(idx).copied().unwrap_or(b'0');
            unsafe {
                xs.add(i).write(ch.cast_signed());
            }
            s >>= 6;
        }
        // Darwin mkdir mode is often 0700 for mkdtemp.
        let rc = unsafe { crate::posix::mkdir(template, 0o700) };
        if rc == 0 {
            return template;
        }
        // Retry only on EEXIST.
        if errno::get_errno() != 17 {
            return core::ptr::null_mut();
        }
    }
    errno::set_errno(17); // EEXIST
    core::ptr::null_mut()
}

/// Darwin `mkpath_np` — create every path component (`mkdir -p` style).
///
/// Observed: modern `ld` `-lto_library` builds `/tmp/ld-support-<pid>/libLTO.dylib`
/// via `mkpath_np` then waits for the tree. Soft always-0 never created the
/// dir → infinite access/stat loop on a missing temp path.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mkpath_np(path: *const c_char, mode: u16) -> c_int {
    if path.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let len = unsafe { strlen(path) };
    if len == 0 || len >= 1024 {
        errno::set_errno(EINVAL);
        return -1;
    }
    // Copy to mutable buffer so we can insert NULs at each `/`.
    let mut buf = [0_u8; 1024];
    unsafe {
        core::ptr::copy_nonoverlapping(path.cast::<u8>(), buf.as_mut_ptr(), len);
    }
    buf[len] = 0;
    let mode_i = c_int::from(mode);
    // Walk components: for `/a/b/c` create `/a`, `/a/b`, `/a/b/c`.
    let mut i = 0_usize;
    // Skip leading slashes but keep absolute root.
    while i < len && buf[i] == b'/' {
        i = i.saturating_add(1);
    }
    while i < len {
        // Find next slash.
        let mut j = i;
        while j < len && buf[j] != b'/' {
            j = j.saturating_add(1);
        }
        // Temporarily terminate at j (or end).
        let saved = buf[j];
        buf[j] = 0;
        let cpath = buf.as_ptr().cast::<c_char>();
        let rc = unsafe { crate::posix::mkdir(cpath, mode_i) };
        let err = if rc != 0 {
            errno::get_errno()
        } else {
            0
        };
        buf[j] = saved;
        if rc != 0 && err != 17 {
            // EEXIST is fine; anything else fails the whole path.
            return -1;
        }
        // Skip slash run.
        i = j;
        while i < len && buf[i] == b'/' {
            i = i.saturating_add(1);
        }
    }
    0
}

/// `___tolower` (ASCII).
#[unsafe(export_name = "__tolower")]
pub(crate) unsafe extern "C" fn __tolower(c: c_int) -> c_int {
    let upper_a = c_int::from(b'A');
    let upper_z = c_int::from(b'Z');
    let lower_a = c_int::from(b'a');
    if (upper_a..=upper_z).contains(&c) {
        c.wrapping_sub(upper_a).wrapping_add(lower_a)
    } else {
        c
    }
}

/// `pthread_attr_setstacksize` soft success.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_attr_setstacksize(
    _attr: *mut c_void,
    _size: usize,
) -> c_int {
    0
}

/// Darwin BSD `qsort_r` (thunk **before** compar — not GNU order).
///
/// ```c
/// void qsort_r(void *base, size_t nel, size_t width, void *thunk,
///              int (*compar)(void *, const void *, const void *));
/// ```
///
/// Observed: Apple `ld-classic` `Parser<arm64>::sectionIndexSorter` (G4).
/// Wrong arg order called the thunk as a function → SEGV with PC on stack.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn qsort_r(
    base: *mut c_void,
    nel: usize,
    width: usize,
    thunk: *mut c_void,
    compar: Option<unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void) -> c_int>,
) {
    if base.is_null() || nel < 2 || width == 0 {
        return;
    }
    let Some(cmp) = compar else {
        return;
    };
    // Simple insertion sort with thunk.
    unsafe {
        let bytes = base.cast::<u8>();
        let mut outer = 1_usize;
        while outer < nel {
            let mut inner = outer;
            while inner > 0 {
                let left = bytes.add(inner.saturating_sub(1).saturating_mul(width));
                let right = bytes.add(inner.saturating_mul(width));
                if cmp(thunk, left.cast(), right.cast()) <= 0 {
                    break;
                }
                // swap width bytes
                let mut off = 0_usize;
                while off < width {
                    let tmp = left.add(off).read();
                    left.add(off).write(right.add(off).read());
                    right.add(off).write(tmp);
                    off = off.saturating_add(1);
                }
                inner = inner.saturating_sub(1);
            }
            outer = outer.saturating_add(1);
        }
    }
}

/// `vm_page_size` global.
#[unsafe(no_mangle)]
#[used]
pub(crate) static mut vm_page_size: usize = 16384;

/// `mach_host_self` → soft port 1.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mach_host_self() -> u32 {
    1
}

/// `host_statistics` — soft zero fill / success.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn host_statistics(
    _host: u32,
    _flavor: c_int,
    host_info_out: *mut c_int,
    host_info_out_cnt: *mut u32,
) -> c_int {
    if !host_info_out.is_null() && !host_info_out_cnt.is_null() {
        let n = unsafe { (*host_info_out_cnt) as usize };
        let mut i = 0_usize;
        while i < n {
            unsafe {
                host_info_out.add(i).write(0);
            }
            i = i.saturating_add(1);
        }
    }
    0
}

// ── CommonCrypto / corecrypto soft digests (ld-classic UUID) ───────────────
//
// Apple `ld-classic` `OutputFile::computeContentUUID`:
//   `di = ccsha256_di();` then sizes for stack ctx, then `ccdigest_*`.
// Inline `ccdigest_final` is `di->final(di, ctx, out)` — function pointer at
// `ccdigest_info` +0x38 (Itanium arm64). Soft: zero digest (UUID still written).
//
// Layout from public corecrypto `ccdigest.h` (not a paste of Apple sources):
//   output_size, state_size, block_size, oid_size, oid*, initial_state*,
//   compress*, final* [, impl, compress_parallel* on newer].

type CcCompressFn = unsafe extern "C" fn(*mut c_void, usize, *const c_void);
type CcFinalFn = unsafe extern "C" fn(*const c_void, *mut c_void, *mut u8);

/// `struct ccdigest_info` (arm64; matches corecrypto header field order).
/// Pointer fields stored as `usize` so the static is `Sync` (always null soft).
#[repr(C)]
struct CcDigestInfo {
    output_size: usize,
    state_size: usize,
    block_size: usize,
    oid_size: usize,
    oid: usize,
    initial_state: usize,
    compress: Option<CcCompressFn>,
    final_fn: Option<CcFinalFn>,
}

/// Soft compress: no-op (UUID path only needs final to fill the buffer).
unsafe extern "C" fn soft_compress(_state: *mut c_void, _nblocks: usize, _data: *const c_void) {}

/// Soft final: zero `output_size` bytes into `digest`.
///
/// Signature matches `di->final(di, ctx, digest)` (not the free `ccdigest_final`
/// wrapper symbol — ld often inlines to this pointer).
unsafe extern "C" fn soft_final(di: *const c_void, _ctx: *mut c_void, digest: *mut u8) {
    if di.is_null() || digest.is_null() {
        return;
    }
    // SAFETY: di is our static CcDigestInfo.
    let out_size = unsafe { di.cast::<CcDigestInfo>().read().output_size }.min(64);
    unsafe {
        core::ptr::write_bytes(digest, 0, out_size);
    }
}

// SAFETY: static digest-info tables; function pointers are immortal freestanding
// soft stubs. `oid` / `initial_state` unused by soft path.
static SHA256_DI: CcDigestInfo = CcDigestInfo {
    output_size: 32,
    state_size: 32,
    block_size: 64,
    oid_size: 0,
    oid: 0,
    initial_state: 0,
    compress: Some(soft_compress),
    final_fn: Some(soft_final),
};

static SHA1_DI: CcDigestInfo = CcDigestInfo {
    output_size: 20,
    state_size: 20,
    block_size: 64,
    oid_size: 0,
    oid: 0,
    initial_state: 0,
    compress: Some(soft_compress),
    final_fn: Some(soft_final),
};

/// `const struct ccdigest_info *ccsha256_di(void)` — Apple `ld-classic` (G4).
///
/// Must be a **function** (stub `bl`); a data symbol made the PLT jump into
/// zeros → SEGV in `computeContentUUID`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ccsha256_di() -> *const c_void {
    core::ptr::addr_of!(SHA256_DI).cast()
}

/// `const struct ccdigest_info *ccsha1_di(void)`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ccsha1_di() -> *const c_void {
    core::ptr::addr_of!(SHA1_DI).cast()
}

/// `ccdigest_init` soft (zero nbits + state prefix).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ccdigest_init(di: *const c_void, ctx: *mut c_void) {
    if di.is_null() || ctx.is_null() {
        return;
    }
    // ctx size ≈ state_size + 8 + block_size + 4; clear a bounded prefix.
    // SAFETY: di is our CcDigestInfo; ctx is caller stack of ccdigest_di_size.
    let info = unsafe { di.cast::<CcDigestInfo>().read() };
    let n = info
        .state_size
        .saturating_add(8)
        .saturating_add(info.block_size)
        .saturating_add(8)
        .min(512);
    unsafe {
        core::ptr::write_bytes(ctx.cast::<u8>(), 0, n);
    }
}

/// `ccdigest_update` soft (no-op; UUID under kh is non-cryptographic).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ccdigest_update(
    _di: *const c_void,
    _ctx: *mut c_void,
    _len: usize,
    _data: *const c_void,
) {
}

/// `ccdigest_final` free function — same as soft `di->final`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ccdigest_final(
    di: *const c_void,
    ctx: *mut c_void,
    digest: *mut c_void,
) {
    unsafe {
        soft_final(di, ctx, digest.cast());
    }
}

/// `CCDigest` one-shot soft (zero digest).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CCDigest(
    _algorithm: u32,
    _data: *const c_void,
    _length: usize,
    output: *mut u8,
) -> c_int {
    if !output.is_null() {
        unsafe {
            core::ptr::write_bytes(output, 0, 32);
        }
    }
    0
}

// ── soft libm used by ld/tapi ───────────────────────────────────────────────

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
