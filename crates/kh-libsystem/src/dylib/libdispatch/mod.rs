//! libdispatch (GCD) soft surface — run blocks on the calling thread.

#![allow(unused_imports)]

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

use crate::kh_core::heap::malloc;

type DispatchApplyFn = Option<unsafe extern "C" fn(*mut c_void, usize)>;

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

/// Soft semaphore counter (process-wide; enough for Rust std / single-thread guests).
static SEM_TOKEN: AtomicI32 = AtomicI32::new(0x5345_4D00); // "SEM\0"
static SEM_COUNT: AtomicI32 = AtomicI32::new(0);

/// `dispatch_semaphore_create` → soft token (non-null).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_semaphore_create(value: isize) -> *mut c_void {
    let v = i32::try_from(value).unwrap_or(0);
    SEM_COUNT.store(v, Ordering::SeqCst);
    let tok = SEM_TOKEN.fetch_add(1, Ordering::Relaxed);
    core::ptr::with_exposed_provenance_mut(usize::try_from(tok).unwrap_or(1).max(1))
}

/// `dispatch_semaphore_signal` → increment; return prior count (soft).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_semaphore_signal(_dsema: *mut c_void) -> isize {
    let prev = SEM_COUNT.fetch_add(1, Ordering::SeqCst);
    isize::try_from(prev).unwrap_or(0)
}

/// `dispatch_semaphore_wait` → decrement if positive, else soft-success (no park).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_semaphore_wait(
    _dsema: *mut c_void,
    _timeout: u64,
) -> isize {
    loop {
        let cur = SEM_COUNT.load(Ordering::SeqCst);
        if cur > 0 {
            if SEM_COUNT
                .compare_exchange(cur, cur.saturating_sub(1), Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return 0;
            }
            continue;
        }
        // Soft: never block forever under freestanding; succeed.
        return 0;
    }
}

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
///
/// Real GCD accepts `queue == NULL` (global concurrent). Soft ignores the
/// queue and always runs on the calling thread so modern Apple `ld`
/// `checkUndefines` still populates its local undef vector (it drives the
/// collect via `dispatch_apply` + a stack block).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dispatch_apply(
    iterations: usize,
    queue: *mut c_void,
    block: *mut c_void,
) {
    let _ = queue;
    if block.is_null() || iterations == 0 {
        return;
    }
    // Cap runaway iteration counts from corrupted options (soft).
    let iters = iterations.min(1 << 20);
    // Block invoke for apply takes (block, index).
    unsafe {
        let invoke = block_invoke_ptr(block);
        if invoke.is_null() {
            return;
        }
        let f: DispatchApplyFn = core::mem::transmute(invoke);
        if let Some(func) = f {
            let mut idx = 0_usize;
            while idx < iters {
                func(block, idx);
                idx = idx.saturating_add(1);
            }
        }
    }
}

