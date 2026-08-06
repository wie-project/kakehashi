//! Soft libobjc + minimal Foundation class data for modern Apple `ld` (clang G5).
//!
//! The default CLT linker (`ld`, not `ld-classic`) loads Foundation + libobjc.
//! Bottle has neither; bind falls through to freestanding libSystem. Soft stubs
//! keep load + early `main` from aborting on missing trampolines so the next
//! real need surfaces in the log (trace-first).
//!
//! Not a real ObjC runtime: no class hierarchy, no method tables, no ARC heap.
//! `objc_msgSend` returns nil / 0; retain/release are identity / no-op.
//! Clean-room only — no Apple sources.

#![allow(
    non_snake_case,
    non_upper_case_globals,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::missing_safety_doc,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::used_underscore_binding
)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

// ── Autorelease pool (soft stack of tokens) ─────────────────────────────────

static POOL_DEPTH: AtomicUsize = AtomicUsize::new(0);
static POOL_TOKEN: AtomicUsize = AtomicUsize::new(1);

/// `objc_autoreleasePoolPush` → opaque pool token.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_autoreleasePoolPush() -> *mut c_void {
    let _ = POOL_DEPTH.fetch_add(1, Ordering::Relaxed);
    let n = POOL_TOKEN.fetch_add(1, Ordering::Relaxed);
    // Non-null soft token (high half so PAGEZERO probes still pass).
    (0x2_0000_0000_usize.wrapping_add(n)) as *mut c_void
}

/// `objc_autoreleasePoolPop` — soft no-op (no deferred releases).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_autoreleasePoolPop(_pool: *mut c_void) {
    let _ = POOL_DEPTH.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |d| {
        Some(d.saturating_sub(1))
    });
}

// ── ARC / retain-release (identity) ─────────────────────────────────────────

/// `objc_retain` — soft: return the same pointer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_retain(obj: *mut c_void) -> *mut c_void {
    obj
}

/// `objc_release` — soft no-op.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_release(_obj: *mut c_void) {}

/// `objc_retainAutorelease` — soft: return object (no pool registration).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_retainAutorelease(obj: *mut c_void) -> *mut c_void {
    obj
}

/// `objc_retainAutoreleasedReturnValue` — soft: identity.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_retainAutoreleasedReturnValue(
    obj: *mut c_void,
) -> *mut c_void {
    obj
}

/// `objc_autorelease` — soft: identity (no pool).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_autorelease(obj: *mut c_void) -> *mut c_void {
    obj
}

/// `objc_autoreleaseReturnValue` — soft: identity.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_autoreleaseReturnValue(obj: *mut c_void) -> *mut c_void {
    obj
}

/// `objc_storeStrong` — soft: write pointer, ignore old.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_storeStrong(location: *mut *mut c_void, obj: *mut c_void) {
    if !location.is_null() {
        unsafe {
            core::ptr::write(location, obj);
        }
    }
}

// ── msgSend / class opts (nil / zero) ───────────────────────────────────────

/// `objc_msgSend` — soft: return nil. Real selector dispatch is out of scope;
/// modern `ld` early paths that only need pool push/pop + retain still run.
/// When a path needs a real NSObject method, extend here or soft-Foundation.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_msgSend(
    _receiver: *mut c_void,
    _sel: *const c_void,
    // Extra args live in registers/stack; we ignore them.
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `objc_msgSendSuper2` — soft nil.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_msgSendSuper2(
    _super: *mut c_void,
    _sel: *const c_void,
) -> *mut c_void {
    core::ptr::null_mut()
}

/// `objc_opt_class` — soft: return receiver (treat as Class) or null.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_opt_class(obj: *mut c_void) -> *mut c_void {
    obj
}

/// `objc_opt_isKindOfClass` — soft: always false (0).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_opt_isKindOfClass(
    _obj: *mut c_void,
    _cls: *mut c_void,
) -> usize {
    0
}

/// `objc_opt_respondsToSelector` — soft: always false.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_opt_respondsToSelector(
    _obj: *mut c_void,
    _sel: *const c_void,
) -> usize {
    0
}

/// `objc_getClass` — soft: null (no class registry).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn objc_getClass(_name: *const u8) -> *mut c_void {
    core::ptr::null_mut()
}

/// `sel_registerName` — soft: return the C string pointer as SEL token.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sel_registerName(name: *const u8) -> *const c_void {
    name.cast()
}

/// `class_getName` — soft: empty name.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn class_getName(_cls: *mut c_void) -> *const u8 {
    c"".as_ptr().cast()
}

// ── Soft Class data objects (Foundation class refs used by modern ld) ───────
//
// Layout is not a real objc_class; only the address is used as an opaque id
// for class methods. Methods via msgSend still return nil.
// Export names use `$` (invalid in Rust idents) via `export_name`.

macro_rules! soft_objc_class {
    ($rust:ident, $sym:literal) => {
        #[unsafe(export_name = $sym)]
        #[used]
        pub(crate) static mut $rust: [usize; 8] = [0; 8];
    };
}

soft_objc_class!(OBJC_CLASS_NSArray, "OBJC_CLASS_$_NSArray");
soft_objc_class!(OBJC_CLASS_NSDictionary, "OBJC_CLASS_$_NSDictionary");
soft_objc_class!(OBJC_CLASS_NSInputStream, "OBJC_CLASS_$_NSInputStream");
soft_objc_class!(
    OBJC_CLASS_NSJSONSerialization,
    "OBJC_CLASS_$_NSJSONSerialization"
);
soft_objc_class!(OBJC_CLASS_NSNumber, "OBJC_CLASS_$_NSNumber");
soft_objc_class!(OBJC_CLASS_NSString, "OBJC_CLASS_$_NSString");
soft_objc_class!(OBJC_CLASS_NSObject, "OBJC_CLASS_$_NSObject");
soft_objc_class!(OBJC_CLASS_NSData, "OBJC_CLASS_$_NSData");
soft_objc_class!(OBJC_CLASS_NSMutableArray, "OBJC_CLASS_$_NSMutableArray");
soft_objc_class!(
    OBJC_CLASS_NSMutableDictionary,
    "OBJC_CLASS_$_NSMutableDictionary"
);
soft_objc_class!(OBJC_CLASS_NSMutableString, "OBJC_CLASS_$_NSMutableString");

// ── os_unfair_lock (modern ld / Foundation) ─────────────────────────────────
// Darwin: locked word is non-zero while held. Soft: simple CAS on the u32.

/// `os_unfair_lock_lock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_unfair_lock_lock(lock: *mut u32) {
    if lock.is_null() {
        return;
    }
    // Spin with yield-ish busy loop (guest single-core enough for soft).
    loop {
        let cur = unsafe { core::ptr::read_volatile(lock) };
        if cur == 0 {
            unsafe {
                core::ptr::write_volatile(lock, 1);
            }
            // Cheap barrier for freestanding (no atomic on raw ptr without sync).
            core::sync::atomic::compiler_fence(Ordering::SeqCst);
            return;
        }
        core::hint::spin_loop();
    }
}

/// `os_unfair_lock_lock_with_options` — soft: same as lock.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_unfair_lock_lock_with_options(lock: *mut u32, _options: u32) {
    unsafe {
        os_unfair_lock_lock(lock);
    }
}

/// `os_unfair_lock_trylock` → 1 success / 0 busy.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_unfair_lock_trylock(lock: *mut u32) -> u8 {
    if lock.is_null() {
        return 0;
    }
    let cur = unsafe { core::ptr::read_volatile(lock) };
    if cur != 0 {
        return 0;
    }
    unsafe {
        core::ptr::write_volatile(lock, 1);
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    1
}

/// `os_unfair_lock_unlock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_unfair_lock_unlock(lock: *mut u32) {
    if lock.is_null() {
        return;
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    unsafe {
        core::ptr::write_volatile(lock, 0);
    }
}

// ── os_log / signpost soft (telemetry; modern ld probes) ────────────────────

/// `os_log_create` → soft non-null token.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_log_create(
    _subsystem: *const u8,
    _category: *const u8,
) -> *mut c_void {
    0x3_0000_0001_usize as *mut c_void
}

/// `os_signpost_enabled` → false.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_signpost_enabled(_log: *mut c_void) -> u8 {
    0
}

/// `os_signpost_id_make_with_pointer` → soft id.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn os_signpost_id_make_with_pointer(
    _log: *mut c_void,
    ptr: *const c_void,
) -> u64 {
    ptr.addr() as u64
}

/// `_os_signpost_emit_with_name_impl` — soft no-op.
#[unsafe(export_name = "_os_signpost_emit_with_name_impl")]
pub(crate) unsafe extern "C" fn os_signpost_emit_with_name_impl(
    _dso: *const c_void,
    _log: *mut c_void,
    _type_: u8,
    _sp_id: u64,
    _name: *const u8,
    _format: *const u8,
    _buf: *mut u8,
    _size: u32,
) {
}

/// `_dispatch_queue_attr_concurrent` data (modern ld import).
#[unsafe(no_mangle)]
#[used]
pub(crate) static mut _dispatch_queue_attr_concurrent: usize = 1;
