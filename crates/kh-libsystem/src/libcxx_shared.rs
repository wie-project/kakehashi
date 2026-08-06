//! Freestanding `std::__1::__shared_weak_count` / `__shared_count` surface.
//!
//! Observed: Apple clang `-cc1` hits `__shared_weak_count::__release_weak`.
//! Layout follows public libc++ (alternate control block):
//!
//! ```text
//! +0  vptr
//! +8  __shared_owners_   (use_count - 1)
//! +16 __shared_weak_owners_ (weak_count - 1; shared holds one weak)
//! ```
//!
//! Counter rule (public libc++): decrement returns the **new** value; when
//! that value is **-1**, the last owner is gone → virtual `__on_zero_*`.
//!
//! Not a paste of libc++ sources — clean-room from public ABI + trace.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss,
    clippy::ptr_as_ptr
)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicI64, Ordering};

/// Control-block layout (arm64 / LP64).
#[repr(C)]
struct SharedWeakCount {
    vptr: *const *const c_void,
    shared_owners: AtomicI64,
    weak_owners: AtomicI64,
}

/// Itanium: first slot of the vtable object is the first virtual function.
/// For `__shared_weak_count` (public order): dtor, deleting dtor,
/// `__on_zero_shared`, `__on_zero_shared_weak`, `__get_deleter`.
const VFN_ON_ZERO_SHARED: usize = 2;
const VFN_ON_ZERO_SHARED_WEAK: usize = 3;

#[inline]
fn as_swc(this: *mut c_void) -> *mut SharedWeakCount {
    this.cast()
}

/// Call virtual method at `slot` with `this` (Itanium / AArch64 C++).
unsafe fn vcall0(this: *mut SharedWeakCount, slot: usize) {
    if this.is_null() {
        return;
    }
    let vptr = unsafe { (*this).vptr };
    if vptr.is_null() {
        return;
    }
    let fptr = unsafe { *vptr.add(slot) };
    if fptr.is_null() {
        return;
    }
    let f: unsafe extern "C" fn(*mut SharedWeakCount) =
        unsafe { core::mem::transmute(fptr) };
    unsafe {
        f(this);
    }
}

/// `std::__1::__shared_weak_count::__release_weak()`
///
/// Soft: only adjust counters; do **not** call virtual `__on_zero_shared_weak`
/// yet. Wrong vtable slot SEGV'd Apple clang `-cc1` (pc stable @ ~0x2c515b8).
/// Leak control blocks for now; refine dispatch after G3 object output works.
#[unsafe(export_name = "_ZNSt3__119__shared_weak_count14__release_weakEv")]
pub(crate) unsafe extern "C" fn shared_weak_release_weak(this: *mut c_void) {
    if this.is_null() {
        return;
    }
    let swc = as_swc(this);
    let _ = unsafe { (*swc).weak_owners.fetch_sub(1, Ordering::AcqRel) };
    let _ = (VFN_ON_ZERO_SHARED_WEAK, vcall0 as unsafe fn(_, _));
}

/// `std::__1::__shared_weak_count::__release_shared()` (if out-of-line).
///
/// Soft: decrement shared only (no virtual / cascade) — see `__release_weak`.
#[unsafe(export_name = "_ZNSt3__119__shared_weak_count16__release_sharedEv")]
pub(crate) unsafe extern "C" fn shared_weak_release_shared(this: *mut c_void) {
    if this.is_null() {
        return;
    }
    let swc = as_swc(this);
    let _ = unsafe { (*swc).shared_owners.fetch_sub(1, Ordering::AcqRel) };
    let _ = VFN_ON_ZERO_SHARED;
}

/// `std::__1::__shared_count::__release_shared()` → bool (true if last).
#[unsafe(export_name = "_ZNSt3__114__shared_count16__release_sharedEv")]
pub(crate) unsafe extern "C" fn shared_count_release_shared(this: *mut c_void) -> bool {
    if this.is_null() {
        return false;
    }
    let owners = unsafe { this.byte_add(8).cast::<AtomicI64>() };
    let new = unsafe { (*owners).fetch_sub(1, Ordering::AcqRel) }.wrapping_sub(1);
    new == -1
}

/// `std::__1::__shared_weak_count::lock()` → control block or null.
#[unsafe(export_name = "_ZNSt3__119__shared_weak_count4lockEv")]
pub(crate) unsafe extern "C" fn shared_weak_lock(this: *mut c_void) -> *mut c_void {
    if this.is_null() {
        return core::ptr::null_mut();
    }
    let swc = as_swc(this);
    loop {
        let cur = unsafe { (*swc).shared_owners.load(Ordering::Acquire) };
        if cur == -1 {
            return core::ptr::null_mut();
        }
        match unsafe {
            (*swc).shared_owners.compare_exchange_weak(
                cur,
                cur.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
        } {
            Ok(_) => return this,
            Err(_) => core::hint::spin_loop(),
        }
    }
}

/// `std::__1::__shared_weak_count::__get_deleter(type_info const&)` soft null.
#[unsafe(export_name = "_ZNKSt3__119__shared_weak_count13__get_deleterERKSt9type_info")]
pub(crate) unsafe extern "C" fn shared_weak_get_deleter(
    _this: *const c_void,
    _ti: *const c_void,
) -> *const c_void {
    core::ptr::null()
}

/// `std::__1::__shared_weak_count::~__shared_weak_count()` complete object.
#[unsafe(export_name = "_ZNSt3__119__shared_weak_countD2Ev")]
pub(crate) unsafe extern "C" fn shared_weak_dtor(_this: *mut c_void) {
    // Body empty in public libc++; derived control blocks free storage in
    // `__on_zero_shared_weak`.
}

/// `std::__1::__shared_count::~__shared_count()`
#[unsafe(export_name = "_ZNSt3__114__shared_countD2Ev")]
pub(crate) unsafe extern "C" fn shared_count_dtor(_this: *mut c_void) {}

/// Also export C1/D0 aliases when the guest binds complete/deleting forms.
#[unsafe(export_name = "_ZNSt3__119__shared_weak_countD1Ev")]
pub(crate) unsafe extern "C" fn shared_weak_dtor_c1(this: *mut c_void) {
    unsafe {
        shared_weak_dtor(this);
    }
}

#[unsafe(export_name = "_ZNSt3__114__shared_countD1Ev")]
pub(crate) unsafe extern "C" fn shared_count_dtor_c1(this: *mut c_void) {
    unsafe {
        shared_count_dtor(this);
    }
}
