//! Freestanding libc++ synchronization surface (mutex / cond / once).
//!
//! Apple CLT `clang` imports these from `libc++.1.dylib` (aliased to freestanding
//! libSystem). Bodies forward to our pthread primitives. Not a full libc++ —
//! only symbols exercised by guests (trace-first).
//!
//! Layout assumption (Apple arm64 libc++): `std::mutex` / `recursive_mutex` /
//! `condition_variable` embed the corresponding `pthread_*_t` at offset 0.

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::pthread;
use crate::trace;

// ── std::mutex ──────────────────────────────────────────────────────────────

/// `std::mutex::lock()` → nlist `__ZNSt3__15mutex4lockEv`.
#[unsafe(export_name = "_ZNSt3__15mutex4lockEv")]
pub(crate) unsafe extern "C" fn std_mutex_lock(this: *mut c_void) {
    let _ = unsafe { pthread::pthread_mutex_lock(this) };
}

/// `std::mutex::unlock()` → nlist `__ZNSt3__15mutex6unlockEv`.
#[unsafe(export_name = "_ZNSt3__15mutex6unlockEv")]
pub(crate) unsafe extern "C" fn std_mutex_unlock(this: *mut c_void) {
    let _ = unsafe { pthread::pthread_mutex_unlock(this) };
}

/// `std::mutex::~mutex()` → nlist `__ZNSt3__15mutexD1Ev`.
#[unsafe(export_name = "_ZNSt3__15mutexD1Ev")]
pub(crate) unsafe extern "C" fn std_mutex_dtor(this: *mut c_void) {
    let _ = unsafe { pthread::pthread_mutex_destroy(this) };
}

// ── std::recursive_mutex (soft: non-recursive freestanding mutex) ────────────

/// `std::recursive_mutex::recursive_mutex()` → nlist `__ZNSt3__115recursive_mutexC1Ev`.
#[unsafe(export_name = "_ZNSt3__115recursive_mutexC1Ev")]
pub(crate) unsafe extern "C" fn std_recursive_mutex_ctor(this: *mut c_void) {
    let _ = unsafe { pthread::pthread_mutex_init(this, core::ptr::null()) };
}

/// `std::recursive_mutex::~recursive_mutex()` → nlist `__ZNSt3__115recursive_mutexD1Ev`.
#[unsafe(export_name = "_ZNSt3__115recursive_mutexD1Ev")]
pub(crate) unsafe extern "C" fn std_recursive_mutex_dtor(this: *mut c_void) {
    let _ = unsafe { pthread::pthread_mutex_destroy(this) };
}

/// `std::recursive_mutex::lock()` → nlist `__ZNSt3__115recursive_mutex4lockEv`.
#[unsafe(export_name = "_ZNSt3__115recursive_mutex4lockEv")]
pub(crate) unsafe extern "C" fn std_recursive_mutex_lock(this: *mut c_void) {
    let _ = unsafe { pthread::pthread_mutex_lock(this) };
}

/// `std::recursive_mutex::unlock()` → nlist `__ZNSt3__115recursive_mutex6unlockEv`.
#[unsafe(export_name = "_ZNSt3__115recursive_mutex6unlockEv")]
pub(crate) unsafe extern "C" fn std_recursive_mutex_unlock(this: *mut c_void) {
    let _ = unsafe { pthread::pthread_mutex_unlock(this) };
}

// ── std::condition_variable ─────────────────────────────────────────────────

/// `std::condition_variable::~condition_variable()` →
/// `__ZNSt3__118condition_variableD1Ev`.
#[unsafe(export_name = "_ZNSt3__118condition_variableD1Ev")]
pub(crate) unsafe extern "C" fn std_condition_variable_dtor(this: *mut c_void) {
    let _ = unsafe { pthread::pthread_cond_destroy(this) };
}

/// `std::condition_variable::notify_one()` →
/// `__ZNSt3__118condition_variable10notify_oneEv`.
#[unsafe(export_name = "_ZNSt3__118condition_variable10notify_oneEv")]
pub(crate) unsafe extern "C" fn std_condition_variable_notify_one(this: *mut c_void) {
    let _ = unsafe { pthread::pthread_cond_signal(this) };
}

/// `std::condition_variable::notify_all()` →
/// `__ZNSt3__118condition_variable10notify_allEv`.
#[unsafe(export_name = "_ZNSt3__118condition_variable10notify_allEv")]
pub(crate) unsafe extern "C" fn std_condition_variable_notify_all(this: *mut c_void) {
    let _ = unsafe { pthread::pthread_cond_broadcast(this) };
}

/// `std::condition_variable::wait(unique_lock<mutex>&)` →
/// `__ZNSt3__118condition_variable4waitERNS_11unique_lockINS_5mutexEEE`.
///
/// Apple `unique_lock` layout (arm64): first pointer is `mutex*`. We pass that
/// to `pthread_cond_wait`.
#[unsafe(export_name = "_ZNSt3__118condition_variable4waitERNS_11unique_lockINS_5mutexEEE")]
pub(crate) unsafe extern "C" fn std_condition_variable_wait(
    this: *mut c_void,
    ulock: *mut c_void,
) {
    if this.is_null() || ulock.is_null() {
        return;
    }
    // SAFETY: unique_lock stores mutex* at offset 0 on this libc++ ABI.
    let mutex_ptr = unsafe { ulock.cast::<*mut c_void>().read() };
    if mutex_ptr.is_null() {
        return;
    }
    let _ = unsafe { pthread::pthread_cond_wait(this, mutex_ptr) };
}

// ── __call_once ─────────────────────────────────────────────────────────────

/// Flag values used by libc++ `__call_once` (unsigned long).
const ONCE_NOT: usize = 0;
const ONCE_DONE: usize = !0_usize; // common libc++ complete sentinel

/// `std::__1::__call_once(unsigned long&, void*, void(*)(void*))` →
/// `__ZNSt3__111__call_onceERVmPvPFvS2_E`.
#[unsafe(export_name = "_ZNSt3__111__call_onceERVmPvPFvS2_E")]
pub(crate) unsafe extern "C" fn std_call_once(
    flag: *mut usize,
    arg: *mut c_void,
    func: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    if flag.is_null() {
        return;
    }
    // SAFETY: guest once flag.
    let cell = unsafe { &*flag.cast::<AtomicUsize>() };
    if cell.load(Ordering::Acquire) == ONCE_DONE {
        return;
    }
    // Single-flight soft: no process-global mutex yet; fine for --version.
    if cell
        .compare_exchange(ONCE_NOT, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        if let Some(f) = func {
            // SAFETY: callee is guest code expecting `arg`.
            unsafe {
                f(arg);
            }
        }
        cell.store(ONCE_DONE, Ordering::Release);
    } else {
        // Another thread is running (or already done): spin until complete.
        while cell.load(Ordering::Acquire) != ONCE_DONE {
            core::hint::spin_loop();
        }
    }
}

// ── thread soft surface ─────────────────────────────────────────────────────

/// `std::thread::hardware_concurrency()` →
/// `__ZNSt3__16thread20hardware_concurrencyEv`.
#[unsafe(export_name = "_ZNSt3__16thread20hardware_concurrencyEv")]
pub(crate) unsafe extern "C" fn std_thread_hardware_concurrency() -> c_int {
    // Soft: report 1 until sysctl path is wired for guests that care.
    1
}

/// `std::thread::~thread()` → `__ZNSt3__16threadD1Ev` (no-op if not joinable).
#[unsafe(export_name = "_ZNSt3__16threadD1Ev")]
pub(crate) unsafe extern "C" fn std_thread_dtor(_this: *mut c_void) {
    // Soft: real libc++ aborts if joinable; we ignore for freestanding probes.
}

/// `std::thread::join()` → `__ZNSt3__16thread4joinEv`.
#[unsafe(export_name = "_ZNSt3__16thread4joinEv")]
pub(crate) unsafe extern "C" fn std_thread_join(_this: *mut c_void) {
    trace::note(b"[kh-libsystem] std::thread::join soft no-op\n");
}

/// `std::thread::detach()` → `__ZNSt3__16thread6detachEv`.
#[unsafe(export_name = "_ZNSt3__16thread6detachEv")]
pub(crate) unsafe extern "C" fn std_thread_detach(_this: *mut c_void) {
    trace::note(b"[kh-libsystem] std::thread::detach soft no-op\n");
}
