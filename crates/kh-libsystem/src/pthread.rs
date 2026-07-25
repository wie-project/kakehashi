//! Single-guest pthread stubs (no real threads; success no-ops for locks).

use core::ffi::{c_int, c_void};

use crate::trace;

const EAGAIN: i32 = 35;
const EINVAL: i32 = 22;

// Opaque pthread types are guest-sized blobs; we only need the symbols.

/// C `pthread_mutex_init` → nlist `_pthread_mutex_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_init(
    _mutex: *mut c_void,
    _attr: *const c_void,
) -> c_int {
    0
}

/// C `pthread_mutex_destroy` → nlist `_pthread_mutex_destroy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_destroy(_mutex: *mut c_void) -> c_int {
    0
}

/// C `pthread_mutex_lock` → nlist `_pthread_mutex_lock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_lock(_mutex: *mut c_void) -> c_int {
    0
}

/// C `pthread_mutex_unlock` → nlist `_pthread_mutex_unlock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_mutex_unlock(_mutex: *mut c_void) -> c_int {
    0
}

/// C `pthread_cond_init` → nlist `_pthread_cond_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_init(
    _cond: *mut c_void,
    _attr: *const c_void,
) -> c_int {
    0
}

/// C `pthread_cond_destroy` → nlist `_pthread_cond_destroy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_destroy(_cond: *mut c_void) -> c_int {
    0
}

/// C `pthread_cond_wait` → nlist `_pthread_cond_wait` (returns immediately).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_wait(
    _cond: *mut c_void,
    _mutex: *mut c_void,
) -> c_int {
    0
}

/// C `pthread_cond_broadcast` → nlist `_pthread_cond_broadcast`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_cond_broadcast(_cond: *mut c_void) -> c_int {
    0
}

/// C `pthread_attr_init` → nlist `_pthread_attr_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_attr_init(_attr: *mut c_void) -> c_int {
    0
}

/// C `pthread_attr_destroy` → nlist `_pthread_attr_destroy`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_attr_destroy(_attr: *mut c_void) -> c_int {
    0
}

/// C `pthread_attr_setdetachstate` → nlist `_pthread_attr_setdetachstate`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_attr_setdetachstate(
    _attr: *mut c_void,
    _state: c_int,
) -> c_int {
    0
}

/// C `pthread_create` → nlist `_pthread_create` (not supported yet).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_create(
    _thread: *mut c_void,
    _attr: *const c_void,
    _start: *mut c_void,
    _arg: *mut c_void,
) -> c_int {
    trace::note(b"[kh-libsystem] pthread_create (stub EAGAIN)\n");
    // Soft failure: guest may fall back to single-threaded.
    EAGAIN
}

/// C `pthread_join` → nlist `_pthread_join`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_join(
    _thread: *mut c_void,
    _value_ptr: *mut *mut c_void,
) -> c_int {
    EINVAL
}

/// C `pthread_detach` → nlist `_pthread_detach`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_detach(_thread: *mut c_void) -> c_int {
    EINVAL
}
