//! `dlopen` / `dlsym` via host mapped-image helpers.

use core::ffi::{c_char, c_int, c_void};

use crate::kh_core::sys;
use crate::kh_core::helpers::{KH_HELPER_DLOPEN, KH_HELPER_DLSYM};

// ── dl* via host helpers (mapped-image table; see `KH_HELPER_DLOPEN`)
//
// Modern `ld` already maps `@rpath/libLTO.dylib` at process start. Clang still
// passes `-lto_library …/libLTO.dylib`, which re-opens the plugin with
// `dlopen`/`dlsym`. Returning the existing image handle (not null) unblocks
// non-bitcode links without a second map of LLVM.

/// C `dlopen` → host mapped-image table (and on-demand load).
///
/// Policy for `libLTO.dylib` lives in the host helper: already-mapped (ld /
/// clang `-lto_library`) still gets the cookie so `dlsym` does not enter live
/// LLVM plugin entry points; a first-time `dlopen` (otool-classic) maps the
/// dylib and returns a real handle.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dlopen(path: *const c_char, _mode: c_int) -> *mut c_void {
    let path_va = if path.is_null() {
        0_u64
    } else {
        u64::try_from(path.addr()).unwrap_or(0)
    };
    // SAFETY: host helper id matches kh-runtime.
    let h = unsafe { sys::helper1(KH_HELPER_DLOPEN, path_va) };
    if h > 0 {
        let bits = u64::try_from(h).unwrap_or(0);
        return core::ptr::with_exposed_provenance_mut(usize::try_from(bits).unwrap_or(0));
    }
    core::ptr::null_mut()
}

/// C `dlsym` → guest VA from the mapped-image table, or null.
///
/// The LTO cookie handle never resolves symbols (avoids jumping into LLVM
/// under freestanding). Other handles use the host table for real VAs.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    if symbol.is_null() {
        return core::ptr::null_mut();
    }
    let h = u64::try_from(handle.addr()).unwrap_or(0);
    // LTO cookie: no live LLVM entry (non-bitcode path).
    if h == 0x0000_4B48_C701 {
        return core::ptr::null_mut();
    }
    let s = u64::try_from(symbol.addr()).unwrap_or(0);
    // SAFETY: host helper id matches kh-runtime.
    let va = unsafe { sys::helper2(KH_HELPER_DLSYM, h, s) };
    if va <= 0 {
        return core::ptr::null_mut();
    }
    let bits = u64::try_from(va).unwrap_or(0);
    core::ptr::with_exposed_provenance_mut(usize::try_from(bits).unwrap_or(0))
}

/// C `dlclose` → 0 (images stay mapped for the process).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dlclose(_handle: *mut c_void) -> c_int {
    0
}

/// C `dlerror` → static message (guests only print it).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dlerror() -> *mut c_char {
    c"dlopen: image not mapped under kh".as_ptr().cast_mut()
}

/// C `dladdr` → 0 (not found).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dladdr(_addr: *const c_void, _info: *mut c_void) -> c_int {
    0
}

