//! Minimal Apple-framework stubs for guests that still *link* CF/Security/CC
//! (default Darwin curl) when those frameworks are not in the bottle.
//!
//! Bind path: two-level ordinal → missing framework → flat lookup into this
//! dylib (`kh-loader`). Bodies abort or return null; enough to pass load for
//! `curl --version` and to surface real use later via abort notes.

use core::ffi::{c_char, c_int, c_void};

use crate::process::exit_now;
use crate::trace;

fn stub_abort(name: &[u8]) -> ! {
    // Fatal paths always print (verbose libsystem trace stays off by default).
    trace::force_note(b"[kh-libsystem] apple stub called: ");
    trace::force_note(name);
    trace::force_note(b"\n");
    // SAFETY: never returns.
    unsafe {
        exit_now(127);
    }
}

// ── CoreFoundation (data) ───────────────────────────────────────────────────

/// `kCFTypeArrayCallBacks` — opaque table; never read if CF paths unused.
#[unsafe(export_name = "kCFTypeArrayCallBacks")]
#[used]
static K_CF_TYPE_ARRAY_CALLBACKS: [usize; 8] = [0; 8];

// ── CoreFoundation (functions) ──────────────────────────────────────────────

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFArrayAppendValue(_arr: *mut c_void, _value: *const c_void) {
    stub_abort(b"CFArrayAppendValue");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFArrayCreateMutable(
    _alloc: *mut c_void,
    _cap: isize,
    _cbs: *const c_void,
) -> *mut c_void {
    stub_abort(b"CFArrayCreateMutable");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFDataCreate(
    _alloc: *mut c_void,
    _bytes: *const u8,
    _len: isize,
) -> *mut c_void {
    stub_abort(b"CFDataCreate");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFErrorCopyDescription(_err: *mut c_void) -> *mut c_void {
    stub_abort(b"CFErrorCopyDescription");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFErrorGetCode(_err: *mut c_void) -> isize {
    stub_abort(b"CFErrorGetCode");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFRelease(_cf: *mut c_void) {
    // Common on cleanup; no-op if nothing was created.
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringCreateWithCString(
    _alloc: *mut c_void,
    _c_str: *const c_char,
    _encoding: u32,
) -> *mut c_void {
    stub_abort(b"CFStringCreateWithCString");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringGetCString(
    _s: *mut c_void,
    _buf: *mut c_char,
    _buf_size: isize,
    _encoding: u32,
) -> u8 {
    stub_abort(b"CFStringGetCString");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringGetLength(_s: *mut c_void) -> isize {
    stub_abort(b"CFStringGetLength");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CFStringGetMaximumSizeForEncoding(
    _len: isize,
    _encoding: u32,
) -> isize {
    stub_abort(b"CFStringGetMaximumSizeForEncoding");
}

// ── Security.framework ──────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecCertificateCreateWithData(
    _alloc: *mut c_void,
    _data: *mut c_void,
) -> *mut c_void {
    stub_abort(b"SecCertificateCreateWithData");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecPolicyCreateRevocation(_flags: u64) -> *mut c_void {
    stub_abort(b"SecPolicyCreateRevocation");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecPolicyCreateSSL(
    _server: u8,
    _hostname: *mut c_void,
) -> *mut c_void {
    stub_abort(b"SecPolicyCreateSSL");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecTrustCreateWithCertificates(
    _certs: *mut c_void,
    _policies: *mut c_void,
    _trust: *mut *mut c_void,
) -> i32 {
    stub_abort(b"SecTrustCreateWithCertificates");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecTrustEvaluateWithError(
    _trust: *mut c_void,
    _error: *mut *mut c_void,
) -> u8 {
    stub_abort(b"SecTrustEvaluateWithError");
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecTrustSetOCSPResponse(
    _trust: *mut c_void,
    _response: *mut c_void,
) -> i32 {
    stub_abort(b"SecTrustSetOCSPResponse");
}

// ── CommonCrypto ────────────────────────────────────────────────────────────

/// `CCRandomGenerateBytes` → nlist `_CCRandomGenerateBytes` (fill with zeros).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn CCRandomGenerateBytes(bytes: *mut c_void, count: usize) -> c_int {
    if bytes.is_null() || count == 0 {
        return 0;
    }
    // SAFETY: caller buffer; deterministic zero fill (not crypto-grade).
    unsafe {
        let p = bytes.cast::<u8>();
        let mut i = 0_usize;
        while i < count {
            p.add(i).write(0);
            i = i.saturating_add(1);
        }
    }
    0
}
