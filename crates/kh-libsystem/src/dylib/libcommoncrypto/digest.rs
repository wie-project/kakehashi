//! CommonCrypto / corecrypto soft digests (ld-classic UUID path).

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

use crate::kh_core::heap::malloc;
use crate::dylib::libsystem_c::stdio::memcpy;

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

