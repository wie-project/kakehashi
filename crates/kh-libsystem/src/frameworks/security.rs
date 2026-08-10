//! Security.framework soft surface + real cert verify via host helper.

#![allow(unused_imports)]

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::kh_core::heap::{free, malloc};
use crate::kh_core::sys;
use crate::kh_core::trace;

use crate::frameworks::corefoundation::{
    HDR_WORDS, KIND_ARR, KIND_CERT, KIND_DATA, KIND_POLICY, KIND_STR, KIND_TRUST, MAX_ARR,
    MAX_VERIFY_BUF, alloc_raw, obj_kind, obj_len, obj_write_hdr, payload_bytes, payload_words,
};
use crate::kh_core::helpers::KH_HELPER_VERIFY_CERT;

static TRUST_NOTE: AtomicUsize = AtomicUsize::new(0);

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecCertificateCreateWithData(
    _alloc: *mut c_void,
    data: *mut c_void,
) -> *mut c_void {
    let bytes = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(core::mem::size_of::<usize>());
    let p = alloc_raw(bytes);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_CERT, 0);
    unsafe {
        payload_words(p).write(data.addr());
    }
    p
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecPolicyCreateRevocation(_flags: u64) -> *mut c_void {
    // Soft policy object (no hostname).
    let bytes = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(core::mem::size_of::<usize>());
    let p = alloc_raw(bytes);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_POLICY, 0);
    p
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecPolicyCreateSSL(
    _server: u8,
    hostname: *mut c_void,
) -> *mut c_void {
    let bytes = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(core::mem::size_of::<usize>());
    let p = alloc_raw(bytes);
    if p.is_null() {
        return core::ptr::null_mut();
    }
    obj_write_hdr(p, KIND_POLICY, 0);
    unsafe {
        payload_words(p).write(hostname.addr());
    }
    p
}

/// `errSecSuccess` = 0.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecTrustCreateWithCertificates(
    certs: *mut c_void,
    policies: *mut c_void,
    trust: *mut *mut c_void,
) -> i32 {
    if trust.is_null() {
        return -1;
    }
    let bytes = HDR_WORDS
        .saturating_mul(core::mem::size_of::<usize>())
        .saturating_add(2_usize.saturating_mul(core::mem::size_of::<usize>()));
    let p = alloc_raw(bytes);
    if p.is_null() {
        return -1;
    }
    obj_write_hdr(p, KIND_TRUST, 0);
    unsafe {
        let pl = payload_words(p);
        pl.write(certs.addr());
        pl.add(1).write(policies.addr());
        trust.write(p);
    }
    0
}

/// Real verify via host CA bundle (Boolean true/false).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecTrustEvaluateWithError(
    trust: *mut c_void,
    error: *mut *mut c_void,
) -> u8 {
    if !error.is_null() {
        unsafe {
            error.write(core::ptr::null_mut());
        }
    }
    if obj_kind(trust) != Some(KIND_TRUST) {
        return 0;
    }

    // Pack on the heap — stack limit forbids 256 KiB locals under pedantic clippy.
    let pack = unsafe { malloc(MAX_VERIFY_BUF) };
    if pack.is_null() {
        return 0;
    }
    unsafe {
        core::ptr::write_bytes(pack.cast::<u8>(), 0, MAX_VERIFY_BUF);
    }
    let pack_slice = unsafe { core::slice::from_raw_parts_mut(pack.cast::<u8>(), MAX_VERIFY_BUF) };
    let mut off = 0_usize;

    let (hostname, certs) = unsafe {
        let pl = payload_words(trust);
        let certs = core::ptr::with_exposed_provenance_mut::<c_void>(pl.read());
        let policies = core::ptr::with_exposed_provenance_mut::<c_void>(pl.add(1).read());
        let host = extract_hostname(policies);
        (host, certs)
    };

    // hostname_len + bytes
    let host_bytes = hostname.as_bytes();
    let host_len = u32::try_from(host_bytes.len()).unwrap_or(0);
    if !write_u32(pack_slice, &mut off, host_len) {
        unsafe {
            free(pack);
        }
        return 0;
    }
    if !write_bytes(pack_slice, &mut off, host_bytes) {
        unsafe {
            free(pack);
        }
        return 0;
    }

    // Gather DER certs (leaf first).
    let mut der_list: [Option<(*const u8, usize)>; MAX_ARR] = [None; MAX_ARR];
    let n_certs = collect_certs(certs, &mut der_list);
    if n_certs == 0 {
        unsafe {
            free(pack);
        }
        return 0;
    }
    if !write_u32(pack_slice, &mut off, u32::try_from(n_certs).unwrap_or(0)) {
        unsafe {
            free(pack);
        }
        return 0;
    }
    for i in 0..n_certs {
        let Some((ptr, len)) = der_list.get(i).copied().flatten() else {
            unsafe {
                free(pack);
            }
            return 0;
        };
        if !write_u32(pack_slice, &mut off, u32::try_from(len).unwrap_or(0)) {
            unsafe {
                free(pack);
            }
            return 0;
        }
        if len > 0 {
            let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
            if !write_bytes(pack_slice, &mut off, slice) {
                unsafe {
                    free(pack);
                }
                return 0;
            }
        }
    }

    let buf_ptr = pack.addr();
    let ret = unsafe {
        sys::helper2(
            crate::kh_core::helpers::KH_HELPER_VERIFY_CERT,
            u64::try_from(buf_ptr).unwrap_or(0),
            u64::try_from(off).unwrap_or(0),
        )
    };
    unsafe {
        free(pack);
    }

    // Verbose only: force_note would spam every HTTPS guest on first verify.
    if TRUST_NOTE.fetch_add(1, Ordering::Relaxed) == 0 {
        if ret == 0 {
            trace::note(b"[kh-libsystem] SecTrust: host CA verify ok\n");
        } else {
            trace::note(b"[kh-libsystem] SecTrust: host CA verify failed\n");
        }
    }

    u8::from(ret == 0)
}

fn extract_hostname(policies: *mut c_void) -> HeaplessHost {
    // Policy object or array of policies; first KIND_POLICY wins.
    if obj_kind(policies) == Some(KIND_POLICY) {
        return hostname_from_policy(policies);
    }
    if obj_kind(policies) == Some(KIND_ARR) {
        let n = usize::try_from(obj_len(policies)).unwrap_or(0);
        let slots = payload_words(policies);
        for i in 0..n.min(MAX_ARR) {
            let addr = unsafe { slots.add(i).read() };
            let p = core::ptr::with_exposed_provenance_mut::<c_void>(addr);
            if obj_kind(p) == Some(KIND_POLICY) {
                return hostname_from_policy(p);
            }
        }
    }
    HeaplessHost::empty()
}

fn hostname_from_policy(policy: *mut c_void) -> HeaplessHost {
    let addr = unsafe { payload_words(policy).read() };
    let host_obj = core::ptr::with_exposed_provenance_mut::<c_void>(addr);
    if obj_kind(host_obj) != Some(KIND_STR) {
        return HeaplessHost::empty();
    }
    let n = usize::try_from(obj_len(host_obj)).unwrap_or(0);
    let mut h = HeaplessHost::empty();
    let copy = n.min(HeaplessHost::CAP);
    unsafe {
        core::ptr::copy_nonoverlapping(payload_bytes(host_obj), h.buf.as_mut_ptr(), copy);
    }
    h.len = copy;
    h
}

fn collect_certs(certs: *mut c_void, out: &mut [Option<(*const u8, usize)>; MAX_ARR]) -> usize {
    let mut n = 0_usize;
    if obj_kind(certs) == Some(KIND_CERT) {
        if let Some(d) = cert_der(certs)
            && let Some(slot) = out.get_mut(0)
        {
            *slot = Some(d);
            n = 1;
        }
        return n;
    }
    if obj_kind(certs) == Some(KIND_ARR) {
        let count = usize::try_from(obj_len(certs)).unwrap_or(0);
        let slots = payload_words(certs);
        for i in 0..count.min(MAX_ARR) {
            let addr = unsafe { slots.add(i).read() };
            let c = core::ptr::with_exposed_provenance_mut::<c_void>(addr);
            if obj_kind(c) == Some(KIND_CERT)
                && let Some(d) = cert_der(c)
                && let Some(slot) = out.get_mut(n)
            {
                *slot = Some(d);
                n = n.saturating_add(1);
            }
        }
    }
    n
}

fn cert_der(cert: *mut c_void) -> Option<(*const u8, usize)> {
    let addr = unsafe { payload_words(cert).read() };
    let data = core::ptr::with_exposed_provenance_mut::<c_void>(addr);
    if obj_kind(data) != Some(KIND_DATA) {
        return None;
    }
    let n = usize::try_from(obj_len(data)).unwrap_or(0);
    if n == 0 {
        return None;
    }
    Some((payload_bytes(data).cast_const(), n))
}

fn write_u32(buf: &mut [u8], off: &mut usize, v: u32) -> bool {
    let start = *off;
    let end = start.saturating_add(4);
    if end > buf.len() {
        return false;
    }
    if let Some(dst) = buf.get_mut(start..end) {
        dst.copy_from_slice(&v.to_le_bytes());
        *off = end;
        true
    } else {
        false
    }
}

fn write_bytes(buf: &mut [u8], off: &mut usize, src: &[u8]) -> bool {
    let start = *off;
    let end = start.saturating_add(src.len());
    if end > buf.len() {
        return false;
    }
    if let Some(dst) = buf.get_mut(start..end) {
        dst.copy_from_slice(src);
        *off = end;
        true
    } else {
        false
    }
}

/// Small stack hostname (no heap).
struct HeaplessHost {
    buf: [u8; 256],
    len: usize,
}

impl HeaplessHost {
    const CAP: usize = 256;
    fn empty() -> Self {
        Self {
            buf: [0; 256],
            len: 0,
        }
    }
    fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn SecTrustSetOCSPResponse(
    _trust: *mut c_void,
    _response: *mut c_void,
) -> i32 {
    0 // errSecSuccess
}
