//! Freestanding libcurl surface for Apple `git-remote-http` (G4).
//!
//! Bottle install name `/usr/lib/libcurl.4.dylib` is a **symlink** to freestanding
//! `libSystem.B.dylib` (same pattern as `libc++.1.dylib`). Symbols live here;
//! network I/O uses host [`crate::KH_HELPER_TLS_CONNECT`]:
//! - `https://` — TCP + rustls; guest `read`/`write` are plaintext over the TLS FD
//! - `http://` — plain TCP (`TLS_FLAG_PLAIN`); same HTTP/1.1 streamer on the FD
//!
//! Clean-room: public curl man-page contracts + observed git usage.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::large_stack_arrays,
    clippy::manual_c_str_literals,
    clippy::match_same_arms,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_cast,
    clippy::useless_conversion
)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

use crate::KH_HELPER_TLS_CONNECT;
use crate::heap::{free, malloc, realloc};
use crate::posix::{close, read};
use crate::stdio::{memcpy, strlen, write};
use crate::sys;

// ── result codes ─────────────────────────────────────────────────────────────

const CURLE_OK: c_int = 0;
const CURLE_FAILED_INIT: c_int = 2;
const CURLE_URL_MALFORMAT: c_int = 3;
const CURLE_COULDNT_CONNECT: c_int = 7;
const CURLE_HTTP_RETURNED_ERROR: c_int = 22;
const CURLE_WRITE_ERROR: c_int = 23;
const CURLE_OUT_OF_MEMORY: c_int = 27;
const CURLE_OPERATION_TIMEDOUT: c_int = 28;
const CURLE_SSL_CONNECT_ERROR: c_int = 35;
const CURLE_BAD_FUNCTION_ARGUMENT: c_int = 43;

const CURLM_OK: c_int = 0;
const CURLM_BAD_HANDLE: c_int = 1;
const CURLM_BAD_EASY_HANDLE: c_int = 2;
const CURLM_OUT_OF_MEMORY: c_int = 3;
const CURLM_INTERNAL_ERROR: c_int = 4;
const CURLM_BAD_FUNCTION_ARGUMENT: c_int = 6;

const CURLMSG_DONE: c_int = 1;
const CURLSSLSET_OK: c_int = 0;
const CURLVERSION_NOW: c_int = 11;

// Common CURLOPT numbers used by git-remote-http.
const CURLOPT_WRITEDATA: c_int = 10_001;
const CURLOPT_URL: c_int = 10_002;
const CURLOPT_READDATA: c_int = 10_009;
const CURLOPT_ERRORBUFFER: c_int = 10_010;
const CURLOPT_POSTFIELDS: c_int = 10_015;
const CURLOPT_USERAGENT: c_int = 10_018;
const CURLOPT_HTTPHEADER: c_int = 10_023;
const CURLOPT_CUSTOMREQUEST: c_int = 10_036;
const CURLOPT_NOBODY: c_int = 44;
const CURLOPT_FAILONERROR: c_int = 45;
const CURLOPT_UPLOAD: c_int = 46;
const CURLOPT_POST: c_int = 47;
const CURLOPT_PUT: c_int = 54;
const CURLOPT_POSTFIELDSIZE: c_int = 60;
const CURLOPT_SSL_VERIFYPEER: c_int = 64;
const CURLOPT_CAINFO: c_int = 10_065;
const CURLOPT_HTTPGET: c_int = 80;
const CURLOPT_WRITEFUNCTION: c_int = 20_011;
const CURLOPT_READFUNCTION: c_int = 20_012;
const CURLOPT_POSTFIELDSIZE_LARGE: c_int = 30_120;
const CURLOPT_COPYPOSTFIELDS: c_int = 10_165;

const CURLINFO_STRING: c_int = 0x100_000;
const CURLINFO_LONG: c_int = 0x200_000;
const CURLINFO_DOUBLE: c_int = 0x300_000;
const CURLINFO_OFF_T: c_int = 0x600_000;
const CURLINFO_EFFECTIVE_URL: c_int = CURLINFO_STRING + 1;
const CURLINFO_RESPONSE_CODE: c_int = CURLINFO_LONG + 2;
const CURLINFO_SIZE_DOWNLOAD: c_int = CURLINFO_DOUBLE + 8;
const CURLINFO_CONTENT_TYPE: c_int = CURLINFO_STRING + 18;
const CURLINFO_SIZE_DOWNLOAD_T: c_int = CURLINFO_OFF_T + 8;

type WriteCb = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;
type ReadCb = unsafe extern "C" fn(*mut c_char, usize, usize, *mut c_void) -> usize;

const MAGIC_EASY: u32 = 0x4B48_4359; // KHCY
const MAGIC_MULTI: u32 = 0x4B48_434D; // KHCM
const MAGIC_SLIST: u32 = 0x4B48_4353; // KHCS
/// Host TLS/TCP connect request (`KH_HELPER_TLS_CONNECT`); LE, 64 bytes.
const KHTLS_MAGIC: u32 = 0x4B48_544C; // KHTL
const TLS_FLAG_VERIFY: u32 = 1;
/// Plain TCP only (no rustls) — freestanding `http://` remotes.
const TLS_FLAG_PLAIN: u32 = 2;

const MAX_HDR_BLOB: usize = 8 * 1024;
/// Streaming I/O chunk for HTTP body (multi‑GiB packs never fully buffered).
const IO_CHUNK: usize = 64 * 1024;
/// Max HTTP response header block before body.
const MAX_RESP_HDR: usize = 64 * 1024;
/// Cap for gathered POST bodies (want-lists / READFUNCTION / after inflate).
const MAX_POST_GATHER: usize = 64 * 1024 * 1024;
const ERRBUF_LEN: usize = 256;

/// Packed request for host rustls TCP+TLS connect → guest FD.
#[repr(C)]
struct KhTlsConnect {
    magic: u32,
    version: u32,
    flags: u32,
    port: u32,
    hostname: u64,
    hostname_len: u64,
    ca_path: u64,
    out_fd: u64,
    errbuf: u64,
    errbuf_cap: u64,
}

#[repr(C)]
struct Slist {
    magic: u32,
    data: *mut c_char,
    next: *mut Slist,
}

const EF_POST: u32 = 1;
const EF_PUT: u32 = 2;
const EF_NOBODY: u32 = 4;
const EF_UPLOAD: u32 = 8;
const EF_FAIL: u32 = 16;
const EF_SSL_VERIFY: u32 = 32;
const EF_DONE: u32 = 64;

/// Guest easy handle (`#[repr(C)]` so magic stays at offset 0).
#[repr(C)]
struct Easy {
    magic: u32,
    _pad: u32,
    url: *mut c_char,
    custom_request: *mut c_char,
    user_agent: *mut c_char,
    ca_info: *mut c_char,
    post_fields: *const c_void,
    post_field_size: i64,
    headers: *mut Slist,
    write_fn: Option<WriteCb>,
    write_data: *mut c_void,
    read_fn: Option<ReadCb>,
    read_data: *mut c_void,
    error_buffer: *mut c_char,
    flags: u32,
    response_code: c_long,
    result: c_int,
    download_size: i64,
    effective_url: *mut c_char,
    content_type: *mut c_char,
}

struct MultiEntry {
    easy: *mut Easy,
    done: bool,
    result: c_int,
    msg_delivered: bool,
}

struct Multi {
    magic: u32,
    entries: *mut MultiEntry,
    n_entries: usize,
    cap_entries: usize,
    last_msg: CurlMsg,
}

/// Layout matches libcurl `CURLMsg` on LP64 (msg + pad, easy*, data union).
#[repr(C)]
struct CurlMsg {
    msg: c_int,
    _pad: c_int,
    easy_handle: *mut c_void,
    /// `CURLMsg.data.result` (`CURLcode`) in the low bits of the union.
    data_result: u64,
}

static GLOBAL_INITS: AtomicI32 = AtomicI32::new(0);

static VERSION_STR: &[u8] = b"8.21.0-kakehashi\0";
static HOST_STR: &[u8] = b"aarch64-apple-darwin-kakehashi\0";
static SSL_STR: &[u8] = b"rustls/host\0";
static LIBZ_STR: &[u8] = b"1.2.11-kh\0";
static PROTO_HTTP: &[u8] = b"http\0";
static PROTO_HTTPS: &[u8] = b"https\0";
static mut PROTOCOLS: [*const c_char; 3] = [ptr::null(), ptr::null(), ptr::null()];
static mut VERSION_INFO: CurlVersionInfo = CurlVersionInfo {
    age: CURLVERSION_NOW,
    version: ptr::null(),
    version_num: 0x0008_1500,
    host: ptr::null(),
    features: (1 << 0) | (1 << 2),
    ssl_version: ptr::null(),
    ssl_version_num: 0,
    libz_version: ptr::null(),
    protocols: ptr::null(),
    ares: ptr::null(),
    ares_num: 0,
    libidn: ptr::null(),
    iconv_ver_num: 0,
    libssh_version: ptr::null(),
    brotli_ver_num: 0,
    brotli_version: ptr::null(),
    nghttp2_ver_num: 0,
    nghttp2_version: ptr::null(),
    quic_version: ptr::null(),
    cainfo: ptr::null(),
    capath: ptr::null(),
    zstd_ver_num: 0,
    zstd_version: ptr::null(),
    hyper_version: ptr::null(),
    gsasl_version: ptr::null(),
    feature_names: ptr::null(),
};

#[repr(C)]
struct CurlVersionInfo {
    age: c_int,
    version: *const c_char,
    version_num: u32,
    host: *const c_char,
    features: c_int,
    ssl_version: *const c_char,
    ssl_version_num: c_long,
    libz_version: *const c_char,
    protocols: *const *const c_char,
    ares: *const c_char,
    ares_num: c_int,
    libidn: *const c_char,
    iconv_ver_num: c_int,
    libssh_version: *const c_char,
    brotli_ver_num: u32,
    brotli_version: *const c_char,
    nghttp2_ver_num: u32,
    nghttp2_version: *const c_char,
    quic_version: *const c_char,
    cainfo: *const c_char,
    capath: *const c_char,
    zstd_ver_num: u32,
    zstd_version: *const c_char,
    hyper_version: *const c_char,
    gsasl_version: *const c_char,
    feature_names: *const *const c_char,
}

fn ensure_version_info() {
    // SAFETY: freestanding process-global init; guest is single-threaded here.
    unsafe {
        let vi = &mut *core::ptr::addr_of_mut!(VERSION_INFO);
        if !vi.version.is_null() {
            return;
        }
        vi.version = VERSION_STR.as_ptr().cast();
        vi.host = HOST_STR.as_ptr().cast();
        vi.ssl_version = SSL_STR.as_ptr().cast();
        vi.libz_version = LIBZ_STR.as_ptr().cast();
        let protos = &mut *core::ptr::addr_of_mut!(PROTOCOLS);
        protos[0] = PROTO_HTTP.as_ptr().cast();
        protos[1] = PROTO_HTTPS.as_ptr().cast();
        protos[2] = ptr::null();
        vi.protocols = protos.as_ptr();
    }
}

fn easy_from(p: *mut c_void) -> Option<&'static mut Easy> {
    if p.is_null() || p.addr() < crate::stdio::PAGEZERO_END {
        return None;
    }

    let e_ptr = p.cast::<Easy>();

    let magic = unsafe { core::ptr::addr_of!((*e_ptr).magic).read_unaligned() };
    if magic != MAGIC_EASY {
        return None;
    }

    let e = unsafe { &mut *e_ptr };
    Some(e)
}

fn multi_from(p: *mut c_void) -> Option<&'static mut Multi> {
    // Same barrier shape as easy_from (null + PAGEZERO + magic).
    if p.is_null() || p.addr() < crate::stdio::PAGEZERO_END {
        return None;
    }
    // SAFETY: null + PAGEZERO rejected; only curl_multi_init writes MAGIC_MULTI.
    let m = unsafe { &mut *p.cast::<Multi>() };
    if m.magic != MAGIC_MULTI {
        return None;
    }
    Some(m)
}

#[inline]
fn ptr_live(p: *const c_void) -> bool {
    !p.is_null() && p.addr() >= crate::stdio::PAGEZERO_END
}

fn set_err(easy: &Easy, msg: &[u8]) {
    if easy.error_buffer.is_null() {
        return;
    }
    let n = msg.len().min(ERRBUF_LEN.saturating_sub(1));
    unsafe {
        memcpy(easy.error_buffer.cast(), msg.as_ptr().cast(), n);
        *easy.error_buffer.add(n) = 0;
    }
}

fn dup_cstr(src: *const c_char) -> Option<*mut c_char> {
    if src.is_null() {
        return Some(ptr::null_mut());
    }
    // PAGEZERO / unrebased guest pointers (seen as 0x4000_0000 in G4).
    if src.addr() < crate::stdio::PAGEZERO_END {
        return None;
    }
    let n = unsafe { strlen(src) };
    let p = unsafe { malloc(n.saturating_add(1)) }.cast::<c_char>();
    if p.is_null() {
        return None;
    }
    unsafe {
        memcpy(p.cast(), src.cast(), n.saturating_add(1));
    }
    Some(p)
}

fn free_cstr(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            free(p.cast());
        }
    }
}

fn headers_blob(list: *mut Slist, out: &mut [u8]) -> usize {
    let mut off = 0_usize;
    let mut cur = list;
    let mut guard = 0_usize;
    while ptr_live(cur.cast()) {
        let node = unsafe { &*cur };
        if node.magic != MAGIC_SLIST {
            break;
        }
        if ptr_live(node.data.cast()) {
            let n = unsafe { strlen(node.data) };
            if off.saturating_add(n).saturating_add(1) > out.len() {
                break;
            }
            unsafe {
                memcpy(out.as_mut_ptr().add(off).cast(), node.data.cast(), n);
            }
            off = off.saturating_add(n);
            if let Some(slot) = out.get_mut(off) {
                *slot = b'\n';
            }
            off = off.saturating_add(1);
        }
        cur = node.next;
        guard = guard.saturating_add(1);
        if guard > 10_000 {
            break;
        }
    }
    off
}

fn method_of(easy: &Easy) -> u32 {
    if easy.flags & EF_NOBODY != 0 {
        2
    } else if easy.flags & EF_POST != 0 || !easy.post_fields.is_null() {
        1
    } else if easy.flags & (EF_PUT | EF_UPLOAD) != 0 {
        3
    } else {
        0
    }
}

unsafe extern "C" fn default_write(
    _ptr: *mut c_char,
    size: usize,
    nmemb: usize,
    _userdata: *mut c_void,
) -> usize {
    size.saturating_mul(nmemb)
}

/// Parsed `https://[userinfo@]host[:port]/path` (http:// also for local tests).
///
/// `userinfo` is `user:pass` for HTTP Basic (GitHub: `x-access-token:gho_…` or
/// `oauth2:TOKEN`). Empty `userinfo_len` means unauthenticated.
struct ParsedUrl {
    https: bool,
    host: [u8; 256],
    host_len: usize,
    port: u16,
    /// Path beginning with `/` (default `/`).
    path: [u8; 2048],
    path_len: usize,
    /// Raw `user:password` (not base64); max 512 bytes.
    userinfo: [u8; 512],
    userinfo_len: usize,
}

fn parse_url(url: *const c_char) -> Option<ParsedUrl> {
    if url.is_null() || !ptr_live(url.cast()) {
        return None;
    }
    let n = unsafe { strlen(url) };
    if n == 0 || n > 4096 {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(url.cast::<u8>(), n) };
    let (https, rest) = if bytes.starts_with(b"https://") {
        (true, bytes.get(8..)?)
    } else if bytes.starts_with(b"http://") {
        (false, bytes.get(7..)?)
    } else {
        return None;
    };
    let slash = rest.iter().position(|&b| b == b'/').unwrap_or(rest.len());
    let authority = rest.get(..slash)?;
    let path_raw = rest.get(slash..).unwrap_or(b"/");
    if authority.is_empty() {
        return None;
    }

    // Optional userinfo: user[:pass]@host…
    let (userinfo_s, hostport) = if let Some(at) = authority.iter().position(|&b| b == b'@') {
        let ui = authority.get(..at)?;
        let hp = authority.get(at.saturating_add(1)..)?;
        if ui.is_empty() || hp.is_empty() {
            return None;
        }
        (ui, hp)
    } else {
        (&[][..], authority)
    };
    if userinfo_s.len() > 512 {
        return None;
    }

    // host[:port] — port only when suffix is all digits (not user:pass).
    let (host_s, port) = if let Some(colon) = hostport.iter().rposition(|&b| b == b':') {
        let h = hostport.get(..colon)?;
        let p = hostport.get(colon.saturating_add(1)..)?;
        if h.is_empty() {
            return None;
        }
        if !p.is_empty() && p.iter().all(u8::is_ascii_digit) {
            let mut v: u32 = 0;
            for &c in p {
                v = v.saturating_mul(10).saturating_add(u32::from(c - b'0'));
                if v > 65535 {
                    return None;
                }
            }
            (h, v as u16)
        } else {
            // Colon but not a port (unusual host) — treat whole as host.
            (hostport, 0)
        }
    } else {
        (hostport, 0)
    };
    if host_s.is_empty() || host_s.len() >= 256 {
        return None;
    }
    let mut out = ParsedUrl {
        https,
        host: [0; 256],
        host_len: host_s.len(),
        port: if port == 0 {
            if https {
                443
            } else {
                80
            }
        } else {
            port
        },
        path: [0; 2048],
        path_len: 0,
        userinfo: [0; 512],
        userinfo_len: userinfo_s.len(),
    };
    out.host[..host_s.len()].copy_from_slice(host_s);
    if !userinfo_s.is_empty() {
        out.userinfo[..userinfo_s.len()].copy_from_slice(userinfo_s);
    }
    let path = if path_raw.is_empty() { b"/" } else { path_raw };
    if path.len() >= out.path.len() {
        return None;
    }
    out.path[..path.len()].copy_from_slice(path);
    out.path_len = path.len();
    Some(out)
}

/// RFC 4648 base64 (no padding strip; always pads). Returns encoded length.
fn base64_encode(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    const T: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let n = src.len();
    let out_len = n.div_ceil(3).saturating_mul(4);
    if dst.len() < out_len {
        return None;
    }
    let mut o = 0_usize;
    let mut i = 0_usize;
    while i + 3 <= n {
        let b0 = src[i];
        let b1 = src[i + 1];
        let b2 = src[i + 2];
        dst[o] = T[(b0 >> 2) as usize];
        dst[o + 1] = T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
        dst[o + 2] = T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize];
        dst[o + 3] = T[(b2 & 0x3f) as usize];
        o = o.saturating_add(4);
        i = i.saturating_add(3);
    }
    let rem = n.saturating_sub(i);
    if rem == 1 {
        let b0 = src[i];
        dst[o] = T[(b0 >> 2) as usize];
        dst[o + 1] = T[((b0 & 0x03) << 4) as usize];
        dst[o + 2] = b'=';
        dst[o + 3] = b'=';
        o = o.saturating_add(4);
    } else if rem == 2 {
        let b0 = src[i];
        let b1 = src[i + 1];
        dst[o] = T[(b0 >> 2) as usize];
        dst[o + 1] = T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
        dst[o + 2] = T[((b1 & 0x0f) << 2) as usize];
        dst[o + 3] = b'=';
        o = o.saturating_add(4);
    }
    Some(o)
}

fn append_bytes(dst: &mut [u8], off: &mut usize, src: &[u8]) -> bool {
    let end = off.saturating_add(src.len());
    if end > dst.len() {
        return false;
    }
    dst[*off..end].copy_from_slice(src);
    *off = end;
    true
}

fn append_u64(dst: &mut [u8], off: &mut usize, mut v: u64) -> bool {
    let mut tmp = [0_u8; 20];
    let mut i = tmp.len();
    if v == 0 {
        i = i.saturating_sub(1);
        tmp[i] = b'0';
    } else {
        while v > 0 && i > 0 {
            i = i.saturating_sub(1);
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    append_bytes(dst, off, &tmp[i..])
}

fn header_line_has_name(line: &[u8], name: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let n = line.get(..colon).unwrap_or(&[]);
    if n.len() != name.len() {
        return false;
    }
    n.eq_ignore_ascii_case(name)
}

fn headers_contain(blob: &[u8], name: &[u8]) -> bool {
    for line in blob.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if header_line_has_name(line, name) {
            return true;
        }
    }
    false
}

/// Connect guest FD for freestanding HTTP(S): TLS (https) or plain TCP (http).
fn socket_connect_fd(easy: &Easy, host: &[u8], port: u16, https: bool) -> Result<c_int, c_int> {
    let mut err_local = [0_u8; ERRBUF_LEN];
    let mut out_fd: i32 = -1;
    let mut flags = 0_u32;
    if https {
        if easy.flags & EF_SSL_VERIFY != 0 {
            flags |= TLS_FLAG_VERIFY;
        }
    } else {
        flags |= TLS_FLAG_PLAIN;
    }
    let ca_path = if https && ptr_live(easy.ca_info.cast()) {
        easy.ca_info as u64
    } else {
        0
    };
    let req = KhTlsConnect {
        magic: KHTLS_MAGIC,
        version: 1,
        flags,
        port: u32::from(port),
        hostname: host.as_ptr() as u64,
        hostname_len: host.len() as u64,
        ca_path,
        out_fd: core::ptr::from_mut(&mut out_fd) as u64,
        errbuf: err_local.as_mut_ptr() as u64,
        errbuf_cap: ERRBUF_LEN as u64,
    };
    let rc = unsafe { sys::helper1(KH_HELPER_TLS_CONNECT, core::ptr::from_ref(&req) as u64) };
    if rc < 0 {
        let msg: &[u8] = if err_local[0] != 0 {
            &err_local
        } else if https {
            b"tls connect failed\0"
        } else {
            b"tcp connect failed\0"
        };
        set_err(easy, msg);
        return Err(match (-rc) as i32 {
            28 => CURLE_OPERATION_TIMEDOUT,
            35 => CURLE_SSL_CONNECT_ERROR,
            _ => CURLE_COULDNT_CONNECT,
        });
    }
    if out_fd < 0 {
        set_err(easy, b"connect bad fd\0");
        return Err(CURLE_COULDNT_CONNECT);
    }
    Ok(out_fd)
}

fn write_all_fd(fd: c_int, mut data: &[u8]) -> bool {
    while !data.is_empty() {
        let n = unsafe { write(fd, data.as_ptr().cast(), data.len()) };
        if n <= 0 {
            return false;
        }
        let nu = n as usize;
        if nu > data.len() {
            return false;
        }
        data = data.get(nu..).unwrap_or(&[]);
    }
    true
}

fn read_some_fd(fd: c_int, buf: &mut [u8]) -> isize {
    unsafe { read(fd, buf.as_mut_ptr().cast(), buf.len()) }
}

fn feed_write_cb(easy: &Easy, data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let write_cb = easy.write_fn.unwrap_or(default_write);
    let mut off = 0_usize;
    while off < data.len() {
        let chunk = data.len().saturating_sub(off).min(16 * 1024);
        let p = unsafe { data.as_ptr().add(off) };
        let n = unsafe { write_cb(p.cast_mut().cast(), 1, chunk, easy.write_data) };
        if n != chunk {
            return false;
        }
        off = off.saturating_add(chunk);
    }
    true
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i.saturating_add(4))
}

fn parse_status_code(hdr: &[u8]) -> u32 {
    // HTTP/1.x NNN
    let line = hdr.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.split(|&b| b == b' ');
    let _ = parts.next();
    let code = parts.next().unwrap_or(&[]);
    let mut v: u32 = 0;
    for &c in code {
        if !c.is_ascii_digit() {
            break;
        }
        v = v.saturating_mul(10).saturating_add(u32::from(c - b'0'));
    }
    v
}

fn header_value<'a>(hdr: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    for line in hdr.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if !header_line_has_name(line, name) {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let mut v = line.get(colon.saturating_add(1)..)?;
        while v.first() == Some(&b' ') || v.first() == Some(&b'\t') {
            v = v.get(1..)?;
        }
        // Trim parameters for Content-Type (`type/sub; charset`).
        if name.eq_ignore_ascii_case(b"content-type") {
            if let Some(semi) = v.iter().position(|&b| b == b';') {
                v = v.get(..semi)?;
            }
            while v.last() == Some(&b' ') {
                v = v.get(..v.len().saturating_sub(1))?;
            }
        }
        return Some(v);
    }
    None
}

fn parse_content_length(hdr: &[u8]) -> Option<u64> {
    let v = header_value(hdr, b"content-length")?;
    let mut n: u64 = 0;
    for &c in v {
        if !c.is_ascii_digit() {
            break;
        }
        n = n.saturating_mul(10).saturating_add(u64::from(c - b'0'));
    }
    Some(n)
}

fn is_chunked(hdr: &[u8]) -> bool {
    header_value(hdr, b"transfer-encoding")
        .is_some_and(|v| v.windows(7).any(|w| w.eq_ignore_ascii_case(b"chunked")))
}

fn perform_easy(easy: &mut Easy) -> c_int {
    if easy.url.is_null() || !ptr_live(easy.url.cast()) {
        set_err(easy, b"no URL set\0");
        easy.result = CURLE_URL_MALFORMAT;
        easy.flags |= EF_DONE;
        return easy.result;
    }

    let Some(url) = parse_url(easy.url) else {
        set_err(easy, b"URL malformat\0");
        easy.result = CURLE_URL_MALFORMAT;
        easy.flags |= EF_DONE;
        return easy.result;
    };

    // Path B: HTTP/1.1 over host TCP guest FD (rustls for https://, plain for http://).
    let host = &url.host[..url.host_len];
    let fd = match socket_connect_fd(easy, host, url.port, url.https) {
        Ok(f) => f,
        Err(code) => {
            easy.result = code;
            easy.flags |= EF_DONE;
            return easy.result;
        }
    };

    let result = perform_http_on_fd(easy, fd, &url);
    let _ = unsafe { close(fd) };
    easy.result = result;
    easy.flags |= EF_DONE;
    if result == CURLE_OK {
        free_cstr(easy.effective_url);
        easy.effective_url = dup_cstr(easy.url).unwrap_or(ptr::null_mut());
    }
    result
}

/// Gathered POST/PUT body: optional freestanding-owned buffer.
struct PostBody {
    ptr: *const u8,
    len: usize,
    /// When true, `ptr` was allocated with freestanding `malloc` and must be freed.
    owned: bool,
}

impl PostBody {
    fn empty() -> Self {
        Self {
            ptr: ptr::null(),
            len: 0,
            owned: false,
        }
    }

    fn as_slice(&self) -> &[u8] {
        if self.ptr.is_null() || self.len == 0 {
            return &[];
        }
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn free_owned(&mut self) {
        if self.owned && !self.ptr.is_null() {
            unsafe {
                free(self.ptr.cast_mut().cast());
            }
        }
        self.ptr = ptr::null();
        self.len = 0;
        self.owned = false;
    }
}

/// Collect POSTFIELDS or READFUNCTION into a contiguous buffer.
fn gather_post_body(easy: &Easy) -> Result<PostBody, c_int> {
    if ptr_live(easy.post_fields) {
        let len = if easy.post_field_size >= 0 {
            usize::try_from(easy.post_field_size).unwrap_or(0)
        } else {
            unsafe { strlen(easy.post_fields.cast()) }
        };
        if len > MAX_POST_GATHER {
            return Err(CURLE_OUT_OF_MEMORY);
        }
        return Ok(PostBody {
            ptr: easy.post_fields.cast::<u8>(),
            len,
            owned: false,
        });
    }

    let Some(read_cb) = easy.read_fn else {
        // POST with empty body is allowed (Content-Length: 0).
        return Ok(PostBody::empty());
    };

    // READFUNCTION path (git large want-lists when postBuffer is exceeded).
    let known = if easy.post_field_size >= 0 {
        usize::try_from(easy.post_field_size).unwrap_or(0)
    } else {
        0
    };
    if known > MAX_POST_GATHER {
        return Err(CURLE_OUT_OF_MEMORY);
    }

    let mut cap = if known > 0 {
        known
    } else {
        64 * 1024
    };
    cap = cap.clamp(1, MAX_POST_GATHER);
    let mut buf = unsafe { malloc(cap) }.cast::<u8>();
    if buf.is_null() {
        return Err(CURLE_OUT_OF_MEMORY);
    }
    let mut filled = 0_usize;
    loop {
        if known > 0 && filled >= known {
            break;
        }
        if filled >= cap {
            if known > 0 || cap >= MAX_POST_GATHER {
                unsafe {
                    free(buf.cast());
                }
                return Err(CURLE_OUT_OF_MEMORY);
            }
            let new_cap = cap.saturating_mul(2).min(MAX_POST_GATHER).max(cap.saturating_add(1));
            let nbuf = unsafe { realloc(buf.cast(), new_cap) }.cast::<u8>();
            if nbuf.is_null() {
                unsafe {
                    free(buf.cast());
                }
                return Err(CURLE_OUT_OF_MEMORY);
            }
            buf = nbuf;
            cap = new_cap;
        }
        let space = if known > 0 {
            known.saturating_sub(filled).min(cap.saturating_sub(filled))
        } else {
            cap.saturating_sub(filled)
        };
        if space == 0 {
            break;
        }
        let dest = unsafe { buf.add(filled) };
        let n = unsafe { read_cb(dest.cast(), 1, space, easy.read_data) };
        if n == 0 {
            break;
        }
        if n > space {
            unsafe {
                free(buf.cast());
            }
            return Err(CURLE_BAD_FUNCTION_ARGUMENT);
        }
        filled = filled.saturating_add(n);
    }
    if filled == 0 {
        unsafe {
            free(buf.cast());
        }
        return Ok(PostBody::empty());
    }
    Ok(PostBody {
        ptr: buf.cast_const(),
        len: filled,
        owned: true,
    })
}

/// If guest claims `Content-Encoding: gzip` but body is zlib (Apple git), decode
/// and strip the header so GitHub accepts the upload-pack POST.
fn maybe_decode_claim_gzip(user_hdrs: &[u8], body: &mut PostBody) -> bool {
    let Some(ce) = header_value(user_hdrs, b"content-encoding") else {
        return false;
    };
    if !ce.eq_ignore_ascii_case(b"gzip") {
        return false;
    }
    let src = body.as_slice();
    if src.is_empty() {
        return true; // still strip empty CE
    }
    let Some((p, n)) = crate::zlib::inflate_to_malloc(src) else {
        // Keep wire body but still strip CE — better than advertising false gzip.
        return true;
    };
    body.free_owned();
    body.ptr = p.cast_const();
    body.len = n;
    body.owned = true;
    true
}

fn perform_http_on_fd(easy: &mut Easy, fd: c_int, url: &ParsedUrl) -> c_int {
    let mut body = match gather_post_body(easy) {
        Ok(b) => b,
        Err(code) => {
            set_err(easy, b"post body gather failed\0");
            return code;
        }
    };

    let mut hdr_storage = [0_u8; MAX_HDR_BLOB];
    let hdr_len = headers_blob(easy.headers, &mut hdr_storage);
    let user_hdrs = &hdr_storage[..hdr_len];
    let strip_ce = maybe_decode_claim_gzip(user_hdrs, &mut body);
    let post_len = body.len as u64;

    // Build request line + headers + body into one buffer when body is small;
    // large POST bodies are rare for git want-lists (usually <1 MiB).
    let method: &[u8] = match method_of(easy) {
        1 => b"POST",
        2 => b"HEAD",
        3 => b"PUT",
        _ => b"GET",
    };

    // Request buffer: method SP path SP HTTP/1.1 CRLF + headers + CRLF + optional body.
    let est = method
        .len()
        .saturating_add(1)
        .saturating_add(url.path_len)
        .saturating_add(16)
        .saturating_add(hdr_len)
        .saturating_add(256)
        .saturating_add(body.len);
    let req_cap = est.saturating_add(64);
    let req_buf = unsafe { malloc(req_cap) }.cast::<u8>();
    if req_buf.is_null() {
        body.free_owned();
        set_err(easy, b"oom request\0");
        return CURLE_OUT_OF_MEMORY;
    }
    let req_slice = unsafe { core::slice::from_raw_parts_mut(req_buf, req_cap) };
    let mut off = 0_usize;
    let ok = append_bytes(req_slice, &mut off, method)
        && append_bytes(req_slice, &mut off, b" ")
        && append_bytes(req_slice, &mut off, &url.path[..url.path_len])
        && append_bytes(req_slice, &mut off, b" HTTP/1.1\r\n");
    if !ok {
        unsafe {
            free(req_buf.cast());
        }
        body.free_owned();
        set_err(easy, b"request too large\0");
        return CURLE_OUT_OF_MEMORY;
    }

    if !headers_contain(user_hdrs, b"host") {
        let _ = append_bytes(req_slice, &mut off, b"Host: ");
        let _ = append_bytes(req_slice, &mut off, &url.host[..url.host_len]);
        if url.port != 443 && url.port != 80 {
            let _ = append_bytes(req_slice, &mut off, b":");
            let _ = append_u64(req_slice, &mut off, u64::from(url.port));
        }
        let _ = append_bytes(req_slice, &mut off, b"\r\n");
    }
    // URL userinfo → HTTP Basic (git often embeds x-access-token:… for HTTPS).
    if url.userinfo_len > 0 && !headers_contain(user_hdrs, b"authorization") {
        let mut b64 = [0_u8; 700];
        let Some(b64_n) = base64_encode(&url.userinfo[..url.userinfo_len], &mut b64) else {
            unsafe {
                free(req_buf.cast());
            }
            body.free_owned();
            set_err(easy, b"auth encode overflow\0");
            return CURLE_OUT_OF_MEMORY;
        };
        if !append_bytes(req_slice, &mut off, b"Authorization: Basic ")
            || !append_bytes(req_slice, &mut off, &b64[..b64_n])
            || !append_bytes(req_slice, &mut off, b"\r\n")
        {
            unsafe {
                free(req_buf.cast());
            }
            body.free_owned();
            set_err(easy, b"auth header overflow\0");
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if !headers_contain(user_hdrs, b"user-agent") {
        if ptr_live(easy.user_agent.cast()) {
            let ua_n = unsafe { strlen(easy.user_agent) };
            let ua = unsafe { core::slice::from_raw_parts(easy.user_agent.cast::<u8>(), ua_n) };
            let _ = append_bytes(req_slice, &mut off, b"User-Agent: ");
            let _ = append_bytes(req_slice, &mut off, ua);
            let _ = append_bytes(req_slice, &mut off, b"\r\n");
        } else {
            let _ = append_bytes(req_slice, &mut off, b"User-Agent: kakehashi-libcurl\r\n");
        }
    }
    // Forward guest headers; skip hop-by-hop framing (we set Content-Length).
    // Also drop Content-Encoding when we decoded a false "gzip" (zlib) body.
    for line in user_hdrs.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if header_line_has_name(line, b"content-length")
            || header_line_has_name(line, b"transfer-encoding")
            || header_line_has_name(line, b"connection")
            || (strip_ce && header_line_has_name(line, b"content-encoding"))
        {
            continue;
        }
        if !append_bytes(req_slice, &mut off, line) || !append_bytes(req_slice, &mut off, b"\r\n") {
            unsafe {
                free(req_buf.cast());
            }
            body.free_owned();
            set_err(easy, b"request headers overflow\0");
            return CURLE_OUT_OF_MEMORY;
        }
    }
    if method_of(easy) == 1 || method_of(easy) == 3 || post_len > 0 {
        let _ = append_bytes(req_slice, &mut off, b"Content-Length: ");
        let _ = append_u64(req_slice, &mut off, post_len);
        let _ = append_bytes(req_slice, &mut off, b"\r\n");
    }
    let _ = append_bytes(req_slice, &mut off, b"Connection: close\r\n\r\n");

    if post_len > 0 {
        let body_bytes = body.as_slice();
        if !append_bytes(req_slice, &mut off, body_bytes) {
            unsafe {
                free(req_buf.cast());
            }
            body.free_owned();
            set_err(easy, b"post body overflow\0");
            return CURLE_OUT_OF_MEMORY;
        }
    }
    body.free_owned();

    let req_bytes = &req_slice[..off];
    if !write_all_fd(fd, req_bytes) {
        unsafe {
            free(req_buf.cast());
        }
        set_err(easy, b"send request failed\0");
        return CURLE_COULDNT_CONNECT;
    }
    unsafe {
        free(req_buf.cast());
    }

    // Read response headers (and possibly first body bytes).
    let hdr_buf = unsafe { malloc(MAX_RESP_HDR) }.cast::<u8>();
    if hdr_buf.is_null() {
        set_err(easy, b"oom response headers\0");
        return CURLE_OUT_OF_MEMORY;
    }
    let mut hdr_filled = 0_usize;
    let mut header_end = None;
    while header_end.is_none() {
        if hdr_filled >= MAX_RESP_HDR {
            unsafe {
                free(hdr_buf.cast());
            }
            set_err(easy, b"response headers too large\0");
            return CURLE_COULDNT_CONNECT;
        }
        let space = MAX_RESP_HDR.saturating_sub(hdr_filled);
        let dest = unsafe { core::slice::from_raw_parts_mut(hdr_buf.add(hdr_filled), space) };
        let n = read_some_fd(fd, dest);
        if n <= 0 {
            unsafe {
                free(hdr_buf.cast());
            }
            set_err(easy, b"read response headers failed\0");
            return CURLE_COULDNT_CONNECT;
        }
        hdr_filled = hdr_filled.saturating_add(n as usize);
        let view = unsafe { core::slice::from_raw_parts(hdr_buf, hdr_filled) };
        header_end = find_header_end(view);
    }
    let hend = header_end.unwrap_or(hdr_filled);
    let hdr_view = unsafe { core::slice::from_raw_parts(hdr_buf, hend) };
    let http_code = parse_status_code(hdr_view);
    easy.response_code = c_long::from(http_code);

    free_cstr(easy.content_type);
    easy.content_type = if let Some(ct) = header_value(hdr_view, b"content-type") {
        let mut tmp = [0_u8; 128];
        let n = ct.len().min(tmp.len().saturating_sub(1));
        tmp[..n].copy_from_slice(&ct[..n]);
        tmp[n] = 0;
        dup_cstr(tmp.as_ptr().cast()).unwrap_or(ptr::null_mut())
    } else {
        ptr::null_mut()
    };

    if easy.flags & EF_FAIL != 0 && http_code >= 400 {
        unsafe {
            free(hdr_buf.cast());
        }
        set_err(easy, b"HTTP error\0");
        return CURLE_HTTP_RETURNED_ERROR;
    }

    // Body starts after headers; may already be buffered.
    let mut pending =
        unsafe { core::slice::from_raw_parts(hdr_buf.add(hend), hdr_filled.saturating_sub(hend)) };
    let mut download: u64 = 0;

    let body_rc = if method_of(easy) == 2 {
        // HEAD — no body.
        CURLE_OK
    } else if is_chunked(hdr_view) {
        stream_chunked_body(easy, fd, &mut pending, hdr_buf, &mut download)
    } else if let Some(clen) = parse_content_length(hdr_view) {
        stream_fixed_body(easy, fd, &mut pending, clen, &mut download)
    } else {
        // Connection: close / EOF delimited.
        stream_until_eof(easy, fd, &mut pending, &mut download)
    };

    unsafe {
        free(hdr_buf.cast());
    }
    easy.download_size = download as i64;
    body_rc
}

fn stream_fixed_body(
    easy: &Easy,
    fd: c_int,
    pending: &mut &[u8],
    content_len: u64,
    download: &mut u64,
) -> c_int {
    let mut left = content_len;
    if !pending.is_empty() {
        let take = (pending.len() as u64).min(left) as usize;
        let chunk = &pending[..take];
        if !feed_write_cb(easy, chunk) {
            set_err(easy, b"write callback short\0");
            return CURLE_WRITE_ERROR;
        }
        *download = download.saturating_add(take as u64);
        left = left.saturating_sub(take as u64);
        *pending = pending.get(take..).unwrap_or(&[]);
    }
    let mut buf = [0_u8; IO_CHUNK];
    while left > 0 {
        let want = (left as usize).min(buf.len());
        let n = read_some_fd(fd, &mut buf[..want]);
        if n <= 0 {
            set_err(easy, b"short body read\0");
            return CURLE_COULDNT_CONNECT;
        }
        let nu = n as usize;
        if !feed_write_cb(easy, &buf[..nu]) {
            set_err(easy, b"write callback short\0");
            return CURLE_WRITE_ERROR;
        }
        *download = download.saturating_add(nu as u64);
        left = left.saturating_sub(nu as u64);
    }
    CURLE_OK
}

fn stream_until_eof(easy: &Easy, fd: c_int, pending: &mut &[u8], download: &mut u64) -> c_int {
    if !pending.is_empty() {
        if !feed_write_cb(easy, pending) {
            set_err(easy, b"write callback short\0");
            return CURLE_WRITE_ERROR;
        }
        *download = download.saturating_add(pending.len() as u64);
        *pending = &[];
    }
    let mut buf = [0_u8; IO_CHUNK];
    loop {
        let n = read_some_fd(fd, &mut buf);
        if n == 0 {
            return CURLE_OK;
        }
        if n < 0 {
            set_err(easy, b"body read error\0");
            return CURLE_COULDNT_CONNECT;
        }
        let nu = n as usize;
        if !feed_write_cb(easy, &buf[..nu]) {
            set_err(easy, b"write callback short\0");
            return CURLE_WRITE_ERROR;
        }
        *download = download.saturating_add(nu as u64);
    }
}

/// Chunked transfer decoding (HTTP/1.1).
fn stream_chunked_body(
    easy: &Easy,
    fd: c_int,
    pending: &mut &[u8],
    // hdr_buf still owns the storage behind `pending` — only used if we need
    // a scratch; pending is a subslice of it. We re-buffer into a local ring.
    _hdr_buf: *mut u8,
    download: &mut u64,
) -> c_int {
    // Copy any pre-buffered body into a growable-ish fixed scratch.
    let mut scratch = [0_u8; IO_CHUNK.saturating_mul(2)];
    let mut scratch_len = 0_usize;
    if !pending.is_empty() {
        let n = pending.len().min(scratch.len());
        scratch[..n].copy_from_slice(&pending[..n]);
        scratch_len = n;
        *pending = &[];
    }

    loop {
        // Ensure we have a full chunk-size line.
        let line_end = loop {
            if let Some(i) = scratch[..scratch_len].windows(2).position(|w| w == b"\r\n") {
                break i;
            }
            if scratch_len >= scratch.len() {
                set_err(easy, b"chunk size line too long\0");
                return CURLE_COULDNT_CONNECT;
            }
            let n = read_some_fd(fd, &mut scratch[scratch_len..]);
            if n <= 0 {
                set_err(easy, b"chunk size read fail\0");
                return CURLE_COULDNT_CONNECT;
            }
            scratch_len = scratch_len.saturating_add(n as usize);
        };
        let size_line = &scratch[..line_end];
        // Ignore chunk extensions after `;`.
        let hex = size_line.split(|&b| b == b';').next().unwrap_or(size_line);
        let mut size: u64 = 0;
        for &c in hex {
            let dig = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                b' ' | b'\t' => continue,
                _ => {
                    set_err(easy, b"bad chunk size\0");
                    return CURLE_COULDNT_CONNECT;
                }
            };
            size = (size << 4) | u64::from(dig);
        }
        // Consume size line + CRLF.
        let after = line_end.saturating_add(2);
        if after > scratch_len {
            set_err(easy, b"chunk parse bug\0");
            return CURLE_COULDNT_CONNECT;
        }
        scratch.copy_within(after..scratch_len, 0);
        scratch_len = scratch_len.saturating_sub(after);

        if size == 0 {
            // Trailer headers until blank line — drain and done.
            loop {
                if let Some(i) = scratch[..scratch_len]
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                {
                    let _ = i;
                    return CURLE_OK;
                }
                if scratch[..scratch_len] == *b"\r\n" {
                    return CURLE_OK;
                }
                // Need more trailer data.
                if scratch_len >= scratch.len() {
                    // Compact: keep last few bytes.
                    scratch_len = 0;
                }
                let n = read_some_fd(fd, &mut scratch[scratch_len..]);
                if n <= 0 {
                    return CURLE_OK;
                }
                scratch_len = scratch_len.saturating_add(n as usize);
                // Empty trailer is just CRLF after last chunk.
                if scratch_len >= 2 && &scratch[..2] == b"\r\n" {
                    return CURLE_OK;
                }
            }
        }

        let mut left = size;
        while left > 0 {
            if scratch_len == 0 {
                let want = (left as usize).min(scratch.len());
                let n = read_some_fd(fd, &mut scratch[..want]);
                if n <= 0 {
                    set_err(easy, b"chunk data short\0");
                    return CURLE_COULDNT_CONNECT;
                }
                scratch_len = n as usize;
            }
            let take = (left as usize).min(scratch_len);
            if !feed_write_cb(easy, &scratch[..take]) {
                set_err(easy, b"write callback short\0");
                return CURLE_WRITE_ERROR;
            }
            *download = download.saturating_add(take as u64);
            left = left.saturating_sub(take as u64);
            scratch.copy_within(take..scratch_len, 0);
            scratch_len = scratch_len.saturating_sub(take);
        }
        // Trailing CRLF after chunk data.
        loop {
            if scratch_len >= 2 {
                if &scratch[..2] == b"\r\n" {
                    scratch.copy_within(2..scratch_len, 0);
                    scratch_len = scratch_len.saturating_sub(2);
                    break;
                }
                set_err(easy, b"bad chunk trailer\0");
                return CURLE_COULDNT_CONNECT;
            }
            let n = read_some_fd(fd, &mut scratch[scratch_len..]);
            if n <= 0 {
                set_err(easy, b"chunk trailer read fail\0");
                return CURLE_COULDNT_CONNECT;
            }
            scratch_len = scratch_len.saturating_add(n as usize);
        }
    }
}

// ── exports (no_mangle C ABI; `pub(crate)` like zlib.rs) ─────────────────────

/// C `curl_global_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_global_init(_flags: c_long) -> c_int {
    GLOBAL_INITS.fetch_add(1, Ordering::Relaxed);
    ensure_version_info();
    CURLE_OK
}

/// C `curl_global_cleanup`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_global_cleanup() {
    let _ = GLOBAL_INITS.fetch_sub(1, Ordering::Relaxed);
}

/// C `curl_global_sslset`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_global_sslset(
    _id: c_int,
    _name: *const c_char,
    _avail: *mut *const c_void,
) -> c_int {
    CURLSSLSET_OK
}

/// C `curl_version_info`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_version_info(_age: c_int) -> *const c_void {
    ensure_version_info();
    core::ptr::addr_of!(VERSION_INFO).cast()
}

/// C `curl_easy_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_easy_init() -> *mut c_void {
    let p = unsafe { malloc(core::mem::size_of::<Easy>()) }.cast::<Easy>();
    if p.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::write(
            p,
            Easy {
                magic: MAGIC_EASY,
                _pad: 0,
                url: ptr::null_mut(),
                custom_request: ptr::null_mut(),
                user_agent: ptr::null_mut(),
                ca_info: ptr::null_mut(),
                post_fields: ptr::null(),
                post_field_size: -1,
                headers: ptr::null_mut(),
                write_fn: None,
                write_data: ptr::null_mut(),
                read_fn: None,
                read_data: ptr::null_mut(),
                error_buffer: ptr::null_mut(),
                flags: EF_SSL_VERIFY,
                response_code: 0,
                result: CURLE_OK,
                download_size: 0,
                effective_url: ptr::null_mut(),
                content_type: ptr::null_mut(),
            },
        );
    }
    p.cast()
}

/// C `curl_easy_cleanup`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_easy_cleanup(curl: *mut c_void) {
    let Some(easy) = easy_from(curl) else {
        return;
    };
    free_cstr(easy.url);
    free_cstr(easy.custom_request);
    free_cstr(easy.user_agent);
    free_cstr(easy.ca_info);
    free_cstr(easy.effective_url);
    free_cstr(easy.content_type);
    easy.magic = 0;
    unsafe {
        free(curl.cast());
    }
}

/// C `curl_easy_duphandle`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_easy_duphandle(curl: *mut c_void) -> *mut c_void {
    let Some(src) = easy_from(curl) else {
        return ptr::null_mut();
    };
    let dst = unsafe { curl_easy_init() };
    let Some(d) = easy_from(dst) else {
        return ptr::null_mut();
    };
    d.url = dup_cstr(src.url).unwrap_or(ptr::null_mut());
    d.custom_request = dup_cstr(src.custom_request).unwrap_or(ptr::null_mut());
    d.user_agent = dup_cstr(src.user_agent).unwrap_or(ptr::null_mut());
    d.ca_info = dup_cstr(src.ca_info).unwrap_or(ptr::null_mut());
    d.post_fields = src.post_fields;
    d.post_field_size = src.post_field_size;
    d.headers = src.headers;
    d.write_fn = src.write_fn;
    d.write_data = src.write_data;
    d.read_fn = src.read_fn;
    d.read_data = src.read_data;
    d.error_buffer = src.error_buffer;
    d.flags = src.flags & !EF_DONE;
    dst
}

/// Impl for C `curl_easy_setopt` (see `curl_varargs.c` — Apple arm64 stacks the value).
///
/// # Safety
///
/// `param` is the first variadic slot: pointer, `long`, or function pointer.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_curl_easy_setopt_impl(
    curl: *mut c_void,
    option: c_int,
    param: u64,
) -> c_int {
    let Some(easy) = easy_from(curl) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    let as_ptr = param as *mut c_void;
    let as_long = param as c_long;
    match option {
        CURLOPT_URL => {
            free_cstr(easy.url);
            easy.url = match dup_cstr(as_ptr.cast()) {
                Some(p) => p,
                None => return CURLE_OUT_OF_MEMORY,
            };
        }
        CURLOPT_WRITEDATA => easy.write_data = as_ptr,
        CURLOPT_WRITEFUNCTION => {
            easy.write_fn = if param == 0 {
                None
            } else {
                // SAFETY: guest passes a C function pointer matching WriteCb.
                Some(unsafe { core::mem::transmute::<u64, WriteCb>(param) })
            };
        }
        CURLOPT_READDATA => easy.read_data = as_ptr,
        CURLOPT_READFUNCTION => {
            easy.read_fn = if param == 0 {
                None
            } else {
                Some(unsafe { core::mem::transmute::<u64, ReadCb>(param) })
            };
        }
        CURLOPT_ERRORBUFFER => {
            easy.error_buffer = if ptr_live(as_ptr.cast_const()) {
                as_ptr.cast()
            } else {
                ptr::null_mut()
            };
        }
        CURLOPT_HTTPHEADER => {
            // Reject PAGEZERO / garbage from a broken caller; null clears.
            easy.headers = if param == 0 || !ptr_live(as_ptr.cast_const()) {
                ptr::null_mut()
            } else {
                as_ptr.cast()
            };
        }
        CURLOPT_POSTFIELDS | CURLOPT_COPYPOSTFIELDS => {
            easy.post_fields = if param == 0 || !ptr_live(as_ptr.cast_const()) {
                ptr::null()
            } else {
                as_ptr.cast_const()
            };
            easy.flags |= EF_POST;
        }
        CURLOPT_POSTFIELDSIZE => easy.post_field_size = as_long,
        CURLOPT_POSTFIELDSIZE_LARGE => easy.post_field_size = param as i64,
        CURLOPT_POST => {
            if as_long != 0 {
                easy.flags |= EF_POST;
            } else {
                easy.flags &= !EF_POST;
            }
        }
        CURLOPT_HTTPGET => {
            if as_long != 0 {
                easy.flags &= !(EF_POST | EF_PUT | EF_UPLOAD);
            }
        }
        CURLOPT_NOBODY => {
            if as_long != 0 {
                easy.flags |= EF_NOBODY;
            } else {
                easy.flags &= !EF_NOBODY;
            }
        }
        CURLOPT_PUT => {
            if as_long != 0 {
                easy.flags |= EF_PUT;
            } else {
                easy.flags &= !EF_PUT;
            }
        }
        CURLOPT_UPLOAD => {
            if as_long != 0 {
                easy.flags |= EF_UPLOAD;
            } else {
                easy.flags &= !EF_UPLOAD;
            }
        }
        CURLOPT_FAILONERROR => {
            if as_long != 0 {
                easy.flags |= EF_FAIL;
            } else {
                easy.flags &= !EF_FAIL;
            }
        }
        CURLOPT_SSL_VERIFYPEER => {
            if as_long != 0 {
                easy.flags |= EF_SSL_VERIFY;
            } else {
                easy.flags &= !EF_SSL_VERIFY;
            }
        }
        CURLOPT_CAINFO => {
            free_cstr(easy.ca_info);
            easy.ca_info = match dup_cstr(as_ptr.cast()) {
                Some(p) => p,
                None => return CURLE_OUT_OF_MEMORY,
            };
        }
        CURLOPT_USERAGENT => {
            free_cstr(easy.user_agent);
            easy.user_agent = match dup_cstr(as_ptr.cast()) {
                Some(p) => p,
                None => return CURLE_OUT_OF_MEMORY,
            };
        }
        CURLOPT_CUSTOMREQUEST => {
            free_cstr(easy.custom_request);
            easy.custom_request = match dup_cstr(as_ptr.cast()) {
                Some(p) => p,
                None => return CURLE_OUT_OF_MEMORY,
            };
        }
        // Soft-accept FOLLOWLOCATION and all other options (newer git).
        _ => {}
    }
    CURLE_OK
}

/// Impl for C `curl_easy_getinfo` (see `curl_varargs.c`).
///
/// # Safety
///
/// `param` is a guest pointer to the out-slot for the requested info type.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_curl_easy_getinfo_impl(
    curl: *mut c_void,
    info: c_int,
    param: u64,
) -> c_int {
    let Some(easy) = easy_from(curl) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    if param == 0 || !ptr_live(param as *const c_void) {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    match info {
        CURLINFO_RESPONSE_CODE => unsafe {
            *(param as *mut c_long) = easy.response_code;
        },
        CURLINFO_EFFECTIVE_URL => {
            let url = if easy.effective_url.is_null() {
                easy.url
            } else {
                easy.effective_url
            };
            unsafe {
                *(param as *mut *mut c_char) = url;
            }
        }
        CURLINFO_CONTENT_TYPE => unsafe {
            *(param as *mut *mut c_char) = easy.content_type;
        },
        CURLINFO_SIZE_DOWNLOAD => unsafe {
            *(param as *mut f64) = easy.download_size as f64;
        },
        CURLINFO_SIZE_DOWNLOAD_T => unsafe {
            *(param as *mut i64) = easy.download_size;
        },
        _ => {
            // Soft zeros for unused infos.
            if (info & CURLINFO_DOUBLE) == CURLINFO_DOUBLE {
                unsafe {
                    *(param as *mut f64) = 0.0;
                }
            } else if (info & CURLINFO_LONG) == CURLINFO_LONG {
                unsafe {
                    *(param as *mut c_long) = 0;
                }
            } else if (info & CURLINFO_OFF_T) == CURLINFO_OFF_T {
                unsafe {
                    *(param as *mut i64) = 0;
                }
            } else if (info & CURLINFO_STRING) == CURLINFO_STRING {
                unsafe {
                    *(param as *mut *mut c_void) = ptr::null_mut();
                }
            }
        }
    }
    CURLE_OK
}

/// C `curl_easy_perform`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_easy_perform(curl: *mut c_void) -> c_int {
    let Some(easy) = easy_from(curl) else {
        return CURLE_BAD_FUNCTION_ARGUMENT;
    };
    easy.flags &= !EF_DONE;
    perform_easy(easy)
}

/// C `curl_easy_strerror`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_easy_strerror(code: c_int) -> *const c_char {
    match code {
        CURLE_OK => b"No error\0".as_ptr().cast(),
        CURLE_URL_MALFORMAT => b"URL malformed\0".as_ptr().cast(),
        CURLE_COULDNT_CONNECT => b"Could not connect\0".as_ptr().cast(),
        CURLE_HTTP_RETURNED_ERROR => b"HTTP response code said error\0".as_ptr().cast(),
        CURLE_WRITE_ERROR => b"Failed writing received data\0".as_ptr().cast(),
        CURLE_OUT_OF_MEMORY => b"Out of memory\0".as_ptr().cast(),
        CURLE_OPERATION_TIMEDOUT => b"Timeout\0".as_ptr().cast(),
        CURLE_SSL_CONNECT_ERROR => b"SSL connect error\0".as_ptr().cast(),
        _ => b"curl error\0".as_ptr().cast(),
    }
}

/// C `curl_slist_append`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_slist_append(
    list: *mut c_void,
    data: *const c_char,
) -> *mut c_void {
    let node = unsafe { malloc(core::mem::size_of::<Slist>()) }.cast::<Slist>();
    if node.is_null() {
        return ptr::null_mut();
    }
    let Some(dup) = dup_cstr(data) else {
        unsafe {
            free(node.cast());
        }
        return ptr::null_mut();
    };
    unsafe {
        ptr::write(
            node,
            Slist {
                magic: MAGIC_SLIST,
                data: dup,
                next: ptr::null_mut(),
            },
        );
    }
    if list.is_null() || list.addr() < crate::stdio::PAGEZERO_END {
        return node.cast();
    }
    let mut cur = list.cast::<Slist>();
    let mut guard = 0_usize;
    loop {
        if !ptr_live(cur.cast()) {
            break;
        }
        let n = unsafe { &mut *cur };
        if n.magic != MAGIC_SLIST {
            break;
        }
        if n.next.is_null() {
            n.next = node;
            break;
        }
        if !ptr_live(n.next.cast()) {
            n.next = node;
            break;
        }
        cur = n.next;
        guard = guard.saturating_add(1);
        if guard > 10_000 {
            break;
        }
    }
    list
}

/// C `curl_slist_free_all`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_slist_free_all(list: *mut c_void) {
    let mut cur = list.cast::<Slist>();
    let mut guard = 0_usize;
    while ptr_live(cur.cast()) {
        let node = unsafe { &mut *cur };
        if node.magic != MAGIC_SLIST {
            break;
        }
        let next = node.next;
        free_cstr(node.data);
        node.magic = 0;
        unsafe {
            free(cur.cast());
        }
        cur = next;
        guard = guard.saturating_add(1);
        if guard > 10_000 {
            break;
        }
    }
}

/// C `curl_multi_init`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_init() -> *mut c_void {
    let p = unsafe { malloc(core::mem::size_of::<Multi>()) }.cast::<Multi>();
    if p.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::write(
            p,
            Multi {
                magic: MAGIC_MULTI,
                entries: ptr::null_mut(),
                n_entries: 0,
                cap_entries: 0,
                last_msg: CurlMsg {
                    msg: 0,
                    _pad: 0,
                    easy_handle: ptr::null_mut(),
                    data_result: 0,
                },
            },
        );
    }
    p.cast()
}

/// C `curl_multi_cleanup`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_cleanup(multi: *mut c_void) -> c_int {
    let Some(m) = multi_from(multi) else {
        return CURLM_BAD_HANDLE;
    };
    if !m.entries.is_null() {
        unsafe {
            free(m.entries.cast());
        }
    }
    m.magic = 0;
    unsafe {
        free(multi.cast());
    }
    CURLM_OK
}

/// C `curl_multi_add_handle`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_add_handle(
    multi: *mut c_void,
    easy: *mut c_void,
) -> c_int {
    let Some(m) = multi_from(multi) else {
        return CURLM_BAD_HANDLE;
    };
    let Some(e) = easy_from(easy) else {
        return CURLM_BAD_EASY_HANDLE;
    };
    e.flags &= !EF_DONE;
    e.result = CURLE_OK;
    if m.n_entries == m.cap_entries {
        let new_cap = if m.cap_entries == 0 {
            4
        } else {
            m.cap_entries.saturating_mul(2)
        };
        let nbytes = new_cap.saturating_mul(core::mem::size_of::<MultiEntry>());
        let p = if m.entries.is_null() {
            unsafe { malloc(nbytes) }
        } else {
            unsafe { realloc(m.entries.cast(), nbytes) }
        }
        .cast::<MultiEntry>();
        if p.is_null() {
            return CURLM_OUT_OF_MEMORY;
        }
        m.entries = p;
        m.cap_entries = new_cap;
    }
    unsafe {
        ptr::write(
            m.entries.add(m.n_entries),
            MultiEntry {
                easy: core::ptr::from_mut(e),
                done: false,
                result: CURLE_OK,
                msg_delivered: false,
            },
        );
    }
    m.n_entries = m.n_entries.saturating_add(1);
    CURLM_OK
}

/// C `curl_multi_remove_handle`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_remove_handle(
    multi: *mut c_void,
    easy: *mut c_void,
) -> c_int {
    let Some(m) = multi_from(multi) else {
        return CURLM_BAD_HANDLE;
    };
    let mut i = 0_usize;
    while i < m.n_entries {
        let ent = unsafe { &mut *m.entries.add(i) };
        if ent.easy.cast::<c_void>() == easy {
            let mut j = i;
            while j.saturating_add(1) < m.n_entries {
                unsafe {
                    let next = ptr::read(m.entries.add(j.saturating_add(1)));
                    ptr::write(m.entries.add(j), next);
                }
                j = j.saturating_add(1);
            }
            m.n_entries = m.n_entries.saturating_sub(1);
            return CURLM_OK;
        }
        i = i.saturating_add(1);
    }
    let _ = CURLM_INTERNAL_ERROR;
    CURLM_OK
}

/// C `curl_multi_perform` — runs unfinished easy handles to completion.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_perform(
    multi: *mut c_void,
    running: *mut c_int,
) -> c_int {
    let Some(m) = multi_from(multi) else {
        return CURLM_BAD_HANDLE;
    };
    let mut i = 0_usize;
    while i < m.n_entries {
        let ent = unsafe { &mut *m.entries.add(i) };
        if !ent.done {
            if let Some(easy) = easy_from(ent.easy.cast()) {
                ent.result = perform_easy(easy);
            } else {
                ent.result = CURLE_FAILED_INIT;
            }
            ent.done = true;
            ent.msg_delivered = false;
        }
        i = i.saturating_add(1);
    }
    if !running.is_null() {
        unsafe {
            *running = 0;
        }
    }
    CURLM_OK
}

/// C `curl_multi_fdset` — no host sockets; work already finished in perform.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_fdset(
    multi: *mut c_void,
    _r: *mut c_void,
    _w: *mut c_void,
    _e: *mut c_void,
    max_fd: *mut c_int,
) -> c_int {
    if multi_from(multi).is_none() {
        return CURLM_BAD_HANDLE;
    }
    if !max_fd.is_null() {
        unsafe {
            *max_fd = -1;
        }
    }
    CURLM_OK
}

/// C `curl_multi_timeout`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_timeout(multi: *mut c_void, ms: *mut c_long) -> c_int {
    if multi_from(multi).is_none() {
        return CURLM_BAD_HANDLE;
    }
    if !ms.is_null() {
        unsafe {
            *ms = 0;
        }
    }
    CURLM_OK
}

/// C `curl_multi_info_read`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_info_read(
    multi: *mut c_void,
    msgs_in_queue: *mut c_int,
) -> *mut c_void {
    let Some(m) = multi_from(multi) else {
        return ptr::null_mut();
    };
    let mut i = 0_usize;
    while i < m.n_entries {
        let ent = unsafe { &mut *m.entries.add(i) };
        if ent.done && !ent.msg_delivered {
            ent.msg_delivered = true;
            m.last_msg = CurlMsg {
                msg: CURLMSG_DONE,
                _pad: 0,
                easy_handle: ent.easy.cast(),
                data_result: ent.result as u64,
            };
            let mut left = 0_i32;
            let mut j = 0_usize;
            while j < m.n_entries {
                let e2 = unsafe { &*m.entries.add(j) };
                if e2.done && !e2.msg_delivered {
                    left = left.saturating_add(1);
                }
                j = j.saturating_add(1);
            }
            if !msgs_in_queue.is_null() {
                unsafe {
                    *msgs_in_queue = left;
                }
            }
            return core::ptr::from_mut(&mut m.last_msg).cast();
        }
        i = i.saturating_add(1);
    }
    if !msgs_in_queue.is_null() {
        unsafe {
            *msgs_in_queue = 0;
        }
    }
    let _ = CURLM_BAD_FUNCTION_ARGUMENT;
    ptr::null_mut()
}

/// C `curl_multi_strerror`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn curl_multi_strerror(code: c_int) -> *const c_char {
    match code {
        CURLM_OK => b"No error\0".as_ptr().cast(),
        CURLM_BAD_HANDLE => b"Invalid multi handle\0".as_ptr().cast(),
        CURLM_BAD_EASY_HANDLE => b"Invalid easy handle\0".as_ptr().cast(),
        CURLM_OUT_OF_MEMORY => b"Out of memory\0".as_ptr().cast(),
        _ => b"curl multi error\0".as_ptr().cast(),
    }
}
