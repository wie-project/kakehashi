//! Freestanding zlib surface for Apple `git` object store (`deflate` / `inflate`).
//!
//! Uses [`miniz_oxide`] (pure Rust DEFLATE). Symbols match Darwin `libz.1`
//! re-exports that git binds from libSystem / libz.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::manual_c_str_literals,
    clippy::too_many_arguments,
    clippy::used_underscore_binding
)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use miniz_oxide::deflate::core::{
    CompressorOxide, TDEFLFlush, TDEFLStatus, compress, create_comp_flags_from_zip_params,
};
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::inflate_flags::{
    TINFL_FLAG_PARSE_ZLIB_HEADER, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
};
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};

use crate::errno;
use crate::heap::{free, malloc};

const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_STREAM_ERROR: c_int = -2;
const Z_DATA_ERROR: c_int = -3;
const Z_MEM_ERROR: c_int = -4;
const Z_BUF_ERROR: c_int = -5;
const Z_VERSION_ERROR: c_int = -6;

const Z_SYNC_FLUSH: c_int = 2;
const Z_FULL_FLUSH: c_int = 3;
const Z_FINISH: c_int = 4;

const Z_DEFAULT_COMPRESSION: c_int = -1;
const Z_DEFAULT_STRATEGY: c_int = 0;

/// Darwin / zlib `z_stream` (pointer sizes for arm64).
#[repr(C)]
struct ZStream {
    next_in: *mut u8,
    avail_in: u32,
    total_in: u64,
    next_out: *mut u8,
    avail_out: u32,
    total_out: u64,
    msg: *mut c_char,
    state: *mut c_void,
    zalloc: *mut c_void,
    zfree: *mut c_void,
    opaque: *mut c_void,
    data_type: c_int,
    adler: u64,
    reserved: u64,
}

const MAGIC_DEFLATE: u32 = 0x4B48_4446; // "KHDF"
const MAGIC_INFLATE: u32 = 0x4B48_4946; // "KHIF"

struct DeflateState {
    magic: u32,
    comp: CompressorOxide,
    finished: bool,
}

struct InflateState {
    magic: u32,
    decomp: DecompressorOxide,
    finished: bool,
    /// Full decompressed history (miniz NON_WRAPPING needs prior bytes for
    /// backrefs). `hist_len` is valid data; capacity is `hist_cap`.
    hist: *mut u8,
    hist_cap: usize,
    hist_len: usize,
    /// Bytes already copied out to the caller from `hist`.
    hist_delivered: usize,
}

fn zstream<'a>(strm: *mut c_void) -> Option<&'a mut ZStream> {
    if strm.is_null() {
        return None;
    }
    Some(unsafe { &mut *strm.cast::<ZStream>() })
}

/// C `deflateInit_` → nlist `_deflateInit_`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn deflateInit_(
    strm: *mut c_void,
    level: c_int,
    version: *const c_char,
    stream_size: c_int,
) -> c_int {
    let _ = version;
    if stream_size != 0 && stream_size as usize != core::mem::size_of::<ZStream>() {
        // Soft: Darwin and our layout should match; still accept close sizes.
        if (stream_size as usize) < 64 {
            return Z_VERSION_ERROR;
        }
    }
    unsafe {
        deflateInit2_(
            strm,
            level,
            8,
            15,
            8,
            Z_DEFAULT_STRATEGY,
            version,
            stream_size,
        )
    }
}

/// C `deflateInit2_` → nlist `_deflateInit2_`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn deflateInit2_(
    strm: *mut c_void,
    level: c_int,
    method: c_int,
    window_bits: c_int,
    mem_level: c_int,
    strategy: c_int,
    version: *const c_char,
    stream_size: c_int,
) -> c_int {
    let _ = (version, stream_size, method, mem_level, strategy);
    let Some(zs) = zstream(strm) else {
        return Z_STREAM_ERROR;
    };
    // Only zlib-wrapped DEFLATE (window_bits > 0).
    if window_bits < 0 {
        // raw deflate — treat as zlib for git objects (they use zlib wrapper).
    }
    let lvl = if level == Z_DEFAULT_COMPRESSION {
        6
    } else if (0..=9).contains(&level) {
        level as u8
    } else {
        6
    };
    let flags = create_comp_flags_from_zip_params(i32::from(lvl), 15, 0);
    let raw = unsafe { malloc(core::mem::size_of::<DeflateState>()) };
    if raw.is_null() {
        errno::set_errno(12);
        return Z_MEM_ERROR;
    }
    let st = raw.cast::<DeflateState>();
    unsafe {
        st.write(DeflateState {
            magic: MAGIC_DEFLATE,
            comp: CompressorOxide::new(flags),
            finished: false,
        });
    }
    zs.state = raw;
    zs.total_in = 0;
    zs.total_out = 0;
    zs.msg = ptr::null_mut();
    zs.adler = 1;
    Z_OK
}

/// C `deflate` → nlist `_deflate`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn deflate(strm: *mut c_void, flush: c_int) -> c_int {
    let Some(zs) = zstream(strm) else {
        return Z_STREAM_ERROR;
    };
    if zs.state.is_null() {
        return Z_STREAM_ERROR;
    }
    let st = unsafe { &mut *zs.state.cast::<DeflateState>() };
    if st.magic != MAGIC_DEFLATE {
        return Z_STREAM_ERROR;
    }
    if st.finished {
        return if flush == Z_FINISH {
            Z_STREAM_END
        } else {
            Z_STREAM_ERROR
        };
    }
    if zs.next_out.is_null() || zs.avail_out == 0 {
        return Z_BUF_ERROR;
    }
    let in_len = zs.avail_in as usize;
    let out_len = zs.avail_out as usize;
    let input = if zs.next_in.is_null() || in_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(zs.next_in, in_len) }
    };
    let output = unsafe { core::slice::from_raw_parts_mut(zs.next_out, out_len) };

    let tdefl_flush = match flush {
        Z_SYNC_FLUSH => TDEFLFlush::Sync,
        Z_FULL_FLUSH => TDEFLFlush::Full,
        Z_FINISH => TDEFLFlush::Finish,
        // Z_NO_FLUSH and unknown → none
        _ => TDEFLFlush::None,
    };

    let (status, in_consumed, out_produced) = compress(&mut st.comp, input, output, tdefl_flush);

    zs.next_in = if zs.next_in.is_null() {
        ptr::null_mut()
    } else {
        unsafe { zs.next_in.add(in_consumed) }
    };
    zs.avail_in = zs.avail_in.saturating_sub(in_consumed as u32);
    zs.total_in = zs.total_in.saturating_add(in_consumed as u64);
    zs.next_out = unsafe { zs.next_out.add(out_produced) };
    zs.avail_out = zs.avail_out.saturating_sub(out_produced as u32);
    zs.total_out = zs.total_out.saturating_add(out_produced as u64);

    match status {
        TDEFLStatus::Okay => {
            if out_produced == 0 && in_consumed == 0 && flush != Z_FINISH {
                Z_BUF_ERROR
            } else {
                Z_OK
            }
        }
        TDEFLStatus::Done => {
            st.finished = true;
            Z_STREAM_END
        }
        TDEFLStatus::PutBufFailed => Z_BUF_ERROR,
        TDEFLStatus::BadParam => Z_STREAM_ERROR,
    }
}

/// C `deflateEnd` → nlist `_deflateEnd`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn deflateEnd(strm: *mut c_void) -> c_int {
    let Some(zs) = zstream(strm) else {
        return Z_STREAM_ERROR;
    };
    if !zs.state.is_null() {
        let st = unsafe { &*zs.state.cast::<DeflateState>() };
        if st.magic != MAGIC_DEFLATE {
            return Z_STREAM_ERROR;
        }
        unsafe {
            free(zs.state);
        }
        zs.state = ptr::null_mut();
    }
    Z_OK
}

/// C `inflateInit_` → nlist `_inflateInit_`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn inflateInit_(
    strm: *mut c_void,
    version: *const c_char,
    stream_size: c_int,
) -> c_int {
    unsafe { inflateInit2_(strm, 15, version, stream_size) }
}

/// C `inflateInit2_` → nlist `_inflateInit2_`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn inflateInit2_(
    strm: *mut c_void,
    window_bits: c_int,
    version: *const c_char,
    stream_size: c_int,
) -> c_int {
    let _ = (version, stream_size, window_bits);
    let Some(zs) = zstream(strm) else {
        return Z_STREAM_ERROR;
    };
    let raw = unsafe { malloc(core::mem::size_of::<InflateState>()) };
    if raw.is_null() {
        errno::set_errno(12);
        return Z_MEM_ERROR;
    }
    let st = raw.cast::<InflateState>();
    unsafe {
        st.write(InflateState {
            magic: MAGIC_INFLATE,
            decomp: DecompressorOxide::new(),
            finished: false,
            hist: ptr::null_mut(),
            hist_cap: 0,
            hist_len: 0,
            hist_delivered: 0,
        });
    }
    zs.state = raw;
    zs.total_in = 0;
    zs.total_out = 0;
    zs.msg = ptr::null_mut();
    zs.adler = 1;
    Z_OK
}

/// Grow inflate history so at least `need` more bytes can be written at `hist_len`.
fn inflate_hist_reserve(st: &mut InflateState, need: usize) -> bool {
    let want = st.hist_len.saturating_add(need);
    if want <= st.hist_cap {
        return true;
    }
    let mut new_cap = st.hist_cap.max(4096);
    while new_cap < want {
        new_cap = new_cap.saturating_mul(2);
        if new_cap > 16 * 1024 * 1024 {
            return false;
        }
    }
    let new_ptr = if st.hist.is_null() {
        unsafe { malloc(new_cap) }
    } else {
        unsafe { crate::heap::realloc(st.hist.cast(), new_cap) }
    };
    if new_ptr.is_null() {
        return false;
    }
    st.hist = new_ptr.cast();
    st.hist_cap = new_cap;
    true
}

/// C `inflate` → nlist `_inflate`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn inflate(strm: *mut c_void, flush: c_int) -> c_int {
    let _ = flush;
    let Some(zs) = zstream(strm) else {
        return Z_STREAM_ERROR;
    };
    if zs.state.is_null() {
        return Z_STREAM_ERROR;
    }
    let st = unsafe { &mut *zs.state.cast::<InflateState>() };
    if st.magic != MAGIC_INFLATE {
        return Z_STREAM_ERROR;
    }
    if zs.next_out.is_null() || zs.avail_out == 0 {
        return Z_BUF_ERROR;
    }

    // First: drain any already-decompressed history into the caller's buffer.
    let mut produced_to_user = 0_usize;
    let out_len = zs.avail_out as usize;
    let output = unsafe { core::slice::from_raw_parts_mut(zs.next_out, out_len) };
    if st.hist_delivered < st.hist_len {
        let pending = st.hist_len - st.hist_delivered;
        let n = pending.min(out_len);
        if n > 0 && !st.hist.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(st.hist.add(st.hist_delivered), output.as_mut_ptr(), n);
            }
            st.hist_delivered += n;
            produced_to_user = n;
            zs.next_out = unsafe { zs.next_out.add(n) };
            zs.avail_out = zs.avail_out.saturating_sub(n as u32);
            zs.total_out = zs.total_out.saturating_add(n as u64);
        }
        if st.finished && st.hist_delivered >= st.hist_len {
            return Z_STREAM_END;
        }
        if zs.avail_out == 0 {
            return Z_OK;
        }
    } else if st.finished {
        return Z_STREAM_END;
    }

    // Decompress more into history (full prior output kept for DEFLATE backrefs).
    let room = (zs.avail_out as usize).max(256);
    if !inflate_hist_reserve(st, room) {
        return Z_MEM_ERROR;
    }
    let in_len = zs.avail_in as usize;
    let input = if zs.next_in.is_null() || in_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(zs.next_in, in_len) }
    };
    let hist_slice =
        unsafe { core::slice::from_raw_parts_mut(st.hist, st.hist_cap) };
    let flags = TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    let (status, in_consumed, out_produced) =
        decompress(&mut st.decomp, input, hist_slice, st.hist_len, flags);

    zs.next_in = if zs.next_in.is_null() {
        ptr::null_mut()
    } else {
        unsafe { zs.next_in.add(in_consumed) }
    };
    zs.avail_in = zs.avail_in.saturating_sub(in_consumed as u32);
    zs.total_in = zs.total_in.saturating_add(in_consumed as u64);
    st.hist_len = st.hist_len.saturating_add(out_produced);

    // Copy new bytes to user.
    if st.hist_delivered < st.hist_len && zs.avail_out > 0 {
        let pending = st.hist_len - st.hist_delivered;
        let n = pending.min(zs.avail_out as usize);
        let out_now = unsafe {
            core::slice::from_raw_parts_mut(zs.next_out, zs.avail_out as usize)
        };
        if n > 0 && !st.hist.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(st.hist.add(st.hist_delivered), out_now.as_mut_ptr(), n);
            }
            st.hist_delivered += n;
            produced_to_user = produced_to_user.saturating_add(n);
            zs.next_out = unsafe { zs.next_out.add(n) };
            zs.avail_out = zs.avail_out.saturating_sub(n as u32);
            zs.total_out = zs.total_out.saturating_add(n as u64);
        }
    }

    match status {
        TINFLStatus::Done => {
            st.finished = true;
            if st.hist_delivered >= st.hist_len {
                Z_STREAM_END
            } else {
                Z_OK
            }
        }
        TINFLStatus::NeedsMoreInput | TINFLStatus::HasMoreOutput => {
            if produced_to_user == 0 && in_consumed == 0 && out_produced == 0 {
                Z_BUF_ERROR
            } else {
                Z_OK
            }
        }
        TINFLStatus::Failed
        | TINFLStatus::FailedCannotMakeProgress
        | TINFLStatus::BadParam
        | TINFLStatus::Adler32Mismatch => Z_DATA_ERROR,
    }
}

/// C `inflateEnd` → nlist `_inflateEnd`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn inflateEnd(strm: *mut c_void) -> c_int {
    let Some(zs) = zstream(strm) else {
        return Z_STREAM_ERROR;
    };
    if !zs.state.is_null() {
        let st = unsafe { &mut *zs.state.cast::<InflateState>() };
        if st.magic != MAGIC_INFLATE {
            return Z_STREAM_ERROR;
        }
        if !st.hist.is_null() {
            unsafe {
                free(st.hist.cast());
            }
            st.hist = ptr::null_mut();
        }
        unsafe {
            free(zs.state);
        }
        zs.state = ptr::null_mut();
    }
    Z_OK
}

/// C `zlibVersion` → nlist `_zlibVersion`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zlibVersion() -> *const c_char {
    // Stable static C string.
    static V: &[u8] = b"1.2.11-kh\0";
    V.as_ptr().cast()
}

/// C `crc32` → nlist `_crc32` (IEEE; git pack / index).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn crc32(crc: u32, buf: *const u8, len: u32) -> u32 {
    if buf.is_null() || len == 0 {
        return crc;
    }
    let slice = unsafe { core::slice::from_raw_parts(buf, len as usize) };
    crc32_slice(crc, slice)
}

fn crc32_slice(mut crc: u32, data: &[u8]) -> u32 {
    crc = !crc;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (0_u32).wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// C `adler32` → nlist `_adler32`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn adler32(adler: u32, buf: *const u8, len: u32) -> u32 {
    if buf.is_null() {
        return 1;
    }
    let slice = unsafe { core::slice::from_raw_parts(buf, len as usize) };
    adler32_slice(adler, slice)
}

fn adler32_slice(adler: u32, data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut s1 = adler & 0xffff;
    let mut s2 = (adler >> 16) & 0xffff;
    for &b in data {
        s1 = (s1 + u32::from(b)) % MOD;
        s2 = (s2 + s1) % MOD;
    }
    (s2 << 16) | s1
}

/// C `compressBound` → nlist `_compressBound`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn compressBound(source_len: u64) -> u64 {
    source_len
        .saturating_add(source_len.div_ceil(1000))
        .saturating_add(12)
}

/// C `zError` → nlist `_zError`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn zError(err: c_int) -> *const c_char {
    let s: &[u8] = match err {
        0 => b"OK\0",
        1 => b"stream end\0",
        -2 => b"stream error\0",
        -3 => b"data error\0",
        -4 => b"insufficient memory\0",
        -5 => b"buffer error\0",
        -6 => b"incompatible version\0",
        _ => b"unknown error\0",
    };
    s.as_ptr().cast()
}
