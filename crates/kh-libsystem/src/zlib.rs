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
use miniz_oxide::inflate::stream::{self as mz_stream, InflateState as MzInflateState};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

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

/// Owned inflate engine (miniz streaming state with 32 KiB LZ dictionary).
///
/// Large (~33 KiB); always heap-allocated via freestanding `malloc`.
struct KhInflate {
    magic: u32,
    /// Remembered `window_bits` → raw vs zlib for `inflateReset`.
    window_bits: c_int,
    /// miniz streaming decompressor (zlib-wrapped by default).
    mz: MzInflateState,
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

/// C `deflateReset` → nlist `_deflateReset` (re-init compressor in place).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn deflateReset(strm: *mut c_void) -> c_int {
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
    // Re-create compressor with default mid level (matches git soft reset use).
    let flags = create_comp_flags_from_zip_params(6, 15, 0);
    st.comp = CompressorOxide::new(flags);
    st.finished = false;
    zs.total_in = 0;
    zs.total_out = 0;
    zs.msg = ptr::null_mut();
    zs.adler = 1;
    Z_OK
}

/// C `deflateBound` → soft upper bound (zlib-compatible overestimate).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn deflateBound(
    _strm: *mut c_void,
    source_len: u64,
    _bits: c_int,
) -> u64 {
    // zlib: sourceLen + (sourceLen >> 12) + (sourceLen >> 14) + (sourceLen >> 25) + 13
    source_len
        .saturating_add(source_len >> 12)
        .saturating_add(source_len >> 14)
        .saturating_add(source_len >> 25)
        .saturating_add(13)
}

/// C `deflateSetHeader` → soft no-op (gzip header; git uses zlib wrapper).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn deflateSetHeader(
    _strm: *mut c_void,
    _head: *mut c_void,
) -> c_int {
    Z_OK
}

fn data_format_from_window_bits(window_bits: c_int) -> DataFormat {
    // Positive → zlib header; negative → raw DEFLATE; |window| > 15 can select gzip
    // in real zlib — we only need zlib vs raw for git packs.
    if window_bits < 0 {
        DataFormat::Raw
    } else {
        DataFormat::Zlib
    }
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
    let _ = (version, stream_size);
    let Some(zs) = zstream(strm) else {
        return Z_STREAM_ERROR;
    };
    let raw = unsafe { malloc(core::mem::size_of::<KhInflate>()) };
    if raw.is_null() {
        errno::set_errno(12);
        return Z_MEM_ERROR;
    }
    let st = raw.cast::<KhInflate>();
    unsafe {
        st.write(KhInflate {
            magic: MAGIC_INFLATE,
            window_bits,
            mz: MzInflateState::new(data_format_from_window_bits(window_bits)),
        });
    }
    zs.state = raw;
    zs.total_in = 0;
    zs.total_out = 0;
    zs.msg = ptr::null_mut();
    zs.adler = 1;
    Z_OK
}

/// C `inflateReset` → nlist `_inflateReset`.
///
/// Apple git reuses one `z_stream` across pack objects; without a real reset the
/// second object after `Z_STREAM_END` yields `Z_BUF_ERROR` / data errors mid-pack.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn inflateReset(strm: *mut c_void) -> c_int {
    let Some(zs) = zstream(strm) else {
        return Z_STREAM_ERROR;
    };
    if zs.state.is_null() {
        return Z_STREAM_ERROR;
    }
    let st = unsafe { &mut *zs.state.cast::<KhInflate>() };
    if st.magic != MAGIC_INFLATE {
        return Z_STREAM_ERROR;
    }
    st.mz.reset(data_format_from_window_bits(st.window_bits));
    zs.total_in = 0;
    zs.total_out = 0;
    zs.msg = ptr::null_mut();
    zs.adler = 1;
    Z_OK
}

/// C `inflate` → nlist `_inflate`.
///
/// Uses miniz_oxide's streaming wrapper (32 KiB sliding dictionary + correct
/// `TINFL_FLAG_HAS_MORE_INPUT` for `MZFlush::None`). Hand-rolled NON_WRAPPING
/// history failed on Apple git `index-pack` of multi‑MiB packs
/// (`inflate returned -3` / `-5` at mid-pack offsets).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn inflate(strm: *mut c_void, flush: c_int) -> c_int {
    let Some(zs) = zstream(strm) else {
        return Z_STREAM_ERROR;
    };
    if zs.state.is_null() {
        return Z_STREAM_ERROR;
    }
    let st = unsafe { &mut *zs.state.cast::<KhInflate>() };
    if st.magic != MAGIC_INFLATE {
        return Z_STREAM_ERROR;
    }
    if zs.next_out.is_null() && zs.avail_out != 0 {
        return Z_STREAM_ERROR;
    }

    let in_len = zs.avail_in as usize;
    let input = if zs.next_in.is_null() || in_len == 0 {
        &[][..]
    } else {
        unsafe { core::slice::from_raw_parts(zs.next_in, in_len) }
    };
    // Empty out buffer: still drive miniz so a finished stream can report
    // StreamEnd (and so we don't spin forever returning Z_OK).
    let out_len = zs.avail_out as usize;
    let output = if zs.next_out.is_null() || out_len == 0 {
        &mut [][..]
    } else {
        unsafe { core::slice::from_raw_parts_mut(zs.next_out, out_len) }
    };

    // IMPORTANT: Always `MZFlush::None` for miniz streaming.
    //
    // Real zlib allows multi-call `inflate(..., Z_FINISH)` while more input is
    // still being fed (git `index-pack` / `use_pack` windows). miniz maps
    // `MZFlush::Finish` to "no HAS_MORE_INPUT", which breaks that pattern and
    // surfaces as `Z_BUF_ERROR` / `Z_DATA_ERROR` mid-pack (e.g. offset 499674).
    // Stream end is detected via zlib trailer → `MZStatus::StreamEnd`.
    let _ = flush;
    let res = mz_stream::inflate(&mut st.mz, input, output, MZFlush::None);

    let consumed = res.bytes_consumed;
    let written = res.bytes_written;
    if consumed > 0 {
        zs.next_in = if zs.next_in.is_null() {
            ptr::null_mut()
        } else {
            unsafe { zs.next_in.add(consumed) }
        };
        zs.avail_in = zs.avail_in.saturating_sub(consumed as u32);
        zs.total_in = zs.total_in.saturating_add(consumed as u64);
    }
    if written > 0 {
        zs.next_out = unsafe { zs.next_out.add(written) };
        zs.avail_out = zs.avail_out.saturating_sub(written as u32);
        zs.total_out = zs.total_out.saturating_add(written as u64);
    }

    match res.status {
        Ok(MZStatus::Ok) => Z_OK,
        Ok(MZStatus::StreamEnd) => Z_STREAM_END,
        Ok(MZStatus::NeedDict) => {
            // Git packs do not use preset dictionaries.
            Z_DATA_ERROR
        }
        Err(MZError::Buf) => {
            // Apple `git index-pack` (builtin/index-pack.c `unpack_entry_data`):
            //   do { status = git_inflate(&stream, 0); ... } while (status == Z_OK);
            //   if (status != Z_STREAM_END) bad_object(..., status);
            // It does **not** continue on Z_BUF_ERROR (unlike packfile.c).
            // So "need more input" must be Z_OK, not Z_BUF_ERROR, or small
            // OFS_DELTA objects die with `inflate returned -5` mid-pack.
            if consumed > 0 || written > 0 || in_len == 0 {
                Z_OK
            } else {
                // Input was available but miniz made zero progress → corrupt.
                crate::trace::force_note(b"[kh] inflate Buf with unread input\n");
                Z_DATA_ERROR
            }
        }
        Err(MZError::Data) => {
            crate::trace::force_note(b"[kh] inflate MZError::Data\n");
            Z_DATA_ERROR
        }
        Err(MZError::Mem) => Z_MEM_ERROR,
        Err(MZError::Stream | MZError::Param | _) => Z_STREAM_ERROR,
    }
}

/// C `inflateEnd` → nlist `_inflateEnd`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn inflateEnd(strm: *mut c_void) -> c_int {
    let Some(zs) = zstream(strm) else {
        return Z_STREAM_ERROR;
    };
    if !zs.state.is_null() {
        let st = unsafe { &mut *zs.state.cast::<KhInflate>() };
        if st.magic != MAGIC_INFLATE {
            return Z_STREAM_ERROR;
        }
        st.magic = 0;
        // Drop MzInflateState then free the allocation.
        unsafe {
            ptr::drop_in_place(st);
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

/// Inflate zlib-wrapped (preferred) or raw DEFLATE into a freestanding `malloc` buffer.
///
/// Used by freestanding libcurl when git claims `Content-Encoding: gzip` but
/// actually emits a **zlib** wrapper (not true gzip). Caller must `free` the
/// returned pointer. Cap: 64 MiB decoded.
pub(crate) fn inflate_to_malloc(src: &[u8]) -> Option<(*mut u8, usize)> {
    use miniz_oxide::inflate::{decompress_to_vec, decompress_to_vec_zlib_with_limit};

    const MAX_OUT: usize = 64 * 1024 * 1024;
    if src.is_empty() {
        return None;
    }
    let decoded = match decompress_to_vec_zlib_with_limit(src, MAX_OUT) {
        Ok(v) => v,
        // Raw DEFLATE fallback (no zlib header).
        Err(_) => match decompress_to_vec(src) {
            Ok(v) if v.len() <= MAX_OUT => v,
            _ => return None,
        },
    };
    let n = decoded.len();
    let p = unsafe { malloc(n.max(1)) }.cast::<u8>();
    if p.is_null() {
        return None;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(decoded.as_ptr(), p, n);
    }
    Some((p, n))
}
