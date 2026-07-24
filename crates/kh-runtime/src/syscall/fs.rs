//! Path and stat-related BSD syscalls.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;

use crate::bottle::{self, translate_path};
use crate::mem::registry_check_range;

use super::common::{EBADF, EFAULT, ENOENT, SyscallArgs, SyscallResult, guest_ptr_mut};
use super::fd::guest_to_host_fd;

/// Darwin `struct stat64` size (XNU).
pub(crate) const DARWIN_STAT64_SIZE: usize = 144;

/// `access`.
pub(crate) fn handle_access(args: SyscallArgs) -> SyscallResult {
    let name = "access";
    if !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_path) = translate_path(&path) else {
        return SyscallResult::err(name, ENOENT);
    };
    if host_path.exists() {
        SyscallResult::ok(name, 0)
    } else {
        SyscallResult::err(name, ENOENT)
    }
}

/// `stat` / `stat64` — path `x0`, buffer `x1`.
pub(crate) fn handle_stat(args: SyscallArgs) -> SyscallResult {
    let name = "stat";
    if !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    if !registry_check_range(args.x1, DARWIN_STAT64_SIZE, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_path) = translate_path(&path) else {
        return SyscallResult::err(name, ENOENT);
    };
    let Ok(meta) = std::fs::metadata(&host_path) else {
        return SyscallResult::err(name, ENOENT);
    };
    write_darwin_stat64(args.x1, &meta, name)
}

/// `fstat` / `fstat64` — fd `x0`, buffer `x1`.
pub(crate) fn handle_fstat(args: SyscallArgs) -> SyscallResult {
    let name = "fstat";
    let Some(host) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    if !registry_check_range(args.x1, DARWIN_STAT64_SIZE, true) {
        return SyscallResult::err(name, EFAULT);
    }
    // SAFETY: host fd live; fstat into local libc stat then convert.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(host, std::ptr::addr_of_mut!(st)) };
    if rc != 0 {
        return SyscallResult::err(name, EBADF);
    }
    write_darwin_stat64_from_libc(args.x1, &st, name)
}

fn write_darwin_stat64(buf_addr: u64, meta: &Metadata, name: &'static str) -> SyscallResult {
    let mut raw = [0_u8; DARWIN_STAT64_SIZE];
    fill_stat64_bytes(
        &mut raw,
        trunc_i32(meta.dev()),
        trunc_u16_u32(meta.mode()),
        trunc_u16_u64(meta.nlink()),
        meta.ino(),
        meta.uid(),
        meta.gid(),
        trunc_i32(meta.rdev()),
        meta.atime(),
        meta.mtime(),
        meta.ctime(),
        trunc_i64_from_u64(meta.size()),
        trunc_i64_from_u64(meta.blocks()),
        trunc_i32_from_u64(meta.blksize()),
    );
    // SAFETY: range checked writable.
    let dst =
        unsafe { std::slice::from_raw_parts_mut(guest_ptr_mut(buf_addr), DARWIN_STAT64_SIZE) };
    dst.copy_from_slice(&raw);
    SyscallResult::ok(name, 0)
}

fn write_darwin_stat64_from_libc(
    buf_addr: u64,
    st: &libc::stat,
    name: &'static str,
) -> SyscallResult {
    let mut raw = [0_u8; DARWIN_STAT64_SIZE];
    // libc field widths differ by host OS — convert via integer intermediates.
    fill_stat64_bytes(
        &mut raw,
        narrow_i32(st.st_dev),
        narrow_u16(st.st_mode),
        narrow_u16(st.st_nlink),
        st.st_ino,
        st.st_uid,
        st.st_gid,
        narrow_i32(st.st_rdev),
        st.st_atime,
        st.st_mtime,
        st.st_ctime,
        st.st_size,
        st.st_blocks,
        narrow_i32(st.st_blksize),
    );
    let dst =
        unsafe { std::slice::from_raw_parts_mut(guest_ptr_mut(buf_addr), DARWIN_STAT64_SIZE) };
    dst.copy_from_slice(&raw);
    SyscallResult::ok(name, 0)
}

fn trunc_i32(v: u64) -> i32 {
    i32::try_from(v & 0xFFFF_FFFF).unwrap_or(0)
}

fn trunc_i32_from_u64(v: u64) -> i32 {
    i32::try_from(v.min(u64::from(u32::MAX))).unwrap_or(0)
}

fn trunc_u16_u32(v: u32) -> u16 {
    u16::try_from(v & 0xFFFF).unwrap_or(0)
}

fn trunc_u16_u64(v: u64) -> u16 {
    u16::try_from(v & 0xFFFF).unwrap_or(0)
}

fn trunc_i64_from_u64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Narrow a host `libc` integer field to `i32` without host-specific casts.
fn narrow_i32<T: Copy + TryInto<i64>>(v: T) -> i32 {
    let wide = v.try_into().unwrap_or(0_i64);
    i32::try_from(wide).unwrap_or(if wide.is_negative() {
        i32::MIN
    } else {
        i32::MAX
    })
}

/// Narrow a host `libc` integer field to `u16`.
fn narrow_u16<T: Copy + TryInto<u64>>(v: T) -> u16 {
    let wide = v.try_into().unwrap_or(0_u64);
    u16::try_from(wide & 0xFFFF).unwrap_or(0)
}

/// Packs a Darwin `struct stat64` (144 bytes) little-endian.
#[allow(clippy::too_many_arguments)]
fn fill_stat64_bytes(
    raw: &mut [u8; DARWIN_STAT64_SIZE],
    dev: i32,
    mode: u16,
    nlink: u16,
    ino: u64,
    uid: u32,
    gid: u32,
    rdev: i32,
    atime: i64,
    mtime: i64,
    ctime: i64,
    size: i64,
    blocks: i64,
    blksize: i32,
) {
    put_i32(raw, 0, dev);
    put_u16(raw, 4, mode);
    put_u16(raw, 6, nlink);
    put_u64(raw, 8, ino);
    put_u32(raw, 16, uid);
    put_u32(raw, 20, gid);
    put_i32(raw, 24, rdev);
    put_i64(raw, 32, atime);
    put_i64(raw, 40, 0);
    put_i64(raw, 48, mtime);
    put_i64(raw, 56, 0);
    put_i64(raw, 64, ctime);
    put_i64(raw, 72, 0);
    put_i64(raw, 80, 0);
    put_i64(raw, 88, 0);
    put_i64(raw, 96, size);
    put_i64(raw, 104, blocks);
    put_i32(raw, 112, blksize);
    put_u32(raw, 116, 0);
    put_u32(raw, 120, 0);
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    if let Some(slot) = buf.get_mut(off..off.saturating_add(2)) {
        slot.copy_from_slice(&v.to_le_bytes());
    }
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    if let Some(slot) = buf.get_mut(off..off.saturating_add(4)) {
        slot.copy_from_slice(&v.to_le_bytes());
    }
}

fn put_i32(buf: &mut [u8], off: usize, v: i32) {
    if let Some(slot) = buf.get_mut(off..off.saturating_add(4)) {
        slot.copy_from_slice(&v.to_le_bytes());
    }
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    if let Some(slot) = buf.get_mut(off..off.saturating_add(8)) {
        slot.copy_from_slice(&v.to_le_bytes());
    }
}

fn put_i64(buf: &mut [u8], off: usize, v: i64) {
    if let Some(slot) = buf.get_mut(off..off.saturating_add(8)) {
        slot.copy_from_slice(&v.to_le_bytes());
    }
}
