//! Path and stat-related BSD syscalls.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;

use crate::bottle::{self, translate_path};
use crate::mem::registry_check_range;

use crate::host;

use super::common::{EBADF, EFAULT, ENOENT, SyscallArgs, SyscallResult, guest_write};
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
    let Some(st) = host::fstat_fd(host) else {
        return SyscallResult::err(name, EBADF);
    };
    write_darwin_stat64_from_libc(args.x1, &st, name)
}

fn write_darwin_stat64(buf_addr: u64, meta: &Metadata, name: &'static str) -> SyscallResult {
    let mut raw = [0_u8; DARWIN_STAT64_SIZE];
    fill_stat64_bytes(
        &mut raw,
        &Stat64Fields {
            dev: trunc_i32(meta.dev()),
            mode: trunc_u16_u32(meta.mode()),
            nlink: trunc_u16_u64(meta.nlink()),
            ino: meta.ino(),
            uid: meta.uid(),
            gid: meta.gid(),
            rdev: trunc_i32(meta.rdev()),
            atime: meta.atime(),
            mtime: meta.mtime(),
            ctime: meta.ctime(),
            size: trunc_i64_from_u64(meta.size()),
            blocks: trunc_i64_from_u64(meta.blocks()),
            blksize: trunc_i32_from_u64(meta.blksize()),
        },
    );
    guest_write(buf_addr, &raw);
    SyscallResult::ok(name, 0)
}

fn write_darwin_stat64_from_libc(
    buf_addr: u64,
    st: &libc::stat,
    name: &'static str,
) -> SyscallResult {
    let mut raw = [0_u8; DARWIN_STAT64_SIZE];
    fill_stat64_bytes(
        &mut raw,
        &Stat64Fields {
            dev: narrow_i32(st.st_dev),
            mode: narrow_u16(st.st_mode),
            nlink: narrow_u16(st.st_nlink),
            ino: st.st_ino,
            uid: st.st_uid,
            gid: st.st_gid,
            rdev: narrow_i32(st.st_rdev),
            atime: st.st_atime,
            mtime: st.st_mtime,
            ctime: st.st_ctime,
            size: st.st_size,
            blocks: st.st_blocks,
            blksize: narrow_i32(st.st_blksize),
        },
    );
    guest_write(buf_addr, &raw);
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

/// Fields packed into Darwin `struct stat64` (144 bytes, little-endian).
#[derive(Clone, Copy)]
struct Stat64Fields {
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
}

/// Packs a Darwin `struct stat64` (144 bytes) little-endian.
fn fill_stat64_bytes(raw: &mut [u8; DARWIN_STAT64_SIZE], f: &Stat64Fields) {
    put_i32(raw, 0, f.dev);
    put_u16(raw, 4, f.mode);
    put_u16(raw, 6, f.nlink);
    put_u64(raw, 8, f.ino);
    put_u32(raw, 16, f.uid);
    put_u32(raw, 20, f.gid);
    put_i32(raw, 24, f.rdev);
    put_i64(raw, 32, f.atime);
    put_i64(raw, 40, 0);
    put_i64(raw, 48, f.mtime);
    put_i64(raw, 56, 0);
    put_i64(raw, 64, f.ctime);
    put_i64(raw, 72, 0);
    put_i64(raw, 80, 0);
    put_i64(raw, 88, 0);
    put_i64(raw, 96, f.size);
    put_i64(raw, 104, f.blocks);
    put_i32(raw, 112, f.blksize);
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
