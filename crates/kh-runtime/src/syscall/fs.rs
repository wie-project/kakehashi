//! Path and stat-related BSD syscalls.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;

use crate::bottle::{self, translate_path};
use crate::mem::registry_check_range;

use crate::host;

use super::common::{
    EBADF, EEXIST, EFAULT, EINVAL, ENOENT, EPERM, ERANGE, SyscallArgs, SyscallResult, guest_write,
    reg_as_i32, reg_as_i64,
};
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
    match access_path(&path) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) => {
            // G5: modern ld may probe paths with a dropped `/` (liblib, .sdkusr).
            if e == ENOENT
                && let Some(fixed) = bottle::repair_ld_guest_path(&path)
                && access_path(&fixed).is_ok()
            {
                tracing::debug!(guest = %path, fixed = %fixed, "access ok (ld path repair)");
                return SyscallResult::ok(name, 0);
            }
            SyscallResult::err(name, e)
        }
    }
}

fn access_path(path: &str) -> Result<(), i64> {
    if let Some((dirfd, rel)) = bottle::bottle_openat_rel(path) {
        let Ok(c_rel) = std::ffi::CString::new(rel) else {
            return Err(EFAULT);
        };
        return if host::faccessat_ok(dirfd, &c_rel) {
            Ok(())
        } else {
            Err(ENOENT)
        };
    }
    let Ok(host_path) = translate_path(path) else {
        return Err(ENOENT);
    };
    if host_path.exists() {
        Ok(())
    } else {
        Err(ENOENT)
    }
}

/// `stat` / `stat64` — path `x0`, buffer `x1`.
pub(crate) fn handle_stat(args: SyscallArgs) -> SyscallResult {
    path_stat(args, false, "stat")
}

/// `lstat` / `lstat64` — path `x0`, buffer `x1` (do not follow symlinks).
pub(crate) fn handle_lstat(args: SyscallArgs) -> SyscallResult {
    path_stat(args, true, "lstat")
}

fn path_stat(args: SyscallArgs, no_follow: bool, name: &'static str) -> SyscallResult {
    if !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    if !registry_check_range(args.x1, DARWIN_STAT64_SIZE, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    match path_stat_into(&path, no_follow, args.x1, name) {
        Ok(r) => r,
        Err(ENOENT) => {
            if let Some(fixed) = bottle::repair_ld_guest_path(&path) {
                match path_stat_into(&fixed, no_follow, args.x1, name) {
                    Ok(r) => {
                        tracing::debug!(
                            op = name,
                            guest = %path,
                            fixed = %fixed,
                            "stat ok (ld path repair)"
                        );
                        r
                    }
                    Err(e) => SyscallResult::err(name, e),
                }
            } else {
                SyscallResult::err(name, ENOENT)
            }
        }
        Err(e) => SyscallResult::err(name, e),
    }
}

fn path_stat_into(
    path: &str,
    no_follow: bool,
    buf_va: u64,
    name: &'static str,
) -> Result<SyscallResult, i64> {
    // B1: fstatat(bottle_dirfd, rel) avoids PathBuf + full absolute walk.
    if let Some((dirfd, rel)) = bottle::bottle_openat_rel(path) {
        let Ok(c_rel) = std::ffi::CString::new(rel) else {
            return Err(EFAULT);
        };
        let Some(st) = host::fstatat(dirfd, &c_rel, no_follow) else {
            return Err(ENOENT);
        };
        return Ok(write_darwin_stat64_from_libc(buf_va, &st, name));
    }
    let Ok(host_path) = translate_path(path) else {
        return Err(ENOENT);
    };
    let meta = if no_follow {
        std::fs::symlink_metadata(&host_path)
    } else {
        std::fs::metadata(&host_path)
    };
    let Ok(meta) = meta else {
        return Err(ENOENT);
    };
    Ok(write_darwin_stat64(buf_va, &meta, name))
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

/// Darwin `AT_FDCWD` for `fstatat`.
const AT_FDCWD: i32 = -2;
/// Darwin `AT_SYMLINK_NOFOLLOW`.
const AT_SYMLINK_NOFOLLOW: i32 = 0x0020;

/// `fstatat` — dirfd `x0`, path `x1`, buf `x2`, flag `x3`.
pub(crate) fn handle_fstatat(args: SyscallArgs) -> SyscallResult {
    let name = "fstatat";
    let dirfd = reg_as_i32(args.x0);
    let flag = reg_as_i32(args.x3);
    if !registry_check_range(args.x1, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    if !registry_check_range(args.x2, DARWIN_STAT64_SIZE, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x1, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };

    let no_follow = flag & AT_SYMLINK_NOFOLLOW != 0;

    if dirfd == AT_FDCWD || path.starts_with('/') {
        if let Some((bdfd, rel)) = bottle::bottle_openat_rel(&path) {
            let Ok(c_rel) = std::ffi::CString::new(rel) else {
                return SyscallResult::err(name, EFAULT);
            };
            let Some(st) = host::fstatat(bdfd, &c_rel, no_follow) else {
                return SyscallResult::err(name, ENOENT);
            };
            return write_darwin_stat64_from_libc(args.x2, &st, name);
        }
        let Ok(host_path) = translate_path(&path) else {
            return SyscallResult::err(name, ENOENT);
        };
        let meta = if no_follow {
            std::fs::symlink_metadata(&host_path)
        } else {
            std::fs::metadata(&host_path)
        };
        let Ok(meta) = meta else {
            return SyscallResult::err(name, ENOENT);
        };
        return write_darwin_stat64(args.x2, &meta, name);
    }

    let Some(host_dir) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let Ok(c_rel) = std::ffi::CString::new(path.as_str()) else {
        return SyscallResult::err(name, EFAULT);
    };
    // Relative to guest dirfd: fstatat directly (no /proc/self/fd string walk).
    let Some(st) = host::fstatat(host_dir, &c_rel, no_follow) else {
        return SyscallResult::err(name, ENOENT);
    };
    write_darwin_stat64_from_libc(args.x2, &st, name)
}

/// `unlink` — path `x0`.
pub(crate) fn handle_unlink(args: SyscallArgs) -> SyscallResult {
    let name = "unlink";
    if !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_path) = translate_path(&path) else {
        return SyscallResult::err(name, ENOENT);
    };
    match std::fs::remove_file(&host_path) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SyscallResult::err(name, ENOENT),
        Err(_) => SyscallResult::err(name, EPERM),
    }
}

/// `chdir` — path `x0`. Host CWD is the process working directory (see getcwd).
pub(crate) fn handle_chdir(args: SyscallArgs) -> SyscallResult {
    let name = "chdir";
    if !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_path) = translate_path(&path) else {
        return SyscallResult::err(name, ENOENT);
    };
    match std::env::set_current_dir(&host_path) {
        Ok(()) => {
            tracing::debug!(guest = %path, host = %host_path.display(), "chdir ok");
            SyscallResult::ok(name, 0)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SyscallResult::err(name, ENOENT),
        Err(_) => SyscallResult::err(name, EPERM),
    }
}

/// Darwin `__getcwd` — buf `x0`, buflen `x1`. Writes guest absolute path + NUL.
///
/// Outside the bottle, path is under `/Volumes/linux/…` so open/mkdir still
/// resolve via the host bridge symlink.
pub(crate) fn handle_getcwd(args: SyscallArgs) -> SyscallResult {
    let name = "__getcwd";
    let Ok(buflen) = usize::try_from(args.x1) else {
        return SyscallResult::err(name, EINVAL);
    };
    if buflen == 0 {
        return SyscallResult::err(name, EINVAL);
    }
    if !registry_check_range(args.x0, buflen, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(guest) = bottle::guest_cwd_string() else {
        return SyscallResult::err(name, ENOENT);
    };
    tracing::debug!(
        guest = %guest,
        host = %std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
        "getcwd"
    );
    let bytes = guest.as_bytes();
    // Need room for path + NUL.
    let need = bytes.len().saturating_add(1);
    if need > buflen {
        return SyscallResult::err(name, ERANGE);
    }
    guest_write(args.x0, bytes);
    guest_write(args.x0.saturating_add(u64::try_from(bytes.len()).unwrap_or(0)), &[0]);
    SyscallResult::ok(name, 0)
}

/// `mkdir` — path `x0`, mode `x1` (mode currently ignored; host umask applies).
pub(crate) fn handle_mkdir(args: SyscallArgs) -> SyscallResult {
    let name = "mkdir";
    if !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_path) = translate_path(&path) else {
        return SyscallResult::err(name, ENOENT);
    };
    match std::fs::create_dir(&host_path) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => SyscallResult::err(name, EEXIST),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SyscallResult::err(name, ENOENT),
        Err(_) => SyscallResult::err(name, EPERM),
    }
}

/// `rmdir` — path `x0`.
pub(crate) fn handle_rmdir(args: SyscallArgs) -> SyscallResult {
    let name = "rmdir";
    if !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_path) = translate_path(&path) else {
        return SyscallResult::err(name, ENOENT);
    };
    match std::fs::remove_dir(&host_path) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SyscallResult::err(name, ENOENT),
        Err(_) => SyscallResult::err(name, EPERM),
    }
}

/// `rename` — from `x0`, to `x1`.
pub(crate) fn handle_rename(args: SyscallArgs) -> SyscallResult {
    let name = "rename";
    if !registry_check_range(args.x0, 1, false) || !registry_check_range(args.x1, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(from) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Some(to) = bottle::read_c_string(args.x1, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_from) = translate_path(&from) else {
        return SyscallResult::err(name, ENOENT);
    };
    let Ok(host_to) = translate_path(&to) else {
        return SyscallResult::err(name, ENOENT);
    };
    match std::fs::rename(&host_from, &host_to) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SyscallResult::err(name, ENOENT),
        Err(_) => SyscallResult::err(name, EPERM),
    }
}

/// Map common host `errno` values to Darwin numbers we surface.
fn map_host_errno(host: i32) -> i64 {
    match host {
        e if e == libc::ENOENT => ENOENT,
        e if e == libc::EINVAL => EINVAL,
        e if e == libc::EEXIST => EEXIST,
        e if e == libc::EFAULT => EFAULT,
        e if e == libc::EPERM || e == libc::EACCES => EPERM,
        _ => EPERM,
    }
}

/// `readlink` — path `x0`, buf `x1`, count `x2` (no trailing NUL).
pub(crate) fn handle_readlink(args: SyscallArgs) -> SyscallResult {
    let name = "readlink";
    if !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let count = usize::try_from(args.x2).unwrap_or(0);
    if count > 0 && !registry_check_range(args.x1, count, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(path) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_path) = translate_path(&path) else {
        tracing::debug!(guest = %path, "readlink enoent (translate)");
        return SyscallResult::err(name, ENOENT);
    };
    let Ok(c_path) = std::ffi::CString::new(host_path.as_os_str().as_encoded_bytes()) else {
        return SyscallResult::err(name, EFAULT);
    };
    let mut buf = vec![0_u8; count];
    match host::readlink_path(&c_path, &mut buf) {
        Ok(n) => {
            if let Some(slice) = buf.get(..n).filter(|s| !s.is_empty()) {
                guest_write(args.x1, slice);
            }
            tracing::debug!(guest = %path, host = %host_path.display(), n, "readlink ok");
            SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
        }
        Err(e) => {
            tracing::debug!(
                guest = %path,
                host = %host_path.display(),
                errno = e,
                "readlink err"
            );
            SyscallResult::err(name, map_host_errno(e))
        }
    }
}

/// `symlink` — target `x0`, link path `x1` (both path-translated to host).
///
/// On Darwin the target string is often a guest-absolute path that dyld/the
/// kernel resolve in the same guest namespace. Under kh the host kernel follows
/// the symlink target as a **host** path, so a guest path like
/// `/Volumes/linux/out/foo` (or bottle `/Library/...`) must be stored as the
/// translated host path. Observed: modern `ld` `-lto_library` stages
/// `/tmp/ld-support-*/libLTO.dylib` → guest source; untranslated target made
/// `stat` of the link always ENOENT → infinite staging loop.
pub(crate) fn handle_symlink(args: SyscallArgs) -> SyscallResult {
    let name = "symlink";
    if !registry_check_range(args.x0, 1, false) || !registry_check_range(args.x1, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(target) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Some(link) = bottle::read_c_string(args.x1, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_target) = translate_path(&target) else {
        return SyscallResult::err(name, ENOENT);
    };
    let Ok(host_link) = translate_path(&link) else {
        return SyscallResult::err(name, ENOENT);
    };
    let Ok(c_target) = std::ffi::CString::new(host_target.as_os_str().as_encoded_bytes()) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(c_link) = std::ffi::CString::new(host_link.as_os_str().as_encoded_bytes()) else {
        return SyscallResult::err(name, EFAULT);
    };
    match host::symlink_path(&c_target, &c_link) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) => SyscallResult::err(name, map_host_errno(e)),
    }
}

/// `link` — existing `x0`, new name `x1` (hard link).
pub(crate) fn handle_link(args: SyscallArgs) -> SyscallResult {
    let name = "link";
    if !registry_check_range(args.x0, 1, false) || !registry_check_range(args.x1, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(existing) = bottle::read_c_string(args.x0, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Some(newpath) = bottle::read_c_string(args.x1, 4096) else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(host_existing) = translate_path(&existing) else {
        return SyscallResult::err(name, ENOENT);
    };
    let Ok(host_new) = translate_path(&newpath) else {
        return SyscallResult::err(name, ENOENT);
    };
    let Ok(c_existing) = std::ffi::CString::new(host_existing.as_os_str().as_encoded_bytes())
    else {
        return SyscallResult::err(name, EFAULT);
    };
    let Ok(c_new) = std::ffi::CString::new(host_new.as_os_str().as_encoded_bytes()) else {
        return SyscallResult::err(name, EFAULT);
    };
    match host::link_path(&c_existing, &c_new) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) => SyscallResult::err(name, map_host_errno(e)),
    }
}

/// `ftruncate` — fd `x0`, length `x1`.
pub(crate) fn handle_ftruncate(args: SyscallArgs) -> SyscallResult {
    let name = "ftruncate";
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let len = reg_as_i64(args.x1);
    if len < 0 {
        return SyscallResult::err(name, EINVAL);
    }
    match host::ftruncate_fd(host_fd, len) {
        Some(()) => SyscallResult::ok(name, 0),
        None => SyscallResult::err(name, EBADF),
    }
}

/// `fchmod` — fd `x0`, mode `x1` (so guest `ld` can set `+x` on products).
pub(crate) fn handle_fchmod(args: SyscallArgs) -> SyscallResult {
    let name = "fchmod";
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let mode = u32::try_from(args.x1 & 0xFFFF).unwrap_or(0);
    match host::fchmod_fd(host_fd, mode) {
        Some(()) => SyscallResult::ok(name, 0),
        None => SyscallResult::err(name, EBADF),
    }
}

/// `fsync` — fd `x0`.
pub(crate) fn handle_fsync(args: SyscallArgs) -> SyscallResult {
    let name = "fsync";
    let Some(host_fd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    match host::fsync_fd(host_fd) {
        Some(()) => SyscallResult::ok(name, 0),
        None => SyscallResult::err(name, EBADF),
    }
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
