//! POSIX / BSD file and process surface (syscalls + soft stubs).

// Freestanding scaffolding: pointer/index arithmetic and C statics (getopt).
#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::integer_division,
    static_mut_refs
)]

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};

use crate::kh_core::errno;
use crate::kh_core::heap::{free, malloc};
use crate::kh_core::sys::{
    self, SYS_ACCESS, SYS_CHDIR, SYS_CLOSE, SYS_DUP, SYS_DUP2, SYS_EXECVE, SYS_FCNTL, SYS_FCHMOD,
    SYS_IOCTL,
    SYS_FORK, SYS_FSTAT64, SYS_FSTATAT, SYS_FSYNC, SYS_FTRUNCATE, SYS_GETCWD, SYS_GETEGID,
    SYS_GETEUID, SYS_GETGID, SYS_GETPGRP, SYS_GETPID, SYS_GETPPID, SYS_GETTIMEOFDAY, SYS_GETUID,
    SYS_KILL, SYS_LINK, SYS_LSEEK, SYS_LSTAT64, SYS_MKDIR, SYS_MMAP, SYS_MPROTECT, SYS_MUNMAP,
    SYS_OPEN, SYS_OPENAT, SYS_PREAD, SYS_PWRITE, SYS_READ, SYS_READLINK, SYS_RENAME, SYS_RMDIR,
    SYS_WRITE,
    SYS_SETPGID, SYS_SETSID, SYS_SIGACTION, SYS_SIGPROCMASK, SYS_STAT64, SYS_SYMLINK, SYS_SYSCTL,
    SYS_SYSCTLBYNAME, SYS_UNLINK, SYS_VFORK, SYS_WAIT4,
};
use crate::kh_core::trace;
use crate::{
    KH_HELPER_ARGV, KH_HELPER_EXECUTABLE_PATH, KH_HELPER_GUEST_HOME, KH_HELPER_NCPU,
    KH_HELPER_PARK, KH_HELPER_READDIR, KH_HELPER_SPAWN, KH_HELPER_WAKE,
};

const ENOSYS: i32 = 78;
const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;

#[inline]
fn ptr_u64(p: *const c_void) -> u64 {
    u64::try_from(p.addr()).unwrap_or(0)
}

#[inline]
fn apply_ret(ret: isize) -> isize {
    if ret < 0 {
        errno::set_errno(i32::try_from(ret.saturating_neg()).unwrap_or(1));
    }
    ret
}

/// Map syscall `isize` to C `int` (errno already applied by [`apply_ret`]).
#[inline]
fn ret_c_int(ret: isize) -> c_int {
    let r = apply_ret(ret);
    if r < 0 {
        -1
    } else {
        c_int::try_from(r).unwrap_or(c_int::MAX)
    }
}

/// POSIX `ssize_t` success path: length; error path: **always `-1`** + errno.
///
/// Raw Darwin/BSD syscalls surface `-errno` in the register. Libc wrappers must
/// not leak that to callers — code like git's `is_reinit()` does
/// `readlink(...) != -1` and would treat `-ENOENT` as success.
#[inline]
fn ret_ssize(ret: isize) -> isize {
    let r = apply_ret(ret);
    if r < 0 { -1 } else { r }
}

#[inline]
fn ret_i64(ret: isize) -> i64 {
    let r = apply_ret(ret);
    if r < 0 {
        -1
    } else {
        i64::try_from(r).unwrap_or(-1)
    }
}

#[inline]
fn not_impl(name: &[u8]) -> c_int {
    trace::note(name);
    errno::set_errno(ENOSYS);
    -1
}

#[inline]
fn trunc_i64_to_c_int(v: i64) -> c_int {
    c_int::try_from(v).unwrap_or(if v < 0 { c_int::MIN } else { c_int::MAX })
}

// ── I/O ─────────────────────────────────────────────────────────────────────


/// Impl for C `open` (varargs wrapper in `open_varargs.c` — mode is stack-passed).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_open_impl(
    path: *const c_char,
    oflag: c_int,
    mode: c_int,
) -> c_int {
    if path.is_null() || path.addr() < crate::dylib::libsystem_c::stdio::PAGEZERO_END {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe {
        sys::syscall3(
            SYS_OPEN,
            ptr_u64(path.cast()),
            u64::from(oflag.cast_unsigned()),
            u64::from(mode.cast_unsigned()),
        )
    };
    ret_c_int(ret)
}

/// Darwin `O_RDWR | O_CREAT | O_EXCL` for [`mkstemp`].
const O_RDWR: c_int = 0x0002;
const O_CREAT: c_int = 0x0200;
const O_EXCL: c_int = 0x0800;
const EEXIST: i32 = 17;
const MKSTEMP_ALPH: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// C `mkstemp` → nlist `_mkstemp` (template ends in `XXXXXX`; rewritten in place).
///
/// Used by Apple `git init` for the symlink/case-sensitivity probe.
#[unsafe(no_mangle)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_wrap
)]
pub(crate) unsafe extern "C" fn mkstemp(template: *mut c_char) -> c_int {
    if template.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let len = unsafe { crate::dylib::libsystem_c::stdio::strlen(template) };
    if len < 6 {
        errno::set_errno(EINVAL);
        return -1;
    }
    let xs = unsafe { template.add(len.saturating_sub(6)) };
    // Verify trailing XXXXXX.
    for i in 0..6 {
        if unsafe { *xs.add(i) } != b'X'.cast_signed() {
            errno::set_errno(EINVAL);
            return -1;
        }
    }
    // Cheap LCG seed from address + length.
    let mut state = template.addr().wrapping_mul(0x9E37_79B9).wrapping_add(len);
    for _attempt in 0..256 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let mut s = state;
        for i in 0..6 {
            let idx = s % 62;
            let ch = MKSTEMP_ALPH.get(idx).copied().unwrap_or(b'0');
            unsafe {
                *xs.add(i) = ch.cast_signed();
            }
            s >>= 6;
        }
        let fd = unsafe { kh_open_impl(template, O_RDWR | O_CREAT | O_EXCL, 0o600) };
        if fd >= 0 {
            return fd;
        }
        // Retry only on EEXIST; other errors fail out.
        if errno::get_errno() != EEXIST {
            return -1;
        }
    }
    errno::set_errno(EEXIST);
    -1
}

/// Impl for C `openat` (varargs wrapper in `open_varargs.c`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_openat_impl(
    fd: c_int,
    path: *const c_char,
    oflag: c_int,
    mode: c_int,
) -> c_int {
    if path.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe {
        sys::syscall6(
            SYS_OPENAT,
            u64::from(fd.cast_unsigned()),
            ptr_u64(path.cast()),
            u64::from(oflag.cast_unsigned()),
            u64::from(mode.cast_unsigned()),
            0,
            0,
        )
    };
    ret_c_int(ret)
}

/// C `close` → nlist `_close`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn close(fd: c_int) -> c_int {
    let ret = unsafe { sys::syscall1(SYS_CLOSE, u64::from(fd.cast_unsigned())) };
    ret_c_int(ret)
}

/// Impl for C `fcntl` (varargs wrapper in `fcntl_varargs.c`).
///
/// Darwin `fcntl` is `int fcntl(int, int, ...)`; on Apple arm64 the optional
/// third argument is **stack-passed**. A fixed 3-arg Rust export never saw
/// `O_NONBLOCK` from curl multi → wakeup-pipe `read` hung (tier1).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_fcntl_impl(fd: c_int, cmd: c_int, arg: u64) -> c_int {
    let ret = unsafe {
        sys::syscall3(
            SYS_FCNTL,
            u64::from(fd.cast_unsigned()),
            u64::from(cmd.cast_unsigned()),
            arg,
        )
    };
    ret_c_int(ret)
}

/// C `read` → nlist `_read`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, nbyte: usize) -> isize {
    if buf.is_null() && nbyte > 0 {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe {
        sys::syscall3(
            SYS_READ,
            u64::from(fd.cast_unsigned()),
            ptr_u64(buf),
            u64::try_from(nbyte).unwrap_or(0),
        )
    };
    ret_ssize(ret)
}

/// C `lseek` → nlist `_lseek`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    let ret = unsafe {
        sys::syscall3(
            SYS_LSEEK,
            u64::from(fd.cast_unsigned()),
            offset.cast_unsigned(),
            u64::from(whence.cast_unsigned()),
        )
    };
    ret_i64(ret)
}

/// C `pread` → nlist `_pread` (read at offset without changing file position).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pread(
    fd: c_int,
    buf: *mut c_void,
    nbyte: usize,
    offset: i64,
) -> isize {
    if buf.is_null() && nbyte > 0 {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe {
        sys::syscall4(
            SYS_PREAD,
            u64::from(fd.cast_unsigned()),
            ptr_u64(buf),
            u64::try_from(nbyte).unwrap_or(0),
            offset.cast_unsigned(),
        )
    };
    ret_ssize(ret)
}

/// C `pwrite` → nlist `_pwrite`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pwrite(
    fd: c_int,
    buf: *const c_void,
    nbyte: usize,
    offset: i64,
) -> isize {
    if buf.is_null() && nbyte > 0 {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe {
        sys::syscall4(
            SYS_PWRITE,
            u64::from(fd.cast_unsigned()),
            ptr_u64(buf),
            u64::try_from(nbyte).unwrap_or(0),
            offset.cast_unsigned(),
        )
    };
    ret_ssize(ret)
}

/// C `fstat` → nlist `_fstat` (stat64 buffer).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fstat(fd: c_int, buf: *mut c_void) -> c_int {
    if buf.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe { sys::syscall2(SYS_FSTAT64, u64::from(fd.cast_unsigned()), ptr_u64(buf)) };
    ret_c_int(ret)
}

/// C `stat` → nlist `_stat`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn stat(path: *const c_char, buf: *mut c_void) -> c_int {
    if path.is_null() || buf.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe { sys::syscall2(SYS_STAT64, ptr_u64(path.cast()), ptr_u64(buf)) };
    ret_c_int(ret)
}

/// C `lstat` → nlist `_lstat`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn lstat(path: *const c_char, buf: *mut c_void) -> c_int {
    if path.is_null() || buf.is_null() {
        errno::set_errno(14);
        return -1;
    }
    // Prefer lstat64; runtime may ENOSYS until wired.
    let ret = unsafe { sys::syscall2(SYS_LSTAT64, ptr_u64(path.cast()), ptr_u64(buf)) };
    ret_c_int(ret)
}

/// C `fstatat` → nlist `_fstatat`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fstatat(
    fd: c_int,
    path: *const c_char,
    buf: *mut c_void,
    flag: c_int,
) -> c_int {
    if path.is_null() || buf.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe {
        sys::syscall6(
            SYS_FSTATAT,
            u64::from(fd.cast_unsigned()),
            ptr_u64(path.cast()),
            ptr_u64(buf),
            u64::from(flag.cast_unsigned()),
            0,
            0,
        )
    };
    ret_c_int(ret)
}

/// Darwin `clonefile(2)` flags (public man page).
const CLONE_NOFOLLOW: u32 = 0x0001;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const STAT64_MODE_OFF: usize = 4;
const STAT64_SIZE_OFF: usize = 96;
const S_IFMT_U16: u16 = 0o170_000;
const S_IFDIR_U16: u16 = 0o040_000;

fn stat64_mode(buf: &[u8; 144]) -> u16 {
    let b = [buf[STAT64_MODE_OFF], buf[STAT64_MODE_OFF + 1]];
    u16::from_le_bytes(b)
}

fn stat64_size(buf: &[u8; 144]) -> i64 {
    let mut b = [0_u8; 8];
    b.copy_from_slice(&buf[STAT64_SIZE_OFF..STAT64_SIZE_OFF + 8]);
    i64::from_le_bytes(b)
}

fn copy_fd_to_path(src_fd: c_int, dst_dirfd: c_int, dst: *const c_char, mode: c_int) -> c_int {
    let out = unsafe { kh_openat_impl(dst_dirfd, dst, O_WRONLY | O_CREAT | O_EXCL, mode) };
    if out < 0 {
        return -1;
    }
    let mut buf = [0_u8; 8192];
    loop {
        let n = unsafe { read(src_fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let _ = unsafe { close(out) };
            let _ = unlinkat_best_effort(dst_dirfd, dst);
            return -1;
        }
        if n == 0 {
            break;
        }
        let mut off = 0_usize;
        let total = usize::try_from(n).unwrap_or(0);
        while off < total {
            let w = unsafe {
                sys::syscall3(
                    SYS_WRITE,
                    u64::from(out.cast_unsigned()),
                    ptr_u64(buf.as_ptr().add(off).cast()),
                    u64::try_from(total.saturating_sub(off)).unwrap_or(0),
                )
            };
            if w <= 0 {
                let _ = unsafe { close(out) };
                let _ = unlinkat_best_effort(dst_dirfd, dst);
                return -1;
            }
            off = off.saturating_add(usize::try_from(w).unwrap_or(0));
        }
    }
    let _ = unsafe { close(out) };
    0
}

fn unlinkat_best_effort(dirfd: c_int, path: *const c_char) -> c_int {
    // Best-effort: open+unlink via unlink() when path is absolute-looking; else ignore.
    if path.is_null() {
        return -1;
    }
    let _ = dirfd;
    unsafe { unlink(path) }
}

/// C `fclonefileat` → nlist `_fclonefileat` (copy; Linux has no APFS clone).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fclonefileat(
    srcfd: c_int,
    dst_dirfd: c_int,
    dst: *const c_char,
    _flags: u32,
) -> c_int {
    if dst.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let mut st = [0_u8; 144];
    if unsafe { fstat(srcfd, st.as_mut_ptr().cast()) } != 0 {
        return -1;
    }
    if stat64_mode(&st) & S_IFMT_U16 == S_IFDIR_U16 {
        errno::set_errno(21); // EISDIR
        return -1;
    }
    let mode = c_int::from(stat64_mode(&st) & 0o777);
    let _ = stat64_size(&st);
    copy_fd_to_path(srcfd, dst_dirfd, dst, mode)
}

/// C `clonefileat` → nlist `_clonefileat`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn clonefileat(
    src_dirfd: c_int,
    src: *const c_char,
    dst_dirfd: c_int,
    dst: *const c_char,
    flags: u32,
) -> c_int {
    if src.is_null() || dst.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let src_fd = unsafe { kh_openat_impl(src_dirfd, src, O_RDONLY, 0) };
    if src_fd < 0 {
        return -1;
    }
    if flags & CLONE_NOFOLLOW != 0 {
        // Source already opened without O_NOFOLLOW; soft: proceed as a copy.
    }
    let rc = unsafe { fclonefileat(src_fd, dst_dirfd, dst, flags) };
    let _ = unsafe { close(src_fd) };
    rc
}

/// C `clonefile` → nlist `_clonefile`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn clonefile(
    src: *const c_char,
    dst: *const c_char,
    flags: u32,
) -> c_int {
    const AT_FDCWD: c_int = -2;
    unsafe { clonefileat(AT_FDCWD, src, AT_FDCWD, dst, flags) }
}

/// C `ftruncate` → nlist `_ftruncate`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ftruncate(fd: c_int, length: i64) -> c_int {
    let ret = unsafe {
        sys::syscall2(
            SYS_FTRUNCATE,
            u64::from(fd.cast_unsigned()),
            length.cast_unsigned(),
        )
    };
    ret_c_int(ret)
}

/// C `fsync` → nlist `_fsync`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fsync(fd: c_int) -> c_int {
    let ret = unsafe { sys::syscall1(SYS_FSYNC, u64::from(fd.cast_unsigned())) };
    ret_c_int(ret)
}

// ── path ops ────────────────────────────────────────────────────────────────

/// C `unlink` → nlist `_unlink`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    if path.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe { sys::syscall1(SYS_UNLINK, ptr_u64(path.cast())) };
    ret_c_int(ret)
}

/// C `remove` → nlist `_remove` (file unlink; directories may need rmdir).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn remove(path: *const c_char) -> c_int {
    // SAFETY: same contract as unlink.
    unsafe { unlink(path) }
}

/// C `rename` → nlist `_rename`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rename(from: *const c_char, to: *const c_char) -> c_int {
    if from.is_null() || to.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe { sys::syscall2(SYS_RENAME, ptr_u64(from.cast()), ptr_u64(to.cast())) };
    ret_c_int(ret)
}

/// C `mkdir` → nlist `_mkdir`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mkdir(path: *const c_char, mode: c_int) -> c_int {
    if path.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe {
        sys::syscall2(
            SYS_MKDIR,
            ptr_u64(path.cast()),
            u64::from(mode.cast_unsigned()),
        )
    };
    ret_c_int(ret)
}

/// C `rmdir` → nlist `_rmdir`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    if path.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe { sys::syscall1(SYS_RMDIR, ptr_u64(path.cast())) };
    ret_c_int(ret)
}

/// C `chdir` → nlist `_chdir` (host CWD via BSD `chdir`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn chdir(path: *const c_char) -> c_int {
    if path.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe { sys::syscall1(SYS_CHDIR, ptr_u64(path.cast())) };
    ret_c_int(ret)
}

/// C `getcwd` → nlist `_getcwd` (via Darwin `__getcwd` → guest absolute path).
///
/// Outside the bottle the path is under `/Volumes/linux/…` so absolute
/// open/mkdir still reach the host FS through the bottle bridge.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getcwd(buf: *mut c_char, size: usize) -> *mut c_char {
    // Darwin: `buf == NULL` allocates (as if by malloc). `size == 0` with a
    // non-null buf is EINVAL; with a null buf, pick a PATH_MAX-class buffer.
    let (out, cap, allocated) = if buf.is_null() {
        let cap = if size == 0 { 1024 } else { size };
        let p = unsafe { malloc(cap) }.cast::<c_char>();
        if p.is_null() {
            errno::set_errno(ENOMEM);
            return core::ptr::null_mut();
        }
        (p, cap, true)
    } else {
        if size == 0 {
            errno::set_errno(EINVAL);
            return core::ptr::null_mut();
        }
        (buf, size, false)
    };
    let ret = unsafe {
        sys::syscall2(
            SYS_GETCWD,
            ptr_u64(out.cast()),
            u64::try_from(cap).unwrap_or(0),
        )
    };
    if ret < 0 {
        let _ = apply_ret(ret);
        if allocated {
            unsafe {
                free(out.cast());
            }
        }
        return core::ptr::null_mut();
    }
    out
}

/// C `chmod` → nlist `_chmod` (soft success for path mode; prefer `fchmod` for `+x`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn chmod(_path: *const c_char, _mode: c_int) -> c_int {
    0
}

/// C `fchmod` → nlist `_fchmod` (real BSD; guest `ld` sets executable bits).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fchmod(fd: c_int, mode: c_int) -> c_int {
    let ret = unsafe {
        sys::syscall2(
            SYS_FCHMOD,
            u64::from(fd.cast_unsigned()),
            u64::from(mode.cast_unsigned()),
        )
    };
    ret_c_int(ret)
}

/// C `fchmodat` → nlist `_fchmodat` (`chmod` after `fts_*`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fchmodat(
    fd: c_int,
    path: *const c_char,
    mode: c_int,
    _flag: c_int,
) -> c_int {
    if path.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ofd = unsafe { kh_openat_impl(fd, path, 0, 0) };
    if ofd < 0 {
        return -1;
    }
    let rc = unsafe { fchmod(ofd, mode) };
    let _ = unsafe { close(ofd) };
    rc
}

/// C `chown` → nlist `_chown`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn chown(_path: *const c_char, _uid: u32, _gid: u32) -> c_int {
    not_impl(b"[kh-libsystem] chown ENOSYS\n")
}

/// C `link` → nlist `_link` (hard link: `path` → existing, `link` → new name).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn link(path: *const c_char, link: *const c_char) -> c_int {
    if path.is_null() || link.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe { sys::syscall2(SYS_LINK, ptr_u64(path.cast()), ptr_u64(link.cast())) };
    ret_c_int(ret)
}

/// C `symlink` → nlist `_symlink` (`path` = target, `link` = new symlink path).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn symlink(path: *const c_char, link: *const c_char) -> c_int {
    if path.is_null() || link.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe { sys::syscall2(SYS_SYMLINK, ptr_u64(path.cast()), ptr_u64(link.cast())) };
    ret_c_int(ret)
}

/// C `readlink` → nlist `_readlink` (bytes written; no trailing NUL).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn readlink(
    path: *const c_char,
    buf: *mut c_char,
    bufsize: usize,
) -> isize {
    if path.is_null() || buf.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe {
        sys::syscall3(
            SYS_READLINK,
            ptr_u64(path.cast()),
            ptr_u64(buf.cast()),
            u64::try_from(bufsize).unwrap_or(0),
        )
    };
    ret_ssize(ret)
}

/// C `umask` → nlist `_umask` (returns previous fixed mask).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn umask(cmask: c_int) -> c_int {
    static mut PREV: c_int = 0o022;
    unsafe {
        let old = PREV;
        PREV = cmask & 0o777;
        old
    }
}

/// C `utime` → nlist `_utime` (soft success; Apple `git add` index refresh).
///
/// Older libc API (`struct utimbuf *`); siblings `utimes` / `utimensat` already
/// soft-succeed. Without this export, dyld binds a missing trampoline → exit 127.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn utime(_path: *const c_char, _times: *const c_void) -> c_int {
    0
}

/// C `utimensat` → nlist `_utimensat` (soft success; mtime not applied).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn utimensat(
    _fd: c_int,
    _path: *const c_char,
    _times: *const c_void,
    _flag: c_int,
) -> c_int {
    0
}

/// C `utimes` → nlist `_utimes` (soft success; curl `-R` / `--remote-time`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn utimes(_path: *const c_char, _times: *const c_void) -> c_int {
    0
}

/// C `futimes` → nlist `_futimes` (soft success).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn futimes(_fd: c_int, _times: *const c_void) -> c_int {
    0
}

/// C `lutimes` → nlist `_lutimes` (soft success).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn lutimes(_path: *const c_char, _times: *const c_void) -> c_int {
    0
}

/// C `fsetxattr` → nlist `_fsetxattr` (soft success; curl `--xattr`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fsetxattr(
    _fd: c_int,
    _name: *const c_char,
    _value: *const c_void,
    _size: usize,
    _position: u32,
    _options: c_int,
) -> c_int {
    0
}

/// C `setxattr` → nlist `_setxattr` (soft success).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setxattr(
    _path: *const c_char,
    _name: *const c_char,
    _value: *const c_void,
    _size: usize,
    _position: u32,
    _options: c_int,
) -> c_int {
    0
}

// ── dirent ──────────────────────────────────────────────────────────────────
//
// `opendir` opens the path as a directory FD. `readdir` fills a Darwin-shaped
// `struct dirent` via host helper `KH_HELPER_READDIR` (Linux `fdopendir`/`readdir`
// under the bottle). Required for recursive archive of real directory trees.

const DIR_MAGIC: u32 = 0x4B48_4449; // "KHDI"
const DIRENT_NAME_OFF: usize = 21;
const DIRENT_SIZE: usize = 1048;

/// Darwin `struct dirent` layout (arm64) packed into `ent`.
#[repr(C)]
struct DirStub {
    magic: u32,
    fd: c_int,
    reserved: u32,
    /// Full Darwin dirent buffer returned to the guest.
    ent: [u8; DIRENT_SIZE],
    /// Scratch for host helper name out.
    name_scratch: [u8; 256],
    d_type_scratch: u8,
}

/// C `opendir` → nlist `_opendir`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn opendir(name: *const c_char) -> *mut c_void {
    if name.is_null() {
        errno::set_errno(14);
        return core::ptr::null_mut();
    }
    // O_RDONLY = 0. Directory open succeeds on Linux when path is a dir.
    let fd = unsafe { kh_open_impl(name, 0, 0) };
    if fd < 0 {
        return core::ptr::null_mut();
    }
    let raw = unsafe { malloc(core::mem::size_of::<DirStub>()) };
    if raw.is_null() {
        let _ = unsafe { close(fd) };
        errno::set_errno(ENOMEM);
        return core::ptr::null_mut();
    }
    let d = raw.cast::<DirStub>();
    unsafe {
        (*d).magic = DIR_MAGIC;
        (*d).fd = fd;
        (*d).reserved = 0;
        crate::dylib::libsystem_c::stdio::bzero((*d).ent.as_mut_ptr().cast(), (*d).ent.len());
        crate::dylib::libsystem_c::stdio::bzero(
            (*d).name_scratch.as_mut_ptr().cast(),
            (*d).name_scratch.len(),
        );
        (*d).d_type_scratch = 0;
    }
    raw
}

/// C `closedir` → nlist `_closedir`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn closedir(dirp: *mut c_void) -> c_int {
    if dirp.is_null() {
        errno::set_errno(9);
        return -1;
    }
    let d = dirp.cast::<DirStub>();
    if unsafe { (*d).magic } != DIR_MAGIC {
        errno::set_errno(9);
        return -1;
    }
    let fd = unsafe { (*d).fd };
    unsafe {
        (*d).magic = 0;
        let _ = close(fd);
        free(dirp);
    }
    0
}

/// C `readdir` → nlist `_readdir`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn readdir(dirp: *mut c_void) -> *mut c_void {
    if dirp.is_null() {
        errno::set_errno(9);
        return core::ptr::null_mut();
    }
    let d = dirp.cast::<DirStub>();
    if unsafe { (*d).magic } != DIR_MAGIC {
        errno::set_errno(9);
        return core::ptr::null_mut();
    }

    let fd = unsafe { (*d).fd };
    let name_ptr = unsafe { (*d).name_scratch.as_mut_ptr() };
    let dtype_ptr = unsafe { core::ptr::addr_of_mut!((*d).d_type_scratch) };

    // KH_HELPER_READDIR(fd, name_buf, &d_type) → 1 entry / 0 EOF / -errno
    let ret = unsafe {
        sys::helper3(
            KH_HELPER_READDIR,
            u64::from(fd.cast_unsigned()),
            ptr_u64(name_ptr.cast()),
            ptr_u64(dtype_ptr.cast()),
        )
    };
    if ret < 0 {
        errno::set_errno(i32::try_from(ret.saturating_neg()).unwrap_or(1));
        return core::ptr::null_mut();
    }
    if ret == 0 {
        return core::ptr::null_mut();
    }

    // Pack Darwin dirent into `ent`.
    unsafe {
        let ent = (*d).ent.as_mut_ptr();
        crate::dylib::libsystem_c::stdio::bzero(ent.cast(), DIRENT_SIZE);
        // d_ino = 1 (non-zero), d_seekoff = 0
        let ino: u64 = 1;
        core::ptr::copy_nonoverlapping(ino.to_ne_bytes().as_ptr(), ent, 8);
        // d_reclen at +16
        let reclen: u16 = u16::try_from(DIRENT_SIZE).unwrap_or(u16::MAX);
        core::ptr::copy_nonoverlapping(reclen.to_ne_bytes().as_ptr(), ent.add(16), 2);
        // name length
        let mut namelen = 0_usize;
        while namelen < 255 {
            match (*d).name_scratch.get(namelen) {
                Some(&0) | None => break,
                Some(_) => namelen = namelen.saturating_add(1),
            }
        }
        let namelen_u: u16 = u16::try_from(namelen).unwrap_or(0);
        core::ptr::copy_nonoverlapping(namelen_u.to_ne_bytes().as_ptr(), ent.add(18), 2);
        // d_type at +20
        ent.add(20).write((*d).d_type_scratch);
        // d_name at +21
        core::ptr::copy_nonoverlapping(
            (*d).name_scratch.as_ptr(),
            ent.add(DIRENT_NAME_OFF),
            namelen.saturating_add(1).min(1024),
        );
        ent.cast::<c_void>()
    }
}

/// C `readdir_r` → nlist `_readdir_r` (rustup toolchain scan).
///
/// Fills the caller `entry` buffer (Darwin `struct dirent`) and sets `*result`
/// to `entry`, or to NULL at EOF. Returns 0 on success/EOF.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn readdir_r(
    dirp: *mut c_void,
    entry: *mut c_void,
    result: *mut *mut c_void,
) -> c_int {
    if dirp.is_null() || entry.is_null() || result.is_null() {
        errno::set_errno(22);
        return 22;
    }
    let ent = unsafe { readdir(dirp) };
    if ent.is_null() {
        unsafe {
            *result = core::ptr::null_mut();
        }
        return 0;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(ent.cast::<u8>(), entry.cast::<u8>(), DIRENT_SIZE);
        *result = entry;
    }
    0
}

/// C `dirfd` → nlist `_dirfd`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dirfd(dirp: *mut c_void) -> c_int {
    if dirp.is_null() {
        errno::set_errno(9);
        return -1;
    }
    let d = dirp.cast::<DirStub>();
    if unsafe { (*d).magic } != DIR_MAGIC {
        errno::set_errno(9);
        return -1;
    }
    unsafe { (*d).fd }
}

// ── process / misc ──────────────────────────────────────────────────────────

/// C `fork` → nlist `_fork` (host `fork` via runtime; parent pid / child 0).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fork() -> c_int {
    ret_c_int(unsafe { sys::syscall0(SYS_FORK) })
}

/// C `vfork` → nlist `_vfork` (implemented as `fork` in the translator).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn vfork() -> c_int {
    ret_c_int(unsafe { sys::syscall0(SYS_VFORK) })
}

/// C `wait` → nlist `_wait` (CLT `ar` may re-exec / wait children).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wait(status: *mut c_int) -> c_int {
    unsafe { waitpid(-1, status, 0) }
}

/// C `waitpid` → nlist `_waitpid` (`wait4` without rusage).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    ret_c_int(unsafe {
        sys::syscall4(
            SYS_WAIT4,
            u64::from(pid.cast_unsigned()),
            ptr_u64(status.cast()),
            u64::from(options.cast_unsigned()),
            0,
        )
    })
}

/// C `wait4` → nlist `_wait4` (rusage soft-zeroed by runtime when non-null).
///
/// Observed: Apple clang parent after `posix_spawn` of `-cc1`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wait4(
    pid: c_int,
    status: *mut c_int,
    options: c_int,
    rusage: *mut c_void,
) -> c_int {
    ret_c_int(unsafe {
        sys::syscall4(
            SYS_WAIT4,
            u64::from(pid.cast_unsigned()),
            ptr_u64(status.cast()),
            u64::from(options.cast_unsigned()),
            ptr_u64(rusage.cast_const()),
        )
    })
}

/// C `wait3` → nlist `_wait3` (`wait4(-1, …)`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn wait3(
    status: *mut c_int,
    options: c_int,
    rusage: *mut c_void,
) -> c_int {
    unsafe { wait4(-1, status, options, rusage) }
}

/// C `catopen` → nlist `_catopen` (no message catalogs).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn catopen(_name: *const c_char, _oflag: c_int) -> *mut c_void {
    core::ptr::with_exposed_provenance_mut(1)
}

/// C `catgets` → nlist `_catgets` (return the default string).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn catgets(
    _catd: *mut c_void,
    _set_id: c_int,
    _msg_id: c_int,
    s: *const c_char,
) -> *mut c_char {
    s.cast_mut()
}

/// C `catclose` → nlist `_catclose`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn catclose(_catd: *mut c_void) -> c_int {
    0
}

/// C `crypt` → nlist `_crypt` (static dummy; not a real password hash).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn crypt(_key: *const c_char, salt: *const c_char) -> *mut c_char {
    static mut OUT: [u8; 16] = *b"xx.............\0";
    if !salt.is_null() {
        let a = unsafe { *salt }.cast_unsigned();
        let b = unsafe { *salt.add(1) }.cast_unsigned();
        unsafe {
            OUT[0] = if a == 0 { b'x' } else { a };
            OUT[1] = if b == 0 { b'x' } else { b };
        }
    }
    unsafe { OUT.as_mut_ptr().cast() }
}

/// C `alarm` → nlist `_alarm` (no real SIGALRM; remaining time always 0).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn alarm(_seconds: u32) -> u32 {
    0
}

/// C `setpriority` → nlist `_setpriority` (soft success).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setpriority(_which: c_int, _who: c_int, _prio: c_int) -> c_int {
    0
}

/// C `setutxent` / `endutxent` / `getutxent` → no utmpx database.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setutxent() {}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn endutxent() {}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getutxent() -> *mut c_void {
    core::ptr::null_mut()
}

/// C `setsid` → nlist `_setsid` (new session; used by git maintenance).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setsid() -> c_int {
    ret_c_int(unsafe { sys::syscall0(SYS_SETSID) })
}

/// C `setpgid` → nlist `_setpgid`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setpgid(pid: c_int, pgid: c_int) -> c_int {
    ret_c_int(unsafe {
        sys::syscall2(
            SYS_SETPGID,
            u64::from(pid.cast_unsigned()),
            u64::from(pgid.cast_unsigned()),
        )
    })
}

/// C `getpgrp` → nlist `_getpgrp`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpgrp() -> c_int {
    ret_c_int(unsafe { sys::syscall0(SYS_GETPGRP) })
}

/// C `getpgid` → nlist `_getpgid` (pid 0 → self).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpgid(pid: c_int) -> c_int {
    if pid == 0 {
        return unsafe { getpgrp() };
    }
    // Soft: no full process table; treat as own group if positive pid.
    if pid < 0 {
        errno::set_errno(3); // ESRCH
        return -1;
    }
    // Best-effort: return the pid as pgid (single-session bottle).
    pid
}

/// Darwin `TIOCGPGRP` (`_IOR('t', 119, int)`).
const TIOCGPGRP: u64 = 0x4004_7477;
/// Darwin `TIOCSPGRP` (`_IOW('t', 118, int)`).
const TIOCSPGRP: u64 = 0x8004_7476;
/// Darwin `TIOCGETA` (`_IOR('t', 19, struct termios)`, arm64 size 72).
const TIOCGETA: u64 = 0x4048_7413;

/// C `tcgetpgrp` → `ioctl(TIOCGPGRP)` (host controlling tty).
///
/// Observed: Apple `git index-pack -v` probes controlling-terminal pgrp.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    let mut pgrp = 0_i32;
    let ret = unsafe {
        sys::syscall3(
            SYS_IOCTL,
            u64::from(fd.cast_unsigned()),
            TIOCGPGRP,
            ptr_u64(core::ptr::from_mut(&mut pgrp).cast()),
        )
    };
    if apply_ret(ret) < 0 {
        -1
    } else {
        pgrp
    }
}

/// C `tcsetpgrp` → `ioctl(TIOCSPGRP)`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcsetpgrp(fd: c_int, pgrp: c_int) -> c_int {
    let mut pg = pgrp;
    ret_c_int(unsafe {
        sys::syscall3(
            SYS_IOCTL,
            u64::from(fd.cast_unsigned()),
            TIOCSPGRP,
            ptr_u64(core::ptr::from_mut(&mut pg).cast()),
        )
    })
}

/// C `kill` → nlist `_kill`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kill(pid: c_int, sig: c_int) -> c_int {
    ret_c_int(unsafe {
        sys::syscall2(
            SYS_KILL,
            u64::from(pid.cast_unsigned()),
            u64::from(sig.cast_unsigned()),
        )
    })
}

/// C `dup` → nlist `_dup`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dup(fd: c_int) -> c_int {
    ret_c_int(unsafe { sys::syscall1(SYS_DUP, u64::from(fd.cast_unsigned())) })
}

/// C `dup2` → nlist `_dup2`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    ret_c_int(unsafe {
        sys::syscall2(
            SYS_DUP2,
            u64::from(oldfd.cast_unsigned()),
            u64::from(newfd.cast_unsigned()),
        )
    })
}

/// C `execve` → nlist `_execve` (runtime re-execs `kh run` for Mach-O).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    ret_c_int(unsafe {
        sys::syscall3(
            SYS_EXECVE,
            ptr_u64(path.cast()),
            ptr_u64(argv.cast()),
            ptr_u64(envp.cast()),
        )
    })
}

/// C `execv` → nlist `_execv` (`execve` with current `environ`).
///
/// GNU make / shell spawn paths call this (not always `execve`/`execvp`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    soft_env_seed_defaults();
    let envp = unsafe { environ };
    unsafe { execve(path, argv, envp.cast_const().cast()) }
}

/// C `execvp` → nlist `_execvp` (PATH search then [`execve`]).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    if file.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    // Absolute / relative with slash → direct execve with current environ.
    let has_slash = unsafe {
        let mut p = file;
        loop {
            let b = *p;
            if b == 0 {
                break false;
            }
            if b == b'/'.cast_signed() {
                break true;
            }
            p = p.add(1);
        }
    };
    let envp = unsafe { environ };
    if has_slash {
        return unsafe { execve(file, argv, envp.cast_const().cast()) };
    }

    soft_env_seed_defaults();
    let path_key: &[u8] = b"PATH\0";
    let path_val = unsafe { getenv(path_key.as_ptr().cast()) };
    if path_val.is_null() {
        errno::set_errno(2); // ENOENT
        return -1;
    }
    // Walk PATH=a:b:c
    let mut dir = path_val;
    let mut candidate = [0_u8; 512];
    loop {
        // Find next ':' or NUL.
        let mut end = dir;
        unsafe {
            while *end != 0 && *end != b':'.cast_signed() {
                end = end.add(1);
            }
        }
        let dir_len = usize::try_from(unsafe { end.offset_from(dir) }.max(0)).unwrap_or(0);
        let file_len = soft_env_c_str_len(file);
        let need = dir_len
            .max(1)
            .saturating_add(1)
            .saturating_add(file_len)
            .saturating_add(1);
        if need <= candidate.len() {
            let mut n = if dir_len == 0 {
                // empty PATH component → "."
                if let Some(slot) = candidate.get_mut(0) {
                    *slot = b'.';
                }
                1_usize
            } else {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        dir.cast::<u8>(),
                        candidate.as_mut_ptr(),
                        dir_len,
                    );
                }
                dir_len
            };
            if let Some(slot) = candidate.get_mut(n) {
                *slot = b'/';
            }
            n = n.saturating_add(1);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    file.cast::<u8>(),
                    candidate.as_mut_ptr().add(n),
                    file_len,
                );
            }
            n = n.saturating_add(file_len);
            if let Some(slot) = candidate.get_mut(n) {
                *slot = 0;
            }
            let rc = unsafe { execve(candidate.as_ptr().cast(), argv, envp.cast_const().cast()) };
            if rc != -1 {
                return rc;
            }
        }
        unsafe {
            if *end == 0 {
                break;
            }
            dir = end.add(1);
        }
    }
    // Last errno from execve attempts.
    -1
}

/// C `execl` → nlist `_execl` (varargs not supported; soft fail).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn execl(_path: *const c_char, _arg0: *const c_char) -> c_int {
    errno::set_errno(ENOSYS);
    -1
}

/// C `execlp` → nlist `_execlp` (varargs not supported; soft fail).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn execlp(_file: *const c_char, _arg0: *const c_char) -> c_int {
    errno::set_errno(ENOSYS);
    -1
}

// ── posix_spawn (clang driver spawns -cc1; POSIX return = errno, not -1) ─────

/// Host-side spawn via `KH_HELPER_SPAWN` (no guest `fork` of large maps).
///
/// Soft: ignore `file_actions` / `attrp` (no chdir/dup2/close list yet).
/// Observed: Apple clang G3 compile path hits `_posix_spawn` after G1 works.
///
/// Contract (POSIX / public man): **0** on success, error number on failure
/// (does not use the `-1` + errno libc pattern).
///
/// Process model: previously this did guest `fork`+`execve`, which CoW-duplicated
/// the whole guest address space (CLT `clang` ~hundreds of MiB) before nested
/// `kh run` replaced the image. The helper host-`posix_spawn`s nested `kh`
/// directly — same semantics for Mach-O children, far less tax.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawn(
    pid: *mut c_int,
    path: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if path.is_null() || argv.is_null() {
        return EINVAL;
    }
    // Soft until a guest fails without redirects / spawn flags.
    if !file_actions.is_null() {
        trace::note(b"[kh-libsystem] posix_spawn: file_actions soft-ignored\n");
    }
    if !attrp.is_null() {
        trace::note(b"[kh-libsystem] posix_spawn: attrp soft-ignored\n");
    }
    let env = if envp.is_null() {
        soft_env_seed_defaults();
        unsafe { environ.cast_const().cast() }
    } else {
        envp
    };
    // path / argv / envp are guest VAs (identity map under freestanding).
    let rc = unsafe {
        sys::helper3(
            KH_HELPER_SPAWN,
            u64::try_from(path.addr()).unwrap_or(0),
            u64::try_from(argv.addr()).unwrap_or(0),
            u64::try_from(env.addr()).unwrap_or(0),
        )
    };
    if rc < 0 {
        // Host helper: carry set → positive errno in x0; thin wrapper → -errno.
        let err = rc.saturating_neg();
        return c_int::try_from(err).unwrap_or(EINVAL);
    }
    let child = c_int::try_from(rc).unwrap_or(0);
    if !pid.is_null() {
        unsafe {
            pid.write(child);
        }
    }
    0
}

/// C `posix_spawnp` → nlist `_posix_spawnp` (PATH search then [`posix_spawn`]).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawnp(
    pid: *mut c_int,
    file: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if file.is_null() || argv.is_null() {
        return EINVAL;
    }
    let has_slash = unsafe {
        let mut p = file;
        loop {
            let b = *p;
            if b == 0 {
                break false;
            }
            if b == b'/'.cast_signed() {
                break true;
            }
            p = p.add(1);
        }
    };
    if has_slash {
        return unsafe { posix_spawn(pid, file, file_actions, attrp, argv, envp) };
    }
    soft_env_seed_defaults();
    let path_key: &[u8] = b"PATH\0";
    let path_val = unsafe { getenv(path_key.as_ptr().cast()) };
    if path_val.is_null() {
        return 2; // ENOENT
    }
    let mut dir = path_val;
    let mut candidate = [0_u8; 512];
    let mut last_err = 2_i32; // ENOENT
    loop {
        let mut end = dir;
        unsafe {
            while *end != 0 && *end != b':'.cast_signed() {
                end = end.add(1);
            }
        }
        let dir_len = usize::try_from(unsafe { end.offset_from(dir) }.max(0)).unwrap_or(0);
        let file_len = soft_env_c_str_len(file);
        let need = dir_len
            .max(1)
            .saturating_add(1)
            .saturating_add(file_len)
            .saturating_add(1);
        if need <= candidate.len() {
            let mut n = if dir_len == 0 {
                if let Some(slot) = candidate.get_mut(0) {
                    *slot = b'.';
                }
                1_usize
            } else {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        dir.cast::<u8>(),
                        candidate.as_mut_ptr(),
                        dir_len,
                    );
                }
                dir_len
            };
            if let Some(slot) = candidate.get_mut(n) {
                *slot = b'/';
            }
            n = n.saturating_add(1);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    file.cast::<u8>(),
                    candidate.as_mut_ptr().add(n),
                    file_len,
                );
            }
            n = n.saturating_add(file_len);
            if let Some(slot) = candidate.get_mut(n) {
                *slot = 0;
            }
            let rc = unsafe {
                posix_spawn(
                    pid,
                    candidate.as_ptr().cast(),
                    file_actions,
                    attrp,
                    argv,
                    envp,
                )
            };
            if rc == 0 {
                return 0;
            }
            // Keep trying on "not found"; surface other errors immediately.
            if rc != 2 {
                return rc;
            }
            last_err = rc;
        }
        unsafe {
            if *end == 0 {
                break;
            }
            dir = end.add(1);
        }
    }
    last_err
}

/// Opaque `posix_spawnattr_t` / `posix_spawn_file_actions_t` are Darwin
/// pointer typedefs (`void *` style). Soft: zero the caller's slot so destroy
/// is a no-op; add* helpers no-op. Real apply lives in [`posix_spawn`] later.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawnattr_init(attr: *mut *mut c_void) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    unsafe {
        attr.write(core::ptr::null_mut());
    }
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawnattr_destroy(attr: *mut *mut c_void) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    unsafe {
        attr.write(core::ptr::null_mut());
    }
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawnattr_setflags(
    _attr: *mut *mut c_void,
    _flags: c_int,
) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawnattr_getflags(
    _attr: *const *mut c_void,
    flags: *mut c_int,
) -> c_int {
    if !flags.is_null() {
        unsafe {
            flags.write(0);
        }
    }
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawnattr_setpgroup(
    _attr: *mut *mut c_void,
    _pgroup: c_int,
) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawnattr_setsigmask(
    _attr: *mut *mut c_void,
    _mask: *const c_void,
) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawnattr_setsigdefault(
    _attr: *mut *mut c_void,
    _mask: *const c_void,
) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawn_file_actions_init(actions: *mut *mut c_void) -> c_int {
    if actions.is_null() {
        return EINVAL;
    }
    unsafe {
        actions.write(core::ptr::null_mut());
    }
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawn_file_actions_destroy(
    actions: *mut *mut c_void,
) -> c_int {
    if actions.is_null() {
        return EINVAL;
    }
    unsafe {
        actions.write(core::ptr::null_mut());
    }
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawn_file_actions_addclose(
    _actions: *mut *mut c_void,
    _fd: c_int,
) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawn_file_actions_adddup2(
    _actions: *mut *mut c_void,
    _fd: c_int,
    _newfd: c_int,
) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_spawn_file_actions_addopen(
    _actions: *mut *mut c_void,
    _fd: c_int,
    _path: *const c_char,
    _oflag: c_int,
    _mode: c_int,
) -> c_int {
    0
}

/// C `getpid` → nlist `_getpid`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpid() -> c_int {
    let ret = unsafe { sys::syscall0(SYS_GETPID) };
    if ret < 0 {
        1
    } else {
        c_int::try_from(ret).unwrap_or(1)
    }
}

/// C `getppid` → nlist `_getppid`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getppid() -> c_int {
    let ret = unsafe { sys::syscall0(SYS_GETPPID) };
    if ret < 0 {
        1
    } else {
        c_int::try_from(ret).unwrap_or(1)
    }
}

/// C `getrlimit` → nlist `_getrlimit` (soft zeros).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getrlimit(_resource: c_int, rlp: *mut c_void) -> c_int {
    if rlp.is_null() {
        errno::set_errno(14);
        return -1;
    }
    // Darwin rlimit is two u64s.
    unsafe {
        let p = rlp.cast::<u64>();
        p.write(u64::MAX);
        p.add(1).write(u64::MAX);
    }
    0
}

/// C `setrlimit` → nlist `_setrlimit`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setrlimit(_resource: c_int, _rlp: *const c_void) -> c_int {
    0
}

/// C `isatty` → nlist `_isatty` (host tty via `TIOCGETA`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn isatty(fd: c_int) -> c_int {
    let mut dummy = [0_u8; 72];
    let ret = unsafe {
        sys::syscall3(
            SYS_IOCTL,
            u64::from(fd.cast_unsigned()),
            TIOCGETA,
            ptr_u64(dummy.as_mut_ptr().cast()),
        )
    };
    i32::from(apply_ret(ret) >= 0)
}

/// Impl for C `ioctl` (varargs wrapper in `ioctl_varargs.c`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn kh_ioctl_impl(fd: c_int, request: u64, arg: u64) -> c_int {
    ret_c_int(unsafe {
        sys::syscall3(SYS_IOCTL, u64::from(fd.cast_unsigned()), request, arg)
    })
}

/// C `sched_yield` → nlist `_sched_yield` (rustup download / thread backoff).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sched_yield() -> c_int {
    let _ = unsafe { sys::helper0(crate::kh_core::helpers::KH_HELPER_YIELD) };
    0
}

/// C `usleep` → nlist `_usleep` (yield-based soft sleep for curl G3 cleanup).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn usleep(usec: u32) -> c_int {
    // Soft: yield a few times proportional to usec (not wall-accurate).
    let spins = usec.saturating_div(1000).clamp(1, 50);
    for _ in 0..spins {
        let _ = unsafe { sys::helper0(crate::kh_core::helpers::KH_HELPER_YIELD) };
    }
    0
}

/// C `nanosleep` → nlist `_nanosleep` (soft; advances *rem = 0).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn nanosleep(req: *const c_void, rem: *mut c_void) -> c_int {
    if req.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    // timespec: sec i64 + nsec i64
    let p = req.cast::<i64>();
    let sec = unsafe { p.read() };
    let nsec = unsafe { p.add(1).read() };
    let usec = sec
        .saturating_mul(1_000_000)
        .saturating_add(nsec.saturating_div(1000))
        .clamp(0, 50_000);
    let _ = unsafe { usleep(u32::try_from(usec).unwrap_or(1)) };
    if !rem.is_null() {
        unsafe {
            rem.cast::<i64>().write(0);
            rem.cast::<i64>().add(1).write(0);
        }
    }
    0
}

/// C `getdtablesize` → nlist `_getdtablesize` (same ceiling as `_SC_OPEN_MAX`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getdtablesize() -> c_int {
    1024
}

/// C `sysconf` → nlist `_sysconf`.
///
/// Darwin name numbers (from `<unistd.h>` / XNU): `_SC_ARG_MAX=1`,
/// `_SC_OPEN_MAX=5`, `_SC_PAGE_SIZE=29`, `_SC_NPROCESSORS_ONLN=58`, …
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sysconf(name: c_int) -> i64 {
    match name {
        1 => 256 * 1024, // _SC_ARG_MAX
        2 => 256,        // _SC_CHILD_MAX
        3 => 100,        // _SC_CLK_TCK
        5 => 1024,       // _SC_OPEN_MAX (must exceed guest FD numbers)
        6 | 7 => 1,      // _SC_JOB_CONTROL / _SC_SAVED_IDS
        8 => 200_809,    // _SC_VERSION
        29 => 16_384,    // _SC_PAGE_SIZE (Darwin arm64 default guest page)
        // Darwin: `_SC_NPROCESSORS_CONF=57`, `_SC_NPROCESSORS_ONLN=58`.
        // (84 is a non-Darwin alias some guests probe.)
        57 | 58 | 84 => {
            let n = unsafe { sys::helper0(KH_HELPER_NCPU) };
            if n > 0 {
                i64::try_from(n).unwrap_or(1)
            } else {
                1
            }
        }
        _ => {
            errno::set_errno(EINVAL);
            -1
        }
    }
}

/// Darwin `_CS_DARWIN_USER_TEMP_DIR` (`unistd.h` = 65537).
const CS_DARWIN_USER_TEMP_DIR: c_int = 65_537;
/// Darwin `_CS_DARWIN_USER_CACHE_DIR` = 65538 (soft: same tree sibling).
const CS_DARWIN_USER_CACHE_DIR: c_int = 65_538;
/// Darwin `_CS_DARWIN_USER_DIR` = 65536.
const CS_DARWIN_USER_DIR: c_int = 65_536;

/// C `confstr` → nlist `_confstr`.
///
/// Host clang/ld probe `_CS_DARWIN_USER_TEMP_DIR` for temp file bases. Without
/// this, guests only see soft `TMPDIR=/tmp` (short paths).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn confstr(name: c_int, buf: *mut c_char, len: usize) -> usize {
    let val: &[u8] = match name {
        CS_DARWIN_USER_TEMP_DIR => DARWIN_USER_TEMP_DIR,
        // Soft: cache dir next to temp (Darwin uses …/C/ vs …/T/).
        CS_DARWIN_USER_CACHE_DIR => {
            b"/var/folders/xx/kakehashi_default_user_temp000/C/\0"
        }
        CS_DARWIN_USER_DIR => b"/var/folders/xx/kakehashi_default_user_temp000/\0",
        _ => {
            errno::set_errno(EINVAL);
            return 0;
        }
    };
    // Return value includes the trailing NUL (POSIX).
    let need = val.len(); // already includes NUL in our literals
    if buf.is_null() || len == 0 {
        return need;
    }
    let copy = need.min(len);
    unsafe {
        core::ptr::copy_nonoverlapping(val.as_ptr(), buf.cast::<u8>(), copy);
        // Guarantee NUL if truncated.
        if copy > 0 {
            buf.add(copy.saturating_sub(1)).write(0);
        }
    }
    need
}

/// C `sysctl` → nlist `_sysctl`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sysctl(
    name: *mut c_int,
    namelen: c_int,
    oldp: *mut c_void,
    oldlenp: *mut usize,
    newp: *mut c_void,
    newlen: usize,
) -> c_int {
    let ret = unsafe {
        sys::syscall6(
            SYS_SYSCTL,
            ptr_u64(name.cast()),
            u64::from(namelen.cast_unsigned()),
            ptr_u64(oldp),
            ptr_u64(oldlenp.cast()),
            ptr_u64(newp),
            u64::try_from(newlen).unwrap_or(0),
        )
    };
    ret_c_int(ret)
}

/// C `sysctlbyname` → nlist `_sysctlbyname`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sysctlbyname(
    name: *const c_char,
    oldp: *mut c_void,
    oldlenp: *mut usize,
    newp: *mut c_void,
    newlen: usize,
) -> c_int {
    let ret = unsafe {
        sys::syscall6(
            SYS_SYSCTLBYNAME,
            ptr_u64(name.cast()),
            ptr_u64(oldp),
            ptr_u64(oldlenp.cast()),
            ptr_u64(newp),
            u64::try_from(newlen).unwrap_or(0),
            0,
        )
    };
    ret_c_int(ret)
}

/// Darwin `struct utsname` field width on arm64.
const UTSNAME_FIELD: usize = 256;

unsafe fn write_utsname_field(dst: *mut u8, s: &[u8]) {
    unsafe {
        let mut i = 0_usize;
        while i < 255 {
            let b = s.get(i).copied().unwrap_or(0);
            dst.add(i).write(b);
            if b == 0 {
                return;
            }
            i = i.saturating_add(1);
        }
        dst.add(255).write(0);
    }
}

/// C `uname` → nlist `_uname` (fill Darwin-ish strings).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn uname(name: *mut c_void) -> c_int {
    if name.is_null() {
        errno::set_errno(14);
        return -1;
    }
    // Darwin `struct utsname` is 5 × 256-byte fields on arm64.
    unsafe {
        let base = name.cast::<u8>();
        write_utsname_field(base, b"Darwin");
        write_utsname_field(base.add(UTSNAME_FIELD), b"kakehashi");
        write_utsname_field(base.add(UTSNAME_FIELD.saturating_mul(2)), b"24.0.0");
        write_utsname_field(
            base.add(UTSNAME_FIELD.saturating_mul(3)),
            b"Darwin Kernel Version 24.0.0",
        );
        write_utsname_field(base.add(UTSNAME_FIELD.saturating_mul(4)), b"arm64");
    }
    0
}

/// C `signal` → nlist `_signal` (no-op; returns SIG_DFL).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn signal(_sig: c_int, _handler: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

/// C `bsd_signal` → nlist `_bsd_signal` (POSIX.1-2001; same no-op as `signal`).
///
/// GNU make and other BSD-leaning tools bind this instead of `_signal`. Real
/// libc sets SA_RESTART via `sigaction`; we only need the symbol so the guest
/// does not hit the missing-symbol trampoline (exit 127).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn bsd_signal(sig: c_int, handler: *mut c_void) -> *mut c_void {
    unsafe { signal(sig, handler) }
}

/// Darwin `_NSGetExecutablePath` → Mach-O nlist `__NSGetExecutablePath`.
///
/// On Darwin the C name is `_NSGetExecutablePath`; the object export is
/// `__NSGetExecutablePath` after the leading-underscore convention. We set
/// `export_name = "_NSGetExecutablePath"` so the linker emits the double-
/// underscore form guests import.
///
/// Host helper supplies the real guest path for this `kh run` image (clang
/// re-spawns itself as `-cc1` via this API). Fallback: soft CLT `git` path
/// (historical; enough for `git --version` when the helper is unset).
///
/// Returns 0 on success, −1 if `*bufsize` was too small (then updates size).
#[unsafe(export_name = "_NSGetExecutablePath")]
pub(crate) unsafe extern "C" fn ns_get_executable_path(
    buf: *mut c_char,
    bufsize: *mut u32,
) -> c_int {
    const FALLBACK: &[u8] = b"/Library/Developer/CommandLineTools/usr/bin/git\0";
    if bufsize.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let mut path_buf = [0_u8; 1024];
    let helper_len = unsafe {
        sys::helper2(
            KH_HELPER_EXECUTABLE_PATH,
            u64::try_from(path_buf.as_mut_ptr().addr()).unwrap_or(0),
            u64::try_from(path_buf.len()).unwrap_or(0),
        )
    };
    let path: &[u8] = if helper_len > 1 {
        let n = usize::try_from(helper_len).unwrap_or(1).min(path_buf.len());
        path_buf.get(..n).unwrap_or(FALLBACK)
    } else {
        FALLBACK
    };
    // Include trailing NUL in required size (Darwin semantics).
    let need = u32::try_from(path.len()).unwrap_or(u32::MAX);
    let have = unsafe { *bufsize };
    if have < need || buf.is_null() {
        unsafe {
            *bufsize = need;
        }
        return -1;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(path.as_ptr(), buf.cast::<u8>(), path.len());
        *bufsize = need;
    }
    0
}

/// C `getpagesize` → nlist `_getpagesize` (guest page size; 16 KiB default policy).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpagesize() -> c_int {
    16_384
}

/// C `access` → nlist `_access` (BSD #33).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn access(path: *const c_char, amode: c_int) -> c_int {
    if path.is_null() {
        errno::set_errno(14);
        return -1;
    }
    let ret = unsafe {
        sys::syscall2(
            SYS_ACCESS,
            ptr_u64(path.cast()),
            u64::from(amode.cast_unsigned()),
        )
    };
    ret_c_int(ret)
}

/// C `strlcpy` → nlist `_strlcpy` (BSD string copy; returns strlen(src)).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strlcpy(
    dst: *mut c_char,
    src: *const c_char,
    size: usize,
) -> usize {
    if src.is_null() {
        return 0;
    }
    let src_len = unsafe { crate::dylib::libsystem_c::stdio::strlen(src) };
    if dst.is_null() || size == 0 {
        return src_len;
    }
    let copy = src_len.min(size.saturating_sub(1));
    unsafe {
        if copy > 0 {
            core::ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), copy);
        }
        *dst.add(copy) = 0;
    }
    src_len
}

/// C `sigprocmask` → nlist `_sigprocmask` (BSD #48; soft mask in runtime).
///
/// Hit by Apple `git` early in `main` (`git --version`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sigprocmask(
    how: c_int,
    set: *const c_void,
    oset: *mut c_void,
) -> c_int {
    let ret = unsafe {
        sys::syscall3(
            SYS_SIGPROCMASK,
            u64::from(how.cast_unsigned()),
            ptr_u64(set),
            ptr_u64(oset.cast_const().cast()),
        )
    };
    ret_c_int(ret)
}

/// C `pthread_sigmask` → nlist `_pthread_sigmask` (same soft mask as sigprocmask).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pthread_sigmask(
    how: c_int,
    set: *const c_void,
    oset: *mut c_void,
) -> c_int {
    // Darwin returns 0 / errno as int (not pthread-error style for this wrapper
    // when implemented via sigprocmask in libSystem).
    unsafe { sigprocmask(how, set, oset) }
}

/// C `sigaction` → nlist `_sigaction` (BSD #46; soft state in runtime).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sigaction(
    sig: c_int,
    act: *const c_void,
    oact: *mut c_void,
) -> c_int {
    let ret = unsafe {
        sys::syscall3(
            SYS_SIGACTION,
            u64::from(sig.cast_unsigned()),
            ptr_u64(act),
            ptr_u64(oact.cast_const().cast()),
        )
    };
    ret_c_int(ret)
}

/// C `sigemptyset` → nlist `_sigemptyset`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sigemptyset(set: *mut c_void) -> c_int {
    if set.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    unsafe {
        set.cast::<u32>().write(0);
    }
    0
}

/// C `sigfillset` → nlist `_sigfillset`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sigfillset(set: *mut c_void) -> c_int {
    if set.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    unsafe {
        set.cast::<u32>().write(u32::MAX);
    }
    0
}

/// C `sigaddset` → nlist `_sigaddset`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sigaddset(set: *mut c_void, signo: c_int) -> c_int {
    if set.is_null() || signo <= 0 || signo > 32 {
        errno::set_errno(EINVAL);
        return -1;
    }
    let bit = 1_u32.wrapping_shl(signo.cast_unsigned().saturating_sub(1));
    unsafe {
        let p = set.cast::<u32>();
        p.write(p.read() | bit);
    }
    0
}

/// C `sigdelset` → nlist `_sigdelset`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sigdelset(set: *mut c_void, signo: c_int) -> c_int {
    if set.is_null() || signo <= 0 || signo > 32 {
        errno::set_errno(EINVAL);
        return -1;
    }
    let bit = 1_u32.wrapping_shl(signo.cast_unsigned().saturating_sub(1));
    unsafe {
        let p = set.cast::<u32>();
        p.write(p.read() & !bit);
    }
    0
}

/// C `sigismember` → nlist `_sigismember`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sigismember(set: *const c_void, signo: c_int) -> c_int {
    if set.is_null() || signo <= 0 || signo > 32 {
        errno::set_errno(EINVAL);
        return -1;
    }
    let bit = 1_u32.wrapping_shl(signo.cast_unsigned().saturating_sub(1));
    let cur = unsafe { set.cast::<u32>().read() };
    i32::from((cur & bit) != 0)
}

/// Darwin `___darwin_check_fd_set_overflow` → safe for small FD_SET uses.
#[unsafe(export_name = "__darwin_check_fd_set_overflow")]
pub(crate) unsafe extern "C" fn __darwin_check_fd_set_overflow(
    _fd: c_int,
    _fdset: *const c_void,
    _how: c_int,
) -> c_int {
    // 0 = OK (no overflow). curl select/poll path only.
    0
}

/// C `setlocale` → nlist `_setlocale`.
///
/// Always reports a UTF-8 locale (macOS interactive default). Returning `"C"`
/// made Apple `zsh` treat input as US-ASCII (`?<xx>` on Cyrillic, broken spaces).
///
/// tcsh/`csh` call this before walking `_environ`; seed so `environ` is not
/// NULL (`blk2short(environ)` SEGV).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setlocale(_category: c_int, _locale: *const c_char) -> *mut c_char {
    static mut UTF8_LOCALE: [u8; 12] = *b"en_US.UTF-8\0";
    soft_env_seed_defaults();
    core::ptr::addr_of_mut!(UTF8_LOCALE).cast()
}

// ── Soft process environment (`getenv` / `setenv` / `unsetenv` / `environ`) ─
//
// The loader still places `envp` on the stack for `main`, but Apple `git`'s
// `start_command` walks the **global** `environ` (`char **`). That must be a
// real data symbol: if dyld binds `_environ` to a missing-function trampoline,
// git loads trampoline bytes as a pointer and SIGSEGVs (post-commit path).

const SOFT_ENV_SLOTS: usize = 48;
const SOFT_ENV_WIDTH: usize = 384;

/// `KEY=VALUE\0` slots (freestanding; single guest process).
static mut SOFT_ENV: [[u8; SOFT_ENV_WIDTH]; SOFT_ENV_SLOTS] = [[0; SOFT_ENV_WIDTH]; SOFT_ENV_SLOTS];
static mut SOFT_ENV_LIVE: [bool; SOFT_ENV_SLOTS] = [false; SOFT_ENV_SLOTS];
static mut SOFT_ENV_SEEDED: bool = false;

/// NULL-terminated pointer vector backing C `environ`.
static mut ENVIRON_PTRS: [*mut c_char; SOFT_ENV_SLOTS + 1] =
    [core::ptr::null_mut(); SOFT_ENV_SLOTS + 1];

/// C `environ` → nlist `_environ` (`char **` — the *variable*, not the vector).
///
/// Starts null; `setlocale` / `getenv` / `setenv` seed defaults and point
/// this at [`ENVIRON_PTRS`]. `csh` reads `_environ` right after `setlocale`.
#[unsafe(no_mangle)]
pub(crate) static mut environ: *mut *mut c_char = core::ptr::null_mut();

/// Rebuild [`ENVIRON_PTRS`] / [`environ`] from live soft-env slots.
fn soft_env_rebuild_environ() {
    // SAFETY: single guest process; only touched from C ABI env helpers.
    unsafe {
        let live = &*core::ptr::addr_of!(SOFT_ENV_LIVE);
        let table = &mut *core::ptr::addr_of_mut!(SOFT_ENV);
        let ptrs = &mut *core::ptr::addr_of_mut!(ENVIRON_PTRS);
        let mut n = 0_usize;
        for i in 0..SOFT_ENV_SLOTS {
            if !live.get(i).copied().unwrap_or(false) {
                continue;
            }
            let Some(entry) = table.get_mut(i) else {
                continue;
            };
            let Some(slot) = ptrs.get_mut(n) else {
                break;
            };
            *slot = entry.as_mut_ptr().cast();
            n = n.saturating_add(1);
        }
        if let Some(slot) = ptrs.get_mut(n) {
            *slot = core::ptr::null_mut();
        }
        // Drop any stale trailing pointers past n+1.
        for slot in ptrs.iter_mut().skip(n.saturating_add(1)) {
            *slot = core::ptr::null_mut();
        }
        environ = ptrs.as_mut_ptr();
    }
}

/// Darwin user temp directory (`confstr(_CS_DARWIN_USER_TEMP_DIR)`).
///
/// Real macOS returns a path under `/var/folders/…/T/` (~49 chars). Host
/// `clang -flto` then passes `-object_path_lto $TMPDIR/cc-XXXX.o` (~60 chars).
/// Seeding `TMPDIR=/tmp` made those paths 9–20 chars; freestanding LTO
/// materialize fails for short `-object_path_lto` / `-o` combinations that
/// never appear on real Apple. Match Darwin length class (not `/tmp`).
const DARWIN_USER_TEMP_DIR: &[u8] =
    b"/var/folders/xx/kakehashi_default_user_temp000/T/\0";

/// Seed PATH/HOME/TMPDIR to match the loader stack env (execute.rs), plus
/// host `GIT_*` (clone nested re-exec: `GIT_DIR` must reach git-remote-http).
fn soft_env_seed_defaults() {
    // SAFETY: one-shot seed before guest walks environ.
    unsafe {
        if SOFT_ENV_SEEDED {
            return;
        }
        SOFT_ENV_SEEDED = true;
    }
    // git-core first: Apple `git` execvp's `git-remote-https` (and friends) via
    // PATH; without libexec they fall back to a broken `git remote-https` spawn.
    // CLT `usr/bin` next so guest `make` finds `gcc`/`clang` (real macOS has
    // `/usr/bin` shims; bottle only symlinks `git` there by default).
    let path = b"/Library/Developer/CommandLineTools/usr/libexec/git-core:\
/Library/Developer/CommandLineTools/usr/bin:\
/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\0";
    // Already NUL-terminated static (see `DARWIN_USER_TEMP_DIR`).
    let tmp: &[u8] = DARWIN_USER_TEMP_DIR;
    // HOME via host helper → `/Volumes/linux{host $HOME}` so host
    // `git config --global` / `~/.gitconfig` is visible under `kh run`.
    let mut home_buf = [0_u8; 512];
    let home_len = unsafe {
        sys::helper2(
            KH_HELPER_GUEST_HOME,
            u64::try_from(home_buf.as_mut_ptr().addr()).unwrap_or(0),
            u64::try_from(home_buf.len()).unwrap_or(0),
        )
    };
    let home: &[u8] = if home_len > 1 {
        let n = usize::try_from(home_len).unwrap_or(1).min(home_buf.len());
        home_buf.get(..n).unwrap_or(b"/var/root\0")
    } else {
        b"/var/root\0"
    };
    // Default CLT SDK for Apple clang without a working `xcrun` (headers live
    // under SDKs/MacOSX.sdk after `kh install xcode-tools`).
    let sdkroot = b"/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk\0";
    let developer_dir = b"/Library/Developer/CommandLineTools\0";
    for (name, val) in [
        (b"PATH\0".as_slice(), path.as_slice()),
        (b"HOME\0".as_slice(), home),
        (b"TMPDIR\0".as_slice(), tmp),
        (b"SDKROOT\0".as_slice(), sdkroot.as_slice()),
        (b"DEVELOPER_DIR\0".as_slice(), developer_dir.as_slice()),
        (b"LANG\0".as_slice(), b"en_US.UTF-8\0".as_slice()),
        (b"LC_CTYPE\0".as_slice(), b"en_US.UTF-8\0".as_slice()),
        (b"TERM\0".as_slice(), b"xterm-256color\0".as_slice()),
        (b"BASH_ENV\0".as_slice(), b"/dev/null\0".as_slice()),
        (b"ENV\0".as_slice(), b"/dev/null\0".as_slice()),
    ] {
        let _ = unsafe { soft_env_set(name.as_ptr().cast(), val.as_ptr().cast(), 1) };
    }
    // Nested `kh run` after `execve` inherits host env with GIT_* from the
    // parent guest's soft environ (inject_kh_env). Pull them in so `getenv`
    // / `environ` walks see `GIT_DIR` (required for clone fetch).
    soft_env_seed_git_from_host();
    // Prefer host-inherited SDKROOT/DEVELOPER_DIR when present (nested -cc1).
    soft_env_seed_sdk_from_host();
    // Modern `ld` `-lto_library` re-execs with `DYLD_LIBRARY_PATH=/tmp/ld-support-…`
    // so dyld would pick the staged `libLTO.dylib`. Without seeding, each nested
    // `kh run` starts with a soft env that lacks DYLD_* → infinite re-exec (P1).
    soft_env_seed_dyld_from_host();
    soft_env_seed_keys_from_host(&[
        b"LANG\0",
        b"LC_ALL\0",
        b"LC_CTYPE\0",
        b"LC_MESSAGES\0",
        b"TERM\0",
        b"COLORTERM\0",
        b"COLUMNS\0",
        b"LINES\0",
    ]);
    soft_env_rebuild_environ();
}

/// Pull SDKROOT / DEVELOPER_DIR from the host process (nested `kh run`).
fn soft_env_seed_sdk_from_host() {
    soft_env_seed_keys_from_host(&[b"SDKROOT\0", b"DEVELOPER_DIR\0"]);
}

/// Pull `DYLD_LIBRARY_PATH` / fallback from host (nested `ld` LTO re-exec).
fn soft_env_seed_dyld_from_host() {
    soft_env_seed_keys_from_host(&[
        b"DYLD_LIBRARY_PATH\0",
        b"DYLD_FALLBACK_LIBRARY_PATH\0",
        b"DYLD_FRAMEWORK_PATH\0",
    ]);
}

fn soft_env_seed_keys_from_host(keys: &[&[u8]]) {
    let mut val_buf = [0_u8; SOFT_ENV_WIDTH];
    for key in keys {
        let n = unsafe {
            sys::helper3(
                crate::kh_core::helpers::KH_HELPER_GETENV,
                u64::try_from(key.as_ptr().addr()).unwrap_or(0),
                u64::try_from(val_buf.as_mut_ptr().addr()).unwrap_or(0),
                u64::try_from(val_buf.len()).unwrap_or(0),
            )
        };
        if n <= 1 {
            continue;
        }
        let _ = unsafe { soft_env_set(key.as_ptr().cast(), val_buf.as_ptr().cast(), 1) };
    }
}

/// Pull common `GIT_*` keys from the host process into soft environ.
fn soft_env_seed_git_from_host() {
    // Keys git-remote-http / clone set before spawning helpers.
    const KEYS: &[&[u8]] = &[
        b"GIT_DIR\0",
        b"GIT_WORK_TREE\0",
        b"GIT_OBJECT_DIRECTORY\0",
        b"GIT_ALTERNATE_OBJECT_DIRECTORIES\0",
        b"GIT_COMMON_DIR\0",
        b"GIT_NAMESPACE\0",
        b"GIT_EXEC_PATH\0",
        b"GIT_PROTOCOL\0",
        b"GIT_CONFIG_PARAMETERS\0",
        b"GIT_CONFIG_COUNT\0",
        b"GIT_CONFIG_GLOBAL\0",
        b"GIT_CONFIG_SYSTEM\0",
        b"GIT_HTTP_USER_AGENT\0",
        b"GIT_SSL_NO_VERIFY\0",
        b"GIT_SSL_CAINFO\0",
        b"GIT_CURL_VERBOSE\0",
        b"GIT_TRACE\0",
        b"GIT_TRACE_PACKET\0",
        b"GIT_TRACE_CURL\0",
        b"GIT_TERMINAL_PROMPT\0",
        b"GIT_ASKPASS\0",
        b"GIT_QUARANTINE_PATH\0",
        b"GIT_DEFAULT_HASH\0",
        b"GIT_SHALLOW_FILE\0",
        // SSH remotes: host OpenSSH flags / alternate client (G5).
        b"GIT_SSH\0",
        b"GIT_SSH_COMMAND\0",
    ];
    let mut val_buf = [0_u8; SOFT_ENV_WIDTH];
    for key in KEYS {
        let key_ptr = key.as_ptr();
        let n = unsafe {
            sys::helper3(
                crate::kh_core::helpers::KH_HELPER_GETENV,
                u64::try_from(key_ptr.addr()).unwrap_or(0),
                u64::try_from(val_buf.as_mut_ptr().addr()).unwrap_or(0),
                u64::try_from(val_buf.len()).unwrap_or(0),
            )
        };
        if n <= 1 {
            continue;
        }
        let _ = unsafe { soft_env_set(key.as_ptr().cast(), val_buf.as_ptr().cast(), 1) };
    }
}

/// Internal setenv without re-seeding (used by seed + public setenv).
unsafe fn soft_env_set(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int {
    if name.is_null() || value.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let key_len = soft_env_c_str_len(name);
    let val_len = soft_env_c_str_len(value);
    if key_len == 0 {
        errno::set_errno(EINVAL);
        return -1;
    }
    let need = key_len
        .saturating_add(1)
        .saturating_add(val_len)
        .saturating_add(1);
    if need > SOFT_ENV_WIDTH {
        errno::set_errno(ENOMEM);
        return -1;
    }

    let live = unsafe { &mut *core::ptr::addr_of_mut!(SOFT_ENV_LIVE) };
    let table = unsafe { &mut *core::ptr::addr_of_mut!(SOFT_ENV) };

    let mut free_slot: Option<usize> = None;
    for i in 0..SOFT_ENV_SLOTS {
        let is_live = live.get(i).copied().unwrap_or(false);
        if !is_live {
            if free_slot.is_none() {
                free_slot = Some(i);
            }
            continue;
        }
        let Some(entry) = table.get_mut(i) else {
            continue;
        };
        if soft_env_key_eq(entry, name, key_len) {
            if overwrite == 0 {
                return 0;
            }
            soft_env_write_kv(entry, name, key_len, value, val_len);
            return 0;
        }
    }

    let Some(i) = free_slot else {
        errno::set_errno(ENOMEM);
        return -1;
    };
    let Some(entry) = table.get_mut(i) else {
        errno::set_errno(ENOMEM);
        return -1;
    };
    soft_env_write_kv(entry, name, key_len, value, val_len);
    if let Some(slot) = live.get_mut(i) {
        *slot = true;
    }
    0
}

/// Darwin `_NSGetEnviron` → nlist `__NSGetEnviron` (`char ***`).
///
/// Same underscore convention as [`ns_get_executable_path`].
#[unsafe(export_name = "_NSGetEnviron")]
pub(crate) unsafe extern "C" fn ns_get_environ() -> *mut *mut *mut c_char {
    soft_env_seed_defaults();
    core::ptr::addr_of_mut!(environ)
}

const NS_ARGV_MAX: usize = 16;
const NS_ARGV_BYTES: usize = 4096;

static mut NS_ARGC: i32 = 0;
static mut NS_ARG_STORE: [c_char; NS_ARGV_BYTES] = [0; NS_ARGV_BYTES];
static mut NS_ARGV: [*mut c_char; NS_ARGV_MAX] = [core::ptr::null_mut(); NS_ARGV_MAX];
static mut NS_ARGV_VEC: *mut *mut c_char = core::ptr::null_mut();

fn ns_args_ensure() {
    unsafe {
        if NS_ARGC != 0 {
            return;
        }
        let mut packed = [0_u8; NS_ARGV_BYTES];
        let n = sys::helper2(
            KH_HELPER_ARGV,
            u64::try_from(packed.as_mut_ptr().addr()).unwrap_or(0),
            u64::try_from(packed.len()).unwrap_or(0),
        );
        if n > 4 {
            let nbytes = usize::try_from(n).unwrap_or(4).min(packed.len());
            let argc = u32::from_ne_bytes([
                packed.first().copied().unwrap_or(0),
                packed.get(1).copied().unwrap_or(0),
                packed.get(2).copied().unwrap_or(0),
                packed.get(3).copied().unwrap_or(0),
            ]) as usize;
            let argc = argc.min(NS_ARGV_MAX.saturating_sub(1));
            let mut off = 4_usize;
            let mut store_off = 0_usize;
            for slot in NS_ARGV.iter_mut().take(argc) {
                let start = off;
                while off < nbytes && packed.get(off).copied().unwrap_or(1) != 0 {
                    off = off.saturating_add(1);
                }
                let slen = off.saturating_sub(start).saturating_add(1);
                if store_off.saturating_add(slen) > NS_ARG_STORE.len() {
                    break;
                }
                for k in 0..slen {
                    if let Some(b) = NS_ARG_STORE.get_mut(store_off.saturating_add(k)) {
                        *b = packed
                            .get(start.saturating_add(k))
                            .copied()
                            .unwrap_or(0)
                            .cast_signed();
                    }
                }
                *slot = NS_ARG_STORE.as_mut_ptr().wrapping_add(store_off);
                store_off = store_off.saturating_add(slen);
                off = off.saturating_add(1);
            }
            if let Some(last) = NS_ARGV.get_mut(argc) {
                *last = core::ptr::null_mut();
            }
            NS_ARGV_VEC = NS_ARGV.as_mut_ptr();
            NS_ARGC = i32::try_from(argc).unwrap_or(0);
            if NS_ARGC != 0 {
                return;
            }
        }
        NS_ARG_STORE[0] = 0;
        NS_ARGV[0] = NS_ARG_STORE.as_mut_ptr();
        NS_ARGV[1] = core::ptr::null_mut();
        NS_ARGV_VEC = NS_ARGV.as_mut_ptr();
        NS_ARGC = 1;
    }
}

/// Darwin `_NSGetArgc` → nlist `__NSGetArgc`.
#[unsafe(export_name = "_NSGetArgc")]
pub(crate) unsafe extern "C" fn ns_get_argc() -> *mut i32 {
    ns_args_ensure();
    core::ptr::addr_of_mut!(NS_ARGC)
}

/// Darwin `_NSGetArgv` → nlist `__NSGetArgv`.
#[unsafe(export_name = "_NSGetArgv")]
pub(crate) unsafe extern "C" fn ns_get_argv() -> *mut *mut *mut c_char {
    ns_args_ensure();
    core::ptr::addr_of_mut!(NS_ARGV_VEC)
}

fn soft_env_c_str_len(p: *const c_char) -> usize {
    if p.is_null() {
        return 0;
    }
    let mut n = 0_usize;
    while n < SOFT_ENV_WIDTH {
        // SAFETY: NUL-terminated C string from guest, bounded scan.
        let b = unsafe { *p.add(n) };
        if b == 0 {
            break;
        }
        n = n.saturating_add(1);
    }
    n
}

fn soft_env_key_eq(entry: &[u8], key: *const c_char, key_len: usize) -> bool {
    if key.is_null() || key_len == 0 {
        return false;
    }
    if entry.len() <= key_len {
        return false;
    }
    // entry must be KEY=…
    if entry.get(key_len).copied() != Some(b'=') {
        return false;
    }
    for i in 0..key_len {
        let eb = entry.get(i).copied().unwrap_or(0);
        // SAFETY: key has at least key_len bytes before NUL (caller).
        let kb = unsafe { (*key.add(i)).cast_unsigned() };
        if eb != kb {
            return false;
        }
    }
    true
}

fn soft_env_write_kv(
    entry: &mut [u8; SOFT_ENV_WIDTH],
    name: *const c_char,
    key_len: usize,
    value: *const c_char,
    val_len: usize,
) {
    entry.fill(0);
    unsafe {
        core::ptr::copy_nonoverlapping(name.cast::<u8>(), entry.as_mut_ptr(), key_len);
        if let Some(eq) = entry.get_mut(key_len) {
            *eq = b'=';
        }
        core::ptr::copy_nonoverlapping(
            value.cast::<u8>(),
            entry.as_mut_ptr().add(key_len.saturating_add(1)),
            val_len,
        );
    }
}

/// Apple `_simple_getenv` → nlist `__simple_getenv` (CLT `ranlib` / tools).
///
/// Same contract as `getenv` for the soft environ table (trace-first).
#[unsafe(export_name = "_simple_getenv")]
pub(crate) unsafe extern "C" fn simple_getenv(name: *const c_char) -> *mut c_char {
    unsafe { getenv(name) }
}

/// C `getenv` → nlist `_getenv` (soft table; null if unset).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    soft_env_seed_defaults();
    if name.is_null() {
        return core::ptr::null_mut();
    }
    let key_len = soft_env_c_str_len(name);
    if key_len == 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: process-wide soft env; single guest process.
    let live = unsafe { &*core::ptr::addr_of!(SOFT_ENV_LIVE) };
    let table = unsafe { &*core::ptr::addr_of!(SOFT_ENV) };
    for i in 0..SOFT_ENV_SLOTS {
        if !live.get(i).copied().unwrap_or(false) {
            continue;
        }
        let Some(entry) = table.get(i) else {
            continue;
        };
        if soft_env_key_eq(entry, name, key_len) {
            let val_off = key_len.saturating_add(1);
            return unsafe { entry.as_ptr().add(val_off).cast_mut().cast() };
        }
    }
    core::ptr::null_mut()
}

/// C `putenv` → nlist `_putenv` (`"KEY=value"` string, stored as-is).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn putenv(string: *mut c_char) -> c_int {
    if string.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let len = soft_env_c_str_len(string);
    let mut eq = None;
    for i in 0..len {
        // SAFETY: bounded scan of guest C string.
        if unsafe { *string.add(i) } == b'='.cast_signed() {
            eq = Some(i);
            break;
        }
    }
    let Some(eq) = eq else {
        errno::set_errno(EINVAL);
        return -1;
    };
    let name_len = eq;
    if name_len == 0 {
        errno::set_errno(EINVAL);
        return -1;
    }
    // Temporarily NUL-terminate the key for setenv, then restore '='.
    unsafe {
        string.add(eq).write(0);
        let rc = setenv(string.cast_const(), string.add(eq.saturating_add(1)).cast_const(), 1);
        string.add(eq).write(b'='.cast_signed());
        rc
    }
}

/// C `setenv` → nlist `_setenv`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    soft_env_seed_defaults();
    let rc = unsafe { soft_env_set(name, value, overwrite) };
    if rc == 0 {
        soft_env_rebuild_environ();
    }
    rc
}

/// C `unsetenv` → nlist `_unsetenv`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn unsetenv(name: *const c_char) -> c_int {
    soft_env_seed_defaults();
    if name.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    let key_len = soft_env_c_str_len(name);
    if key_len == 0 {
        errno::set_errno(EINVAL);
        return -1;
    }
    let live = unsafe { &mut *core::ptr::addr_of_mut!(SOFT_ENV_LIVE) };
    let table = unsafe { &mut *core::ptr::addr_of_mut!(SOFT_ENV) };
    for i in 0..SOFT_ENV_SLOTS {
        if !live.get(i).copied().unwrap_or(false) {
            continue;
        }
        let Some(entry) = table.get_mut(i) else {
            continue;
        };
        if soft_env_key_eq(entry, name, key_len) {
            entry.fill(0);
            if let Some(slot) = live.get_mut(i) {
                *slot = false;
            }
            soft_env_rebuild_environ();
            return 0;
        }
    }
    0
}

/// C `uselocale` → nlist `_uselocale` (no thread locales; return null).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn uselocale(_new: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

/// C `getuid` → nlist `_getuid` (host uid via BSD syscall).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getuid() -> u32 {
    let ret = unsafe { sys::syscall0(SYS_GETUID) };
    if ret < 0 {
        0
    } else {
        u32::try_from(ret).unwrap_or(0)
    }
}

/// C `geteuid` → nlist `_geteuid`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn geteuid() -> u32 {
    let ret = unsafe { sys::syscall0(SYS_GETEUID) };
    if ret < 0 {
        0
    } else {
        u32::try_from(ret).unwrap_or(0)
    }
}

/// C `getgid` → nlist `_getgid`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getgid() -> u32 {
    let ret = unsafe { sys::syscall0(SYS_GETGID) };
    if ret < 0 {
        0
    } else {
        u32::try_from(ret).unwrap_or(0)
    }
}

/// C `getegid` → nlist `_getegid`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getegid() -> u32 {
    let ret = unsafe { sys::syscall0(SYS_GETEGID) };
    if ret < 0 {
        0
    } else {
        u32::try_from(ret).unwrap_or(0)
    }
}

/// C `getgroups` → nlist `_getgroups` (primary gid only).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getgroups(gidsetsize: c_int, grouplist: *mut u32) -> c_int {
    if gidsetsize < 0 {
        errno::set_errno(EINVAL);
        return -1;
    }
    if gidsetsize == 0 {
        return 1;
    }
    if grouplist.is_null() {
        errno::set_errno(14);
        return -1;
    }
    unsafe {
        grouplist.write(getgid());
    }
    1
}

/// C `setvbuf` → nlist `_setvbuf` (no buffering).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setvbuf(
    _stream: *mut c_void,
    _buf: *mut c_char,
    _mode: c_int,
    _size: usize,
) -> c_int {
    0
}

/// C `clock_gettime` → nlist `_clock_gettime` (via gettimeofday).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn clock_gettime(clock_id: c_int, tp: *mut c_void) -> c_int {
    let _ = clock_id;
    if tp.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    // timespec: i64 sec + i64 nsec on Darwin arm64
    let mut tv = [0_u8; 16];
    let ret = unsafe { sys::syscall2(SYS_GETTIMEOFDAY, ptr_u64(tv.as_mut_ptr().cast()), 0) };
    if ret < 0 {
        return ret_c_int(ret);
    }
    let sec = i64::from_le_bytes([tv[0], tv[1], tv[2], tv[3], tv[4], tv[5], tv[6], tv[7]]);
    let usec = i32::from_le_bytes([tv[8], tv[9], tv[10], tv[11]]);
    let nsec = i64::from(usec).saturating_mul(1000);
    unsafe {
        let out = tp.cast::<u8>();
        out.copy_from_nonoverlapping(sec.to_le_bytes().as_ptr(), 8);
        out.add(8)
            .copy_from_nonoverlapping(nsec.to_le_bytes().as_ptr(), 8);
    }
    0
}

/// Darwin `clock_gettime_nsec_np` → nlist `_clock_gettime_nsec_np` (ns since epoch-ish).
///
/// rustup uses this after a writable `poll` on the download socket.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn clock_gettime_nsec_np(_clock_id: c_int) -> u64 {
    let mut tv = [0_u8; 16];
    let ret = unsafe { sys::syscall2(SYS_GETTIMEOFDAY, ptr_u64(tv.as_mut_ptr().cast()), 0) };
    if ret < 0 {
        return 0;
    }
    let sec = u64::from_le_bytes([tv[0], tv[1], tv[2], tv[3], tv[4], tv[5], tv[6], tv[7]]);
    let usec = u64::from(u32::from_le_bytes([tv[8], tv[9], tv[10], tv[11]]));
    sec.saturating_mul(1_000_000_000)
        .saturating_add(usec.saturating_mul(1_000))
}

/// Darwin `mach_absolute_time` → nlist `_mach_absolute_time`.
///
/// Returns nanoseconds-as-ticks. Pair with [`mach_timebase_info`] (1/1) so
/// `ticks * numer / denom` is wall-ish ns. Observed: Apple `ld-classic` (G4).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mach_absolute_time() -> u64 {
    let mut tv = [0_u8; 16];
    let ret = unsafe { sys::syscall2(SYS_GETTIMEOFDAY, ptr_u64(tv.as_mut_ptr().cast()), 0) };
    if ret < 0 {
        return 0;
    }
    let sec = u64::from_le_bytes([tv[0], tv[1], tv[2], tv[3], tv[4], tv[5], tv[6], tv[7]]);
    let usec = u64::from(u32::from_le_bytes([tv[8], tv[9], tv[10], tv[11]]));
    sec.saturating_mul(1_000_000_000)
        .saturating_add(usec.saturating_mul(1_000))
}

/// Darwin `mach_timebase_info` → nlist `_mach_timebase_info`.
///
/// Soft 1/1 with [`mach_absolute_time`] ns ticks. `info` is
/// `{ uint32_t numer; uint32_t denom; }`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mach_timebase_info(info: *mut u32) -> c_int {
    if info.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    // SAFETY: caller buffer for two u32s.
    unsafe {
        info.write(1);
        info.add(1).write(1);
    }
    0
}

/// Darwin `mach_continuous_time` → nlist `_mach_continuous_time` (same as absolute).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mach_continuous_time() -> u64 {
    unsafe { mach_absolute_time() }
}

/// C `qsort` → nlist `_qsort` (**heapsort**, O(n log n) worst case).
///
/// Former insertion sort was O(n²): Apple `git index-pack` `qsort`s the full
/// object table after “Resolving deltas: 100%”. On wine (~1.37M objects) that
/// became multi‑hour pure-CPU hang (no I/O, no `.idx`). Folly-scale (~1e5)
/// was merely slow enough to still finish under clone time budgets.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn qsort(
    base: *mut c_void,
    nel: usize,
    width: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) {
    if base.is_null() || nel < 2 || width == 0 {
        return;
    }
    let Some(cmp) = compar else {
        return;
    };
    let cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int = {
        let raw = sys::strip_ptrauth_ia(cmp as usize);
        // SAFETY: stripped IA pointer is the guest comparator (or unchanged).
        unsafe { core::mem::transmute(raw) }
    };
    // SAFETY: guest buffer of nel*width; heapsort in place.
    unsafe {
        qsort_heapsort(base.cast::<u8>(), nel, width, cmp);
    }
}

/// Swap `width` bytes at `a` and `b` (may overlap only if a == b — no-op).
unsafe fn qsort_swap(a: *mut u8, b: *mut u8, width: usize) {
    if a == b {
        return;
    }
    let mut off = 0_usize;
    while off < width {
        // SAFETY: caller guarantees a, b point to width bytes in the array.
        let tmp = unsafe { a.add(off).read() };
        unsafe {
            a.add(off).write(b.add(off).read());
            b.add(off).write(tmp);
        }
        off = off.saturating_add(1);
    }
}

/// Element pointer for index `i` in array `base` of `width`-byte records.
#[inline]
unsafe fn qsort_at(base: *mut u8, width: usize, i: usize) -> *mut u8 {
    // SAFETY: i < nel checked by caller.
    unsafe { base.add(i.saturating_mul(width)) }
}

/// Sift down at `start` within heap of length `end` (exclusive).
unsafe fn qsort_sift_down(
    base: *mut u8,
    width: usize,
    start: usize,
    end: usize,
    cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
) {
    let mut root = start;
    loop {
        let left = root.saturating_mul(2).saturating_add(1);
        if left >= end {
            break;
        }
        let mut swap = root;
        // SAFETY: indices < end ≤ nel.
        let root_p = unsafe { qsort_at(base, width, root) };
        let left_p = unsafe { qsort_at(base, width, left) };
        if unsafe { cmp(left_p.cast(), root_p.cast()) } > 0 {
            swap = left;
        }
        let right = left.saturating_add(1);
        if right < end {
            let swap_p = unsafe { qsort_at(base, width, swap) };
            let right_p = unsafe { qsort_at(base, width, right) };
            if unsafe { cmp(right_p.cast(), swap_p.cast()) } > 0 {
                swap = right;
            }
        }
        if swap == root {
            break;
        }
        let a = unsafe { qsort_at(base, width, root) };
        let b = unsafe { qsort_at(base, width, swap) };
        unsafe {
            qsort_swap(a, b, width);
        }
        root = swap;
    }
}

/// In-place heapsort — no recursion, O(1) extra stack, O(n log n) time.
unsafe fn qsort_heapsort(
    base: *mut u8,
    nel: usize,
    width: usize,
    cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int,
) {
    // Build max-heap: sift from last parent (nel/2 - 1) down to 0.
    #[allow(clippy::integer_division)]
    let mut i = nel / 2;
    while i > 0 {
        i = i.saturating_sub(1);
        unsafe {
            qsort_sift_down(base, width, i, nel, cmp);
        }
    }
    // Repeatedly move max to end and restore heap.
    let mut end = nel;
    while end > 1 {
        end = end.saturating_sub(1);
        let a = unsafe { qsort_at(base, width, 0) };
        let b = unsafe { qsort_at(base, width, end) };
        unsafe {
            qsort_swap(a, b, width);
            qsort_sift_down(base, width, 0, end, cmp);
        }
    }
}

/// C `bsearch` → nlist `_bsearch` (curl G1 after fopen).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    nel: usize,
    width: usize,
    compar: Option<unsafe extern "C" fn(*const c_void, *const c_void) -> c_int>,
) -> *mut c_void {
    if key.is_null() || base.is_null() || nel == 0 || width == 0 {
        return core::ptr::null_mut();
    }
    let Some(cmp) = compar else {
        return core::ptr::null_mut();
    };
    let mut lo = 0_usize;
    let mut hi = nel;
    while lo < hi {
        let mid = lo.saturating_add(hi.saturating_sub(lo).wrapping_shr(1));
        // SAFETY: base is nel*width; mid < nel.
        let elem = unsafe {
            base.cast::<u8>()
                .add(mid.saturating_mul(width))
                .cast::<c_void>()
        };
        // SAFETY: guest compar for key vs elem.
        let ord = unsafe { cmp(key, elem) };
        if ord == 0 {
            return elem.cast_mut();
        }
        if ord < 0 {
            hi = mid;
        } else {
            lo = mid.saturating_add(1);
        }
    }
    core::ptr::null_mut()
}

/// C `getrusage` → nlist `_getrusage` (soft-zero Darwin `struct rusage`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getrusage(_who: c_int, usage: *mut c_void) -> c_int {
    if !usage.is_null() {
        unsafe {
            core::ptr::write_bytes(usage.cast::<u8>(), 0, 144);
        }
    }
    0
}

/// C `getlogin` → nlist `_getlogin`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getlogin() -> *mut c_char {
    static mut NAME: [u8; 10] = *b"kakehashi\0";
    core::ptr::addr_of_mut!(NAME).cast()
}

/// Darwin `struct passwd` (arm64; public `pwd.h`, no `pw_fields` on current SDK).
#[repr(C)]
#[allow(clippy::struct_field_names)]
struct Passwd {
    pw_name: *mut c_char,
    pw_passwd: *mut c_char,
    pw_uid: u32,
    pw_gid: u32,
    pw_change: i64,
    pw_class: *mut c_char,
    pw_gecos: *mut c_char,
    pw_dir: *mut c_char,
    pw_shell: *mut c_char,
    pw_expire: i64,
}

static mut PW_STORE: Passwd = Passwd {
    pw_name: core::ptr::null_mut(),
    pw_passwd: core::ptr::null_mut(),
    pw_uid: 0,
    pw_gid: 0,
    pw_change: 0,
    pw_class: core::ptr::null_mut(),
    pw_gecos: core::ptr::null_mut(),
    pw_dir: core::ptr::null_mut(),
    pw_shell: core::ptr::null_mut(),
    pw_expire: 0,
};
static mut PW_NAME: [u8; 64] = [0; 64];
static mut PW_DIR: [u8; 256] = [0; 256];
static mut PW_SHELL: [u8; 16] = *b"/bin/zsh\0\0\0\0\0\0\0\0";
static mut PW_EMPTY: [u8; 1] = [0];
static mut PW_PASS: [u8; 2] = *b"*\0";
static mut PW_WALKED: bool = false;

fn copy_cstr_to(dst: &mut [u8], src: *const c_char, fallback: &[u8]) {
    dst.fill(0);
    if src.is_null() {
        let n = fallback.len().min(dst.len().saturating_sub(1));
        if n > 0 {
            dst[..n].copy_from_slice(&fallback[..n]);
        }
        return;
    }
    let n = unsafe { super::stdio::strlen(src) };
    let n = n.min(dst.len().saturating_sub(1));
    if n > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(src.cast::<u8>(), dst.as_mut_ptr(), n);
        }
    }
}

fn passwd_fill_store() -> *mut Passwd {
    soft_env_seed_defaults();
    let uid = unsafe { getuid() };
    let gid = unsafe { getgid() };
    let login = unsafe { getlogin() };
    let home = unsafe { getenv(c"HOME".as_ptr()) };
    unsafe {
        copy_cstr_to(&mut PW_NAME, login, b"kakehashi");
        copy_cstr_to(&mut PW_DIR, home, b"/var/root");
        PW_STORE = Passwd {
            pw_name: PW_NAME.as_mut_ptr().cast(),
            pw_passwd: PW_PASS.as_mut_ptr().cast(),
            pw_uid: uid,
            pw_gid: gid,
            pw_change: 0,
            pw_class: PW_EMPTY.as_mut_ptr().cast(),
            pw_gecos: PW_NAME.as_mut_ptr().cast(),
            pw_dir: PW_DIR.as_mut_ptr().cast(),
            pw_shell: PW_SHELL.as_mut_ptr().cast(),
            pw_expire: 0,
        };
        core::ptr::addr_of_mut!(PW_STORE)
    }
}

fn cstr_eq(left: *const c_char, right: *const c_char) -> bool {
    if left.is_null() || right.is_null() {
        return false;
    }
    let mut idx = 0_usize;
    loop {
        let lhs = unsafe { *left.add(idx) };
        let rhs = unsafe { *right.add(idx) };
        if lhs != rhs {
            return false;
        }
        if lhs == 0 {
            return true;
        }
        idx = idx.saturating_add(1);
        if idx > 256 {
            return false;
        }
    }
}

/// C `getpwuid` → nlist `_getpwuid`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpwuid(_uid: u32) -> *mut c_void {
    passwd_fill_store().cast()
}

/// C `getpwnam` → nlist `_getpwnam`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return core::ptr::null_mut();
    }
    let pw = passwd_fill_store();
    if cstr_eq(name, unsafe { (*pw).pw_name }) {
        pw.cast()
    } else {
        core::ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getgrgid(_gid: u32) -> *mut c_void {
    core::ptr::null_mut()
}

/// C `setpwent` → nlist `_setpwent`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setpwent() {
    unsafe {
        PW_WALKED = false;
    }
}

/// C `endpwent` → nlist `_endpwent`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn endpwent() {
    unsafe {
        PW_WALKED = true;
    }
}

/// C `getpwent` → nlist `_getpwent`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpwent() -> *mut c_void {
    unsafe {
        if PW_WALKED {
            return core::ptr::null_mut();
        }
        PW_WALKED = true;
    }
    passwd_fill_store().cast()
}

fn passwd_copy_to(
    dst: *mut Passwd,
    buf: *mut c_char,
    buflen: usize,
) -> Result<(), c_int> {
    if dst.is_null() || buf.is_null() {
        return Err(EINVAL);
    }
    let src = passwd_fill_store();
    let name = unsafe { (*src).pw_name };
    let dir = unsafe { (*src).pw_dir };
    let shell = unsafe { (*src).pw_shell };
    let nlen = unsafe { super::stdio::strlen(name) }.saturating_add(1);
    let dlen = unsafe { super::stdio::strlen(dir) }.saturating_add(1);
    let slen = unsafe { super::stdio::strlen(shell) }.saturating_add(1);
    let need = nlen.saturating_add(dlen).saturating_add(slen).saturating_add(4);
    if buflen < need {
        return Err(34); // ERANGE
    }
    let mut off = 0_usize;
    unsafe {
        core::ptr::copy_nonoverlapping(name.cast::<u8>(), buf.add(off).cast::<u8>(), nlen);
        let name_p = buf.add(off);
        off = off.saturating_add(nlen);
        core::ptr::copy_nonoverlapping(dir.cast::<u8>(), buf.add(off).cast::<u8>(), dlen);
        let dir_p = buf.add(off);
        off = off.saturating_add(dlen);
        core::ptr::copy_nonoverlapping(shell.cast::<u8>(), buf.add(off).cast::<u8>(), slen);
        let shell_p = buf.add(off);
        off = off.saturating_add(slen);
        buf.add(off).write(0);
        let empty_p = buf.add(off);
        off = off.saturating_add(1);
        buf.add(off).write(b'*'.cast_signed());
        buf.add(off.saturating_add(1)).write(0);
        let pass_p = buf.add(off);
        dst.write(Passwd {
            pw_name: name_p,
            pw_passwd: pass_p,
            pw_uid: (*src).pw_uid,
            pw_gid: (*src).pw_gid,
            pw_change: 0,
            pw_class: empty_p,
            pw_gecos: name_p,
            pw_dir: dir_p,
            pw_shell: shell_p,
            pw_expire: 0,
        });
    }
    Ok(())
}

/// C `getpwuid_r` → nlist `_getpwuid_r`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpwuid_r(
    _uid: u32,
    pwd: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    match passwd_copy_to(pwd.cast(), buf, buflen) {
        Ok(()) => {
            if !result.is_null() {
                unsafe {
                    result.write(pwd);
                }
            }
            0
        }
        Err(e) => {
            if !result.is_null() {
                unsafe {
                    result.write(core::ptr::null_mut());
                }
            }
            e
        }
    }
}

/// C `getpwnam_r` → nlist `_getpwnam_r`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpwnam_r(
    name: *const c_char,
    pwd: *mut c_void,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if name.is_null() || unsafe { getpwnam(name) }.is_null() {
        if !result.is_null() {
            unsafe {
                result.write(core::ptr::null_mut());
            }
        }
        return 0;
    }
    unsafe { getpwuid_r(0, pwd, buf, buflen, result) }
}

// ── mmap surface (OpenSSL / curl may map pages) ─────────────────────────────

/// C `mmap` → nlist `_mmap`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> *mut c_void {
    if len == 0 {
        errno::set_errno(EINVAL);
        return core::ptr::with_exposed_provenance_mut::<c_void>(usize::MAX);
    }
    let ret = unsafe {
        sys::syscall6(
            SYS_MMAP,
            ptr_u64(addr),
            u64::try_from(len).unwrap_or(0),
            u64::from(prot.cast_unsigned()),
            u64::from(flags.cast_unsigned()),
            u64::from(fd.cast_unsigned()),
            offset.cast_unsigned(),
        )
    };
    if ret < 0 {
        apply_ret(ret);
        // MAP_FAILED == (void *)-1
        return core::ptr::with_exposed_provenance_mut::<c_void>(usize::MAX);
    }
    let a = usize::try_from(ret).unwrap_or(0);
    core::ptr::with_exposed_provenance_mut::<c_void>(a)
}

/// C `munmap` → nlist `_munmap`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn munmap(addr: *mut c_void, len: usize) -> c_int {
    if addr.is_null() || len == 0 {
        errno::set_errno(EINVAL);
        return -1;
    }
    let ret = unsafe { sys::syscall2(SYS_MUNMAP, ptr_u64(addr), u64::try_from(len).unwrap_or(0)) };
    ret_c_int(ret)
}

/// C `mprotect` → nlist `_mprotect`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int {
    if addr.is_null() || len == 0 {
        errno::set_errno(EINVAL);
        return -1;
    }
    let ret = unsafe {
        sys::syscall3(
            SYS_MPROTECT,
            ptr_u64(addr),
            u64::try_from(len).unwrap_or(0),
            u64::from(prot.cast_unsigned()),
        )
    };
    ret_c_int(ret)
}

/// C `mlock` → nlist `_mlock` (soft success; pages stay resident on host).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mlock(_addr: *const c_void, _len: usize) -> c_int {
    0
}

// ── Mach VM soft (modern Apple `ld`) ────────────────────────────────────────
//
// Observed: modern ld imports `vm_allocate` / `mach_task_self_`. Map to
// anonymous `mmap` / `munmap`. KERN_SUCCESS = 0.

const KERN_SUCCESS: c_int = 0;
const KERN_INVALID_ARGUMENT: c_int = 4;
const KERN_NO_SPACE: c_int = 3;
const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_PRIVATE: c_int = 0x0002;
const MAP_ANON: c_int = 0x1000;

/// `mach_task_self_` data → soft task port token.
#[unsafe(export_name = "mach_task_self_")]
#[used]
static mut MACH_TASK_SELF: usize = 1;

/// `mach_task_self()` → same soft token.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mach_task_self() -> usize {
    1
}

// Mach `semaphore_*` (libpthread / rust std). Ports are 1-based table indices.
const MACH_SEM_CAP: usize = 64;
const KERN_FAILURE: c_int = 5;
const KERN_OPERATION_TIMED_OUT: c_int = 49;

static MACH_SEM_USED: [AtomicBool; MACH_SEM_CAP] = [const { AtomicBool::new(false) }; MACH_SEM_CAP];
static MACH_SEM_COUNT: [AtomicI32; MACH_SEM_CAP] = [const { AtomicI32::new(0) }; MACH_SEM_CAP];
static MACH_SEM_PARK: [AtomicU32; MACH_SEM_CAP] = [const { AtomicU32::new(0) }; MACH_SEM_CAP];

fn mach_sem_idx(port: u32) -> Option<usize> {
    let i = usize::try_from(port).ok()?.checked_sub(1)?;
    if i < MACH_SEM_CAP && MACH_SEM_USED[i].load(Ordering::Acquire) {
        Some(i)
    } else {
        None
    }
}

fn mach_sem_park(i: usize, expected: u32) {
    let addr = u64::try_from(MACH_SEM_PARK[i].as_ptr().addr()).unwrap_or(0);
    let _ = unsafe { sys::helper2(KH_HELPER_PARK, addr, u64::from(expected)) };
}

fn mach_sem_wake(i: usize) {
    let addr = u64::try_from(MACH_SEM_PARK[i].as_ptr().addr()).unwrap_or(0);
    let _ = unsafe { sys::helper2(KH_HELPER_WAKE, addr, 1) };
}

/// `semaphore_create(task, semaphore, policy, value)` → nlist `_semaphore_create`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn semaphore_create(
    _task: usize,
    semaphore: *mut u32,
    _policy: c_int,
    value: c_int,
) -> c_int {
    if semaphore.is_null() || value < 0 {
        return KERN_INVALID_ARGUMENT;
    }
    for i in 0..MACH_SEM_CAP {
        if MACH_SEM_USED[i]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            MACH_SEM_COUNT[i].store(value, Ordering::Release);
            MACH_SEM_PARK[i].store(0, Ordering::Release);
            let port = u32::try_from(i.saturating_add(1)).unwrap_or(1);
            unsafe {
                semaphore.write(port);
            }
            return KERN_SUCCESS;
        }
    }
    KERN_FAILURE
}

/// `semaphore_destroy(task, semaphore)`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn semaphore_destroy(_task: usize, semaphore: u32) -> c_int {
    let Some(i) = mach_sem_idx(semaphore) else {
        return KERN_INVALID_ARGUMENT;
    };
    MACH_SEM_USED[i].store(false, Ordering::Release);
    MACH_SEM_PARK[i].fetch_add(1, Ordering::AcqRel);
    mach_sem_wake(i);
    KERN_SUCCESS
}

/// `semaphore_signal(semaphore)`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn semaphore_signal(semaphore: u32) -> c_int {
    let Some(i) = mach_sem_idx(semaphore) else {
        return KERN_INVALID_ARGUMENT;
    };
    MACH_SEM_COUNT[i].fetch_add(1, Ordering::AcqRel);
    MACH_SEM_PARK[i].fetch_add(1, Ordering::AcqRel);
    mach_sem_wake(i);
    KERN_SUCCESS
}

/// `semaphore_signal_all(semaphore)`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn semaphore_signal_all(semaphore: u32) -> c_int {
    let Some(i) = mach_sem_idx(semaphore) else {
        return KERN_INVALID_ARGUMENT;
    };
    MACH_SEM_COUNT[i].fetch_add(1, Ordering::AcqRel);
    MACH_SEM_PARK[i].fetch_add(1, Ordering::AcqRel);
    let addr = u64::try_from(MACH_SEM_PARK[i].as_ptr().addr()).unwrap_or(0);
    let _ = unsafe { sys::helper2(KH_HELPER_WAKE, addr, 0) };
    KERN_SUCCESS
}

/// `semaphore_wait(semaphore)`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn semaphore_wait(semaphore: u32) -> c_int {
    let Some(i) = mach_sem_idx(semaphore) else {
        return KERN_INVALID_ARGUMENT;
    };
    loop {
        let cur = MACH_SEM_COUNT[i].load(Ordering::Acquire);
        if cur > 0
            && MACH_SEM_COUNT[i]
                .compare_exchange(cur, cur.saturating_sub(1), Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            return KERN_SUCCESS;
        }
        if !MACH_SEM_USED[i].load(Ordering::Acquire) {
            return KERN_INVALID_ARGUMENT;
        }
        let park_gen = MACH_SEM_PARK[i].load(Ordering::Acquire);
        if MACH_SEM_COUNT[i].load(Ordering::Acquire) > 0 {
            continue;
        }
        mach_sem_park(i, park_gen);
    }
}

/// `semaphore_timedwait(semaphore, wait_time)` — one park; timeout if still empty.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn semaphore_timedwait(semaphore: u32, _wait_time: u64) -> c_int {
    let Some(i) = mach_sem_idx(semaphore) else {
        return KERN_INVALID_ARGUMENT;
    };
    let cur = MACH_SEM_COUNT[i].load(Ordering::Acquire);
    if cur > 0
        && MACH_SEM_COUNT[i]
            .compare_exchange(cur, cur.saturating_sub(1), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        return KERN_SUCCESS;
    }
    let park_gen = MACH_SEM_PARK[i].load(Ordering::Acquire);
    mach_sem_park(i, park_gen);
    let cur = MACH_SEM_COUNT[i].load(Ordering::Acquire);
    if cur > 0
        && MACH_SEM_COUNT[i]
            .compare_exchange(cur, cur.saturating_sub(1), Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        return KERN_SUCCESS;
    }
    KERN_OPERATION_TIMED_OUT
}

/// `vm_page_mask` data → page_size-1 (page size also in `ld_surface::vm_page_size`).
#[unsafe(export_name = "vm_page_mask")]
#[used]
static mut VM_PAGE_MASK: usize = 0x3fff; // 16 KiB page mask (matches ld_surface)

/// Darwin arm64 guest page (matches `vm_page_size` / `vm_page_mask`).
const VM_PAGE: usize = 16_384;
const VM_META_WORDS: usize = 2;
const VM_META_BYTES: usize = core::mem::size_of::<usize>() * VM_META_WORDS;

/// Side table of `vm_allocate` interiors. Darwin guests (otool, cctools) pair
/// `mmap` with `vm_deallocate`; peeking 16 bytes before `addr` SIGSEGVs when
/// that page is not ours.
const VM_REG_CAP: usize = 128;

#[derive(Clone, Copy)]
struct VmRegion {
    user: usize,
    raw: usize,
    map_size: usize,
}

static mut VM_REGS: [VmRegion; VM_REG_CAP] = [VmRegion {
    user: 0,
    raw: 0,
    map_size: 0,
}; VM_REG_CAP];
static VM_REGS_LOCK: AtomicBool = AtomicBool::new(false);

fn vm_regs_lock() {
    while VM_REGS_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

fn vm_regs_unlock() {
    VM_REGS_LOCK.store(false, Ordering::Release);
}

fn vm_reg_insert(user: usize, raw: usize, map_size: usize) {
    if user == 0 {
        return;
    }
    vm_regs_lock();
    // SAFETY: exclusive via VM_REGS_LOCK.
    unsafe {
        for slot in &mut VM_REGS {
            if slot.user == 0 {
                *slot = VmRegion {
                    user,
                    raw,
                    map_size,
                };
                break;
            }
        }
    }
    vm_regs_unlock();
}

fn vm_reg_take(user: usize) -> Option<(usize, usize)> {
    if user == 0 {
        return None;
    }
    vm_regs_lock();
    let found = unsafe {
        let mut hit = None;
        for slot in &mut VM_REGS {
            if slot.user == user {
                hit = Some((slot.raw, slot.map_size));
                *slot = VmRegion {
                    user: 0,
                    raw: 0,
                    map_size: 0,
                };
                break;
            }
        }
        hit
    };
    vm_regs_unlock();
    found
}

/// `vm_allocate(task, *addr, size, flags)` → anonymous RW map.
///
/// `flags` bit0 = anywhere (1) vs fixed (0). Soft: always anywhere via mmap.
///
/// **Alignment (G5):** host Linux mmap is often 4 KiB-aligned; modern Apple `ld`
/// `UnsafeHeaderWriter` requires `buffer.data()` aligned to guest page (16 KiB).
/// Over-map and return a 16 KiB-aligned interior pointer. Raw base + map size
/// are recorded in a side table — never recovered by reading before the user
/// pointer (`mmap`+`vm_deallocate` has no prefix page).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn vm_allocate(
    _task: usize,
    addr: *mut *mut c_void,
    size: usize,
    _flags: c_int,
) -> c_int {
    if addr.is_null() || size == 0 {
        return KERN_INVALID_ARGUMENT;
    }
    let map_size = size.saturating_add(VM_PAGE).saturating_add(VM_META_BYTES);
    let raw = unsafe {
        mmap(
            core::ptr::null_mut(),
            map_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        )
    };
    if raw.addr() == usize::MAX || raw.is_null() {
        return KERN_NO_SPACE;
    }
    let raw_addr = raw.addr();
    // Align user to guest page; leave VM_META_BYTES before it for bookkeeping.
    let user_addr = (raw_addr
        .saturating_add(VM_META_BYTES)
        .saturating_add(VM_PAGE - 1))
        & !(VM_PAGE - 1);
    if user_addr.saturating_add(size) > raw_addr.saturating_add(map_size)
        || user_addr < raw_addr.saturating_add(VM_META_BYTES)
    {
        let _ = unsafe { munmap(raw, map_size) };
        return KERN_NO_SPACE;
    }
    vm_reg_insert(user_addr, raw_addr, map_size);
    unsafe {
        addr.write(core::ptr::with_exposed_provenance_mut(user_addr));
    }
    KERN_SUCCESS
}

/// `vm_deallocate(task, addr, size)`.
///
/// Must not load from `addr - N`. Apple cctools (`otool-classic`) maps a file
/// with `mmap` and releases it with `vm_deallocate`; the bytes before the map
/// are unmapped.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn vm_deallocate(
    _task: usize,
    addr: *mut c_void,
    size: usize,
) -> c_int {
    if addr.is_null() || size == 0 {
        return KERN_INVALID_ARGUMENT;
    }
    let (unmap_ptr, unmap_len) = match vm_reg_take(addr.addr()) {
        Some((raw, map_size)) => (core::ptr::with_exposed_provenance_mut(raw), map_size),
        None => (addr, size),
    };
    let rc = unsafe { munmap(unmap_ptr, unmap_len) };
    if rc != 0 {
        KERN_INVALID_ARGUMENT
    } else {
        KERN_SUCCESS
    }
}

/// `vm_remap` — soft: allocate fresh anonymous region (no real remap).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn vm_remap(
    _target_task: usize,
    target_address: *mut *mut c_void,
    size: usize,
    _mask: usize,
    _flags: c_int,
    _src_task: usize,
    _src_address: *mut c_void,
    _copy: c_int,
    _cur_protection: *mut c_int,
    _max_protection: *mut c_int,
    _inheritance: c_int,
) -> c_int {
    unsafe { vm_allocate(1, target_address, size, 1) }
}

// ── PRNG ────────────────────────────────────────────────────────────────────

static mut RAND_STATE: u32 = 1;

/// C `srand` → nlist `_srand`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn srand(seed: u32) {
    unsafe {
        RAND_STATE = if seed == 0 { 1 } else { seed };
    }
}

/// C `rand` → nlist `_rand` (LCG; not crypto).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn rand() -> c_int {
    // SAFETY: single-threaded init paths; fine for curl scaffolding.
    unsafe {
        // Numerical Recipes LCG constants.
        RAND_STATE = RAND_STATE
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        c_int::try_from(RAND_STATE >> 1).unwrap_or(0)
    }
}

// ── time ────────────────────────────────────────────────────────────────────

/// C `gettimeofday` → nlist `_gettimeofday`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn gettimeofday(tp: *mut c_void, tzp: *mut c_void) -> c_int {
    let ret = unsafe { sys::syscall2(SYS_GETTIMEOFDAY, ptr_u64(tp), ptr_u64(tzp)) };
    ret_c_int(ret)
}

/// C `time` → nlist `_time`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn time(tloc: *mut i64) -> i64 {
    // timeval: sec i64 + usec i32 + pad
    let mut tv = [0_u8; 16];
    let ret = unsafe { sys::syscall2(SYS_GETTIMEOFDAY, ptr_u64(tv.as_mut_ptr().cast()), 0) };
    if ret < 0 {
        apply_ret(ret);
        return -1;
    }
    let sec = i64::from_le_bytes([tv[0], tv[1], tv[2], tv[3], tv[4], tv[5], tv[6], tv[7]]);
    if !tloc.is_null() {
        unsafe {
            tloc.write(sec);
        }
    }
    sec
}

/// C `times` → nlist `_times`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn times(buffer: *mut c_void) -> i64 {
    if !buffer.is_null() {
        unsafe {
            crate::dylib::libsystem_c::stdio::bzero(buffer, 32);
        }
    }
    0
}

/// C `timespec_get` → nlist `_timespec_get` (TIME_UTC = 1).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn timespec_get(ts: *mut c_void, base: c_int) -> c_int {
    if ts.is_null() || base != 1 {
        return 0;
    }
    let mut tv = [0_u8; 16];
    let ret = unsafe { sys::syscall2(SYS_GETTIMEOFDAY, ptr_u64(tv.as_mut_ptr().cast()), 0) };
    if ret < 0 {
        return 0;
    }
    let sec = i64::from_le_bytes([tv[0], tv[1], tv[2], tv[3], tv[4], tv[5], tv[6], tv[7]]);
    let usec = i32::from_le_bytes([tv[8], tv[9], tv[10], tv[11]]);
    let nsec = i64::from(usec).saturating_mul(1000);
    unsafe {
        let p = ts.cast::<i64>();
        p.write(sec);
        p.add(1).write(nsec);
    }
    base
}

/// C `gmtime` / `localtime` → static tm (epoch stub).
#[repr(C)]
struct Tm {
    sec: c_int,
    min: c_int,
    hour: c_int,
    mday: c_int,
    mon: c_int,
    year: c_int,
    wday: c_int,
    yday: c_int,
    isdst: c_int,
    gmtoff: i64,
    zone: *const c_char,
}

static mut TM_BUF: Tm = Tm {
    sec: 0,
    min: 0,
    hour: 0,
    mday: 1,
    mon: 0,
    year: 70,
    wday: 4,
    yday: 0,
    isdst: 0,
    gmtoff: 0,
    zone: core::ptr::null(),
};

static mut ZONE: [u8; 4] = *b"UTC\0";

/// C `gmtime` → nlist `_gmtime`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn gmtime(clock: *const i64) -> *mut c_void {
    unsafe { fill_tm(clock).cast() }
}

/// C `localtime` → nlist `_localtime`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn localtime(clock: *const i64) -> *mut c_void {
    unsafe { fill_tm(clock).cast() }
}

/// C `gmtime_r` → nlist `_gmtime_r`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn gmtime_r(clock: *const i64, result: *mut c_void) -> *mut c_void {
    if result.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        fill_tm_into(clock, result.cast());
        result
    }
}

/// C `localtime_r` → nlist `_localtime_r`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn localtime_r(clock: *const i64, result: *mut c_void) -> *mut c_void {
    unsafe { gmtime_r(clock, result) }
}

/// C `difftime` → nlist `_difftime`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn difftime(time1: f64, time0: f64) -> f64 {
    time1 - time0
}

/// POSIX `asctime` buffer: `"Www Mmm dd hh:mm:ss yyyy\n"` + NUL (26+1).
static mut CTIME_BUF: [c_char; 32] = [0; 32];

const WEEKDAYS: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

#[allow(clippy::integer_division)]
fn write_two_digits(dst: &mut [u8], tens_idx: usize, v: c_int, space_pad_tens: bool) {
    let n = v.max(0);
    let tens = n / 10;
    let ones = n % 10;
    if let Some(slot) = dst.get_mut(tens_idx) {
        *slot = if space_pad_tens && tens == 0 {
            b' '
        } else {
            b'0'.wrapping_add(u8::try_from(tens).unwrap_or(0))
        };
    }
    if let Some(slot) = dst.get_mut(tens_idx.saturating_add(1)) {
        *slot = b'0'.wrapping_add(u8::try_from(ones).unwrap_or(0));
    }
}

/// `"Www Mmm dd hh:mm:ss yyyy\n\0"` into `dst` (needs 27 bytes).
unsafe fn write_asctime(tm: &Tm, dst: *mut c_char) {
    let mut buf = *b"Thu Jan  1 00:00:00 1970\n\0";
    let w = usize::try_from(tm.wday.rem_euclid(7)).unwrap_or(0);
    let mo = usize::try_from(tm.mon.rem_euclid(12)).unwrap_or(0);
    if let (Some(day), Some(slot)) = (WEEKDAYS.get(w), buf.get_mut(0..3)) {
        slot.copy_from_slice(*day);
    }
    if let (Some(mon), Some(slot)) = (MONTHS.get(mo), buf.get_mut(4..7)) {
        slot.copy_from_slice(*mon);
    }
    write_two_digits(&mut buf, 8, tm.mday, true);
    write_two_digits(&mut buf, 11, tm.hour, false);
    write_two_digits(&mut buf, 14, tm.min, false);
    write_two_digits(&mut buf, 17, tm.sec, false);
    let year = tm.year.saturating_add(1900).max(0);
    let y = u32::try_from(year).unwrap_or(1970);
    #[allow(clippy::integer_division)]
    {
        if let Some(slot) = buf.get_mut(20) {
            *slot = b'0'.wrapping_add(u8::try_from((y / 1000) % 10).unwrap_or(1));
        }
        if let Some(slot) = buf.get_mut(21) {
            *slot = b'0'.wrapping_add(u8::try_from((y / 100) % 10).unwrap_or(9));
        }
        if let Some(slot) = buf.get_mut(22) {
            *slot = b'0'.wrapping_add(u8::try_from((y / 10) % 10).unwrap_or(7));
        }
        if let Some(slot) = buf.get_mut(23) {
            *slot = b'0'.wrapping_add(u8::try_from(y % 10).unwrap_or(0));
        }
    }
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr().cast::<c_char>(), dst, buf.len());
    }
}

/// C `asctime` → nlist `_asctime`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn asctime(tm: *const c_void) -> *mut c_char {
    if tm.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        write_asctime(&*tm.cast::<Tm>(), CTIME_BUF.as_mut_ptr());
        CTIME_BUF.as_mut_ptr()
    }
}

/// C `asctime_r` → nlist `_asctime_r`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn asctime_r(tm: *const c_void, buf: *mut c_char) -> *mut c_char {
    if tm.is_null() || buf.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        write_asctime(&*tm.cast::<Tm>(), buf);
        buf
    }
}

/// C `ctime` → nlist `_ctime` (otool `-l` timestamps).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ctime(clock: *const i64) -> *mut c_char {
    unsafe { asctime(fill_tm(clock).cast()) }
}

/// C `ctime_r` → nlist `_ctime_r`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ctime_r(clock: *const i64, buf: *mut c_char) -> *mut c_char {
    if buf.is_null() {
        return core::ptr::null_mut();
    }
    let mut tmp = Tm {
        sec: 0,
        min: 0,
        hour: 0,
        mday: 1,
        mon: 0,
        year: 70,
        wday: 4,
        yday: 0,
        isdst: 0,
        gmtoff: 0,
        zone: core::ptr::null(),
    };
    unsafe {
        fill_tm_into(clock, core::ptr::addr_of_mut!(tmp));
        write_asctime(&tmp, buf);
        buf
    }
}

unsafe fn fill_tm(clock: *const i64) -> *mut Tm {
    unsafe {
        fill_tm_into(clock, core::ptr::addr_of_mut!(TM_BUF));
        core::ptr::addr_of_mut!(TM_BUF)
    }
}

unsafe fn fill_tm_into(clock: *const i64, out: *mut Tm) {
    let t = if clock.is_null() {
        0
    } else {
        unsafe { clock.read() }
    };
    // Very rough breakdown (enough for bind + trivial callers / HTTP dates).
    let days = t.div_euclid(86_400);
    let sod = t.rem_euclid(86_400);
    unsafe {
        (*out).sec = trunc_i64_to_c_int(sod.rem_euclid(60));
        (*out).min = trunc_i64_to_c_int(sod.div_euclid(60).rem_euclid(60));
        (*out).hour = trunc_i64_to_c_int(sod.div_euclid(3_600));
        (*out).mday = trunc_i64_to_c_int(days.rem_euclid(28).saturating_add(1));
        (*out).mon = 0;
        (*out).year = trunc_i64_to_c_int(70_i64.saturating_add(days.div_euclid(365)));
        (*out).wday = trunc_i64_to_c_int(days.saturating_add(4).rem_euclid(7));
        (*out).yday = trunc_i64_to_c_int(days.rem_euclid(365));
        (*out).isdst = 0;
        (*out).gmtoff = 0;
        (*out).zone = core::ptr::addr_of!(ZONE).cast();
    }
}

fn strftime_push(out: &mut [u8; 128], oi: &mut usize, b: u8) -> bool {
    if oi.saturating_add(1) >= out.len() {
        return false;
    }
    let Some(slot) = out.get_mut(*oi) else {
        return false;
    };
    *slot = b;
    *oi = oi.saturating_add(1);
    true
}

fn strftime_push_str(out: &mut [u8; 128], oi: &mut usize, bytes: &[u8]) -> bool {
    for &b in bytes {
        if b == 0 {
            break;
        }
        if !strftime_push(out, oi, b) {
            return false;
        }
    }
    true
}

fn strftime_push_u(out: &mut [u8; 128], oi: &mut usize, mut v: u32, width: usize) -> bool {
    let mut buf = [b'0'; 8];
    let mut i = 8_usize;
    if v == 0 {
        i = i.saturating_sub(1);
    } else {
        while v > 0 && i > 0 {
            i = i.saturating_sub(1);
            let digit = u8::try_from(v % 10).unwrap_or(0);
            if let Some(slot) = buf.get_mut(i) {
                *slot = b'0'.wrapping_add(digit);
            }
            v /= 10;
        }
    }
    let digits = 8_usize.saturating_sub(i);
    let pad = width.saturating_sub(digits);
    for _ in 0..pad {
        if !strftime_push(out, oi, b'0') {
            return false;
        }
    }
    let Some(slice) = buf.get(i..) else {
        return false;
    };
    strftime_push_str(out, oi, slice)
}

/// C `strftime` → nlist `_strftime` (subset for HTTP / logs).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn strftime(
    s: *mut c_char,
    max: usize,
    format: *const c_char,
    tm: *const c_void,
) -> usize {
    // Darwin PAGEZERO is 4 GiB; refuse low/unrebased buffers.
    if s.is_null()
        || s.addr() < crate::dylib::libsystem_c::stdio::PAGEZERO_END
        || max == 0
        || format.is_null()
        || format.addr() < crate::dylib::libsystem_c::stdio::PAGEZERO_END
        || tm.is_null()
        || tm.addr() < crate::dylib::libsystem_c::stdio::PAGEZERO_END
    {
        return 0;
    }
    let max = max.min(4096);
    let t = unsafe { &*tm.cast::<Tm>() };
    let mut out = [0_u8; 128];
    let mut oi = 0_usize;
    let mut fi = 0_usize;
    // SAFETY: format is a guest C string (checked above).
    unsafe {
        loop {
            let c = format.add(fi).read().cast_unsigned();
            if c == 0 {
                break;
            }
            fi = fi.saturating_add(1);
            if c != b'%' {
                if !strftime_push(&mut out, &mut oi, c) {
                    return 0;
                }
                continue;
            }
            let spec = format.add(fi).read().cast_unsigned();
            if spec == 0 {
                break;
            }
            fi = fi.saturating_add(1);
            let ok = match spec {
                b'%' => strftime_push(&mut out, &mut oi, b'%'),
                b'Y' => strftime_push_u(
                    &mut out,
                    &mut oi,
                    u32::try_from(t.year.saturating_add(1900)).unwrap_or(0),
                    4,
                ),
                b'm' => strftime_push_u(
                    &mut out,
                    &mut oi,
                    u32::try_from(t.mon.saturating_add(1)).unwrap_or(1),
                    2,
                ),
                b'd' | b'e' => {
                    strftime_push_u(&mut out, &mut oi, u32::try_from(t.mday).unwrap_or(1), 2)
                }
                b'H' => strftime_push_u(&mut out, &mut oi, u32::try_from(t.hour).unwrap_or(0), 2),
                b'M' => strftime_push_u(&mut out, &mut oi, u32::try_from(t.min).unwrap_or(0), 2),
                b'S' => strftime_push_u(&mut out, &mut oi, u32::try_from(t.sec).unwrap_or(0), 2),
                b'a' => {
                    let days = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
                    let idx = usize::try_from(t.wday.rem_euclid(7)).unwrap_or(0);
                    strftime_push_str(&mut out, &mut oi, days.get(idx).copied().unwrap_or(b"???"))
                }
                b'b' | b'h' => {
                    let mons = [
                        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep",
                        b"Oct", b"Nov", b"Dec",
                    ];
                    let idx = usize::try_from(t.mon.rem_euclid(12)).unwrap_or(0);
                    strftime_push_str(&mut out, &mut oi, mons.get(idx).copied().unwrap_or(b"???"))
                }
                b'Z' => strftime_push_str(&mut out, &mut oi, b"UTC"),
                b'z' => strftime_push_str(&mut out, &mut oi, b"+0000"),
                b'T' => strftime_push_str(&mut out, &mut oi, b"T"),
                _ => strftime_push(&mut out, &mut oi, spec),
            };
            if !ok {
                return 0;
            }
        }
    }
    if oi.saturating_add(1) > max {
        return 0;
    }
    unsafe {
        let mut i = 0_usize;
        while i < oi {
            let b = out.get(i).copied().unwrap_or(0);
            s.add(i).write(b.cast_signed());
            i = i.saturating_add(1);
        }
        s.add(oi).write(0);
    }
    oi
}

/// C `mktime` → nlist `_mktime`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn mktime(tm: *mut c_void) -> i64 {
    if tm.is_null() {
        return -1;
    }
    unsafe {
        let t = &*tm.cast::<Tm>();
        let year_off = i64::from(t.year.wrapping_sub(70));
        let days = year_off
            .saturating_mul(365)
            .saturating_add(i64::from(t.yday));
        days.saturating_mul(86_400)
            .saturating_add(i64::from(t.hour).saturating_mul(3_600))
            .saturating_add(i64::from(t.min).saturating_mul(60))
            .saturating_add(i64::from(t.sec))
    }
}

// ── heap ────────────────────────────────────────────────────────────────────

/// C `posix_memalign` → nlist `_posix_memalign`.
///
/// Returns a pointer freeable with `free` (heap header sits immediately before
/// the user address). High alignments use the page-aligned mmap path.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn posix_memalign(
    memptr: *mut *mut c_void,
    alignment: usize,
    size: usize,
) -> c_int {
    if memptr.is_null() || alignment == 0 || !alignment.is_power_of_two() {
        return EINVAL;
    }
    if alignment < core::mem::size_of::<*mut c_void>() {
        return EINVAL;
    }
    let p = crate::kh_core::heap::allocate_aligned(size, alignment);
    if p.is_null() {
        return ENOMEM;
    }
    unsafe {
        memptr.write(p);
    }
    0
}

// ── flock (POSIX; guest `ar` holds archive advisory lock) ────────────────────
//
// Soft: single-process bottle builds don't need cross-process advisory locks.
// Returns 0 for all well-formed ops; EINVAL on bad `operation` bits.
// Public contract: flock(2) man page (LOCK_SH/EX/UN/NB).
//
const LOCK_SH: c_int = 1;
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const LOCK_UN: c_int = 8;

/// C `flock` → nlist `_flock`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn flock(fd: c_int, operation: c_int) -> c_int {
    let _ = fd;
    let op = operation & !LOCK_NB;
    if op != LOCK_SH && op != LOCK_EX && op != LOCK_UN {
        errno::set_errno(EINVAL);
        return -1;
    }
    // Soft success (no host lock). LOCK_NB ignored.
    0
}

// ── getopt (POSIX; guest `ar` / CLI tools) ───────────────────────────────────
//
// Trace-first: CLT `ar -rc` calls `_getopt` immediately. Soft freestanding
// implementation from public POSIX getopt(3) behaviour (man pages / SUS).
// No Darwin/GPL sources.

/// C `optarg` → nlist `_optarg`.
#[unsafe(no_mangle)]
#[used]
#[allow(non_upper_case_globals)]
pub(crate) static mut optarg: *mut c_char = core::ptr::null_mut();

/// C `optind` → nlist `_optind` (next `argv` index; starts at 1).
#[unsafe(no_mangle)]
#[used]
#[allow(non_upper_case_globals)]
pub(crate) static mut optind: c_int = 1;

/// C `opterr` → nlist `_opterr` (print errors to stderr when non-zero).
#[unsafe(no_mangle)]
#[used]
#[allow(non_upper_case_globals)]
pub(crate) static mut opterr: c_int = 1;

/// C `optopt` → nlist `_optopt` (last unknown / missing-arg option char).
#[unsafe(no_mangle)]
#[used]
#[allow(non_upper_case_globals)]
pub(crate) static mut optopt: c_int = 0;

/// C `optreset` → nlist `_optreset` (BSD; non-zero forces a scan restart).
#[unsafe(no_mangle)]
#[used]
#[allow(non_upper_case_globals)]
pub(crate) static mut optreset: c_int = 0;

/// Position within the current `argv[optind]` option cluster (`-abc`).
static mut GETOPT_POS: usize = 1;

unsafe fn getopt_reset_scan() {
    unsafe {
        GETOPT_POS = 1;
    }
}

/// Write a short diagnostic to guest stderr (fd 2) when `opterr != 0`.
unsafe fn getopt_err(argv0: *const c_char, msg: &[u8], bad: u8) {
    if unsafe { opterr } == 0 {
        return;
    }
    let mut buf = [0u8; 160];
    let mut n = 0usize;
    let push = |buf: &mut [u8], n: &mut usize, b: u8| {
        if *n < buf.len() {
            buf[*n] = b;
            *n += 1;
        }
    };
    let push_str = |buf: &mut [u8], n: &mut usize, s: &[u8]| {
        for &b in s {
            push(buf, n, b);
        }
    };
    // argv0
    if argv0.is_null() {
        push_str(&mut buf, &mut n, b"getopt");
    } else {
        let mut p = argv0;
        unsafe {
            while *p != 0 && n < 64 {
                push(&mut buf, &mut n, *p as u8);
                p = p.add(1);
            }
        }
    }
    push_str(&mut buf, &mut n, b": ");
    push_str(&mut buf, &mut n, msg);
    push(&mut buf, &mut n, b'\'');
    push(&mut buf, &mut n, bad);
    push_str(&mut buf, &mut n, b"'\n");
    let _ = unsafe { crate::dylib::libsystem_c::stdio::write(2, buf.as_ptr().cast(), n) };
}

/// C `getopt` → nlist `_getopt`.
///
/// Returns the next option character, `?` / `:` on errors, or `-1` when done.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getopt(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
) -> c_int {
    if argc < 1 || argv.is_null() || optstring.is_null() {
        return -1;
    }
    // SAFETY: globals mutated only on the guest main thread for CLI tools.
    unsafe {
        if optreset != 0 {
            optreset = 0;
            optind = 1;
            getopt_reset_scan();
        }
        if optind < 1 {
            optind = 1;
            getopt_reset_scan();
        }
        if optind >= argc {
            return -1;
        }
        let arg = *argv.add(optind as usize);
        if arg.is_null() {
            return -1;
        }
        let b0 = *arg as u8;
        // Non-option or bare "-" → done (POSIX: leave optind on that argv).
        if b0 != b'-' {
            return -1;
        }
        let b1 = *arg.add(1) as u8;
        if b1 == 0 {
            return -1;
        }
        // "--" end-of-options
        if b1 == b'-' && *arg.add(2) == 0 {
            optind += 1;
            getopt_reset_scan();
            return -1;
        }

        let mut pos = GETOPT_POS;
        if pos == 0 {
            pos = 1;
        }
        let opt_ch = *arg.add(pos) as u8;
        if opt_ch == 0 {
            // Should not happen; advance.
            optind += 1;
            getopt_reset_scan();
            return getopt(argc, argv, optstring);
        }
        optopt = c_int::from(opt_ch);

        // Find opt_ch in optstring; leading ':' enables silent error mode.
        let mut sp = optstring;
        let silent = *sp as u8 == b':';
        if silent {
            sp = sp.add(1);
        }
        let mut found = false;
        let mut needs_arg = false;
        while *sp != 0 {
            let c = *sp as u8;
            sp = sp.add(1);
            if c == opt_ch {
                found = true;
                if *sp as u8 == b':' {
                    needs_arg = true;
                }
                break;
            }
            // Skip trailing ':' of other options.
            if *sp as u8 == b':' {
                sp = sp.add(1);
            }
        }

        if !found {
            // Unknown option.
            GETOPT_POS = pos + 1;
            if *arg.add(GETOPT_POS) == 0 {
                optind += 1;
                getopt_reset_scan();
            }
            let a0 = *argv;
            if !silent {
                getopt_err(a0, b"illegal option -- ", opt_ch);
            }
            return c_int::from(b'?');
        }

        if needs_arg {
            // Argument is rest of this argv, or the next argv.
            let rest = arg.add(pos + 1);
            if *rest != 0 {
                optarg = rest;
                optind += 1;
                getopt_reset_scan();
                return c_int::from(opt_ch);
            }
            // Next argv is the argument.
            if optind + 1 >= argc {
                optind += 1;
                getopt_reset_scan();
                optarg = core::ptr::null_mut();
                let a0 = *argv;
                if silent {
                    return c_int::from(b':');
                }
                getopt_err(a0, b"option requires an argument -- ", opt_ch);
                return c_int::from(b'?');
            }
            optarg = *argv.add((optind + 1) as usize);
            optind += 2;
            getopt_reset_scan();
            return c_int::from(opt_ch);
        }

        // Flag without argument; may be clustered.
        optarg = core::ptr::null_mut();
        GETOPT_POS = pos + 1;
        if *arg.add(GETOPT_POS) == 0 {
            optind += 1;
            getopt_reset_scan();
        }
        c_int::from(opt_ch)
    }
}

const PC_NAME_MAX: c_int = 4;
const PC_PATH_MAX: c_int = 5;
const PC_PIPE_BUF: c_int = 6;

unsafe fn pathconf_value(name: c_int) -> i64 {
    match name {
        PC_NAME_MAX => 255,
        PC_PATH_MAX => 1024,
        PC_PIPE_BUF => 512,
        _ => -1,
    }
}

/// C `pathconf` → nlist `_pathconf`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pathconf(_path: *const c_char, name: c_int) -> i64 {
    unsafe { pathconf_value(name) }
}

/// C `fpathconf` → nlist `_fpathconf`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn fpathconf(_fd: c_int, name: c_int) -> i64 {
    unsafe { pathconf_value(name) }
}

/// Opaque blob for `setmode` / `getmode` (not Apple's layout).
#[repr(C)]
struct ModeHow {
    magic: u32,
    abs: u16,
    add: u16,
    sub: u16,
}

const MODE_MAGIC: u32 = 0x4B48_4D44;
const S_IRWXU: u16 = 0o700;
const S_IRWXG: u16 = 0o070;
const S_IRWXO: u16 = 0o007;
const S_ISUID: u16 = 0o4000;
const S_ISGID: u16 = 0o2000;
const S_ISVTX: u16 = 0o1000;

fn perm_bit(c: u8) -> u16 {
    match c {
        b'r' => 0o444,
        b'w' => 0o222,
        b'x' | b'X' => 0o111,
        b's' => S_ISUID | S_ISGID,
        b't' => S_ISVTX,
        _ => 0,
    }
}

/// C `setmode` → nlist `_setmode`. Parses octal or `u+x` / `a+r` clauses.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setmode(p: *const c_char) -> *mut c_void {
    if p.is_null() {
        return core::ptr::null_mut();
    }
    let raw = unsafe { malloc(core::mem::size_of::<ModeHow>()) };
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let how = raw.cast::<ModeHow>();
    unsafe {
        (*how).magic = MODE_MAGIC;
        (*how).abs = 0xffff;
        (*how).add = 0;
        (*how).sub = 0;
    }
    let mut s = p;
    // Octal?
    let first = unsafe { *s as u8 };
    if first.is_ascii_digit() {
        let mut acc: u16 = 0;
        unsafe {
            while (*s as u8).is_ascii_digit() {
                acc = acc.saturating_mul(8).saturating_add(u16::from(*s as u8 - b'0'));
                s = s.add(1);
            }
            (*how).abs = acc;
        }
        return raw;
    }
    unsafe {
        (*how).abs = 0xffff;
        loop {
            if *s == 0 {
                break;
            }
            if *s as u8 == b',' {
                s = s.add(1);
                continue;
            }
            let mut who: u16 = 0;
            loop {
                match *s as u8 {
                    b'u' => who |= S_IRWXU | S_ISUID,
                    b'g' => who |= S_IRWXG | S_ISGID,
                    b'o' => who |= S_IRWXO,
                    b'a' => who |= S_IRWXU | S_IRWXG | S_IRWXO,
                    _ => break,
                }
                s = s.add(1);
            }
            if who == 0 {
                who = S_IRWXU | S_IRWXG | S_IRWXO;
            }
            let op = *s as u8;
            if op != b'+' && op != b'-' && op != b'=' {
                free(raw);
                return core::ptr::null_mut();
            }
            s = s.add(1);
            let mut bits: u16 = 0;
            loop {
                let b = perm_bit(*s as u8);
                if b == 0 {
                    break;
                }
                bits |= b;
                s = s.add(1);
            }
            bits &= who;
            match op {
                b'+' => (*how).add |= bits,
                b'-' => (*how).sub |= bits,
                b'=' => {
                    (*how).sub |= who;
                    (*how).add |= bits;
                }
                _ => {}
            }
        }
    }
    raw
}

/// C `getmode` → nlist `_getmode`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getmode(set: *const c_void, mode: u16) -> u16 {
    if set.is_null() {
        return mode;
    }
    let how = set.cast::<ModeHow>();
    unsafe {
        if (*how).magic != MODE_MAGIC {
            return mode;
        }
        let mut m = if (*how).abs == 0xffff {
            mode
        } else {
            (*how).abs
        };
        m |= (*how).add;
        m &= !(*how).sub;
        m
    }
}

/// Darwin / BSD `struct option` (LP64).
#[repr(C)]
pub(crate) struct OptionLong {
    name: *const c_char,
    has_arg: c_int,
    flag: *mut c_int,
    val: c_int,
}

const NO_ARGUMENT: c_int = 0;
const REQUIRED_ARGUMENT: c_int = 1;
/// BSD `optional_argument` (2): `--foo` with no `=` leaves `optarg` null.
#[allow(dead_code)]
const OPTIONAL_ARGUMENT: c_int = 2;

unsafe fn cstr_eq_len(opt_name: *const c_char, text: *const c_char, text_len: usize) -> bool {
    if opt_name.is_null() || text.is_null() {
        return false;
    }
    unsafe {
        for i in 0..text_len {
            let c = *opt_name.add(i);
            if c == 0 || c != *text.add(i) {
                return false;
            }
        }
        *opt_name.add(text_len) == 0
    }
}

unsafe fn cstr_is_prefix(name: *const c_char, prefix: *const c_char, prefix_len: usize) -> bool {
    if name.is_null() || prefix.is_null() {
        return false;
    }
    unsafe {
        for i in 0..prefix_len {
            if *name.add(i) == 0 || *name.add(i) != *prefix.add(i) {
                return false;
            }
        }
        true
    }
}

unsafe fn argv_cstr(argv: *const *mut c_char, idx: c_int) -> *mut c_char {
    unsafe { *argv.add(idx as usize) }
}

/// Match `--name` / `--name=arg` against `longopts`. Exact match wins;
/// otherwise a unique prefix. Returns index or `None` if none / ambiguous.
unsafe fn match_longopt(
    longopts: *const OptionLong,
    name: *const c_char,
    name_len: usize,
) -> Option<usize> {
    if longopts.is_null() || name.is_null() {
        return None;
    }
    let mut exact: Option<usize> = None;
    let mut prefix: Option<usize> = None;
    let mut ambiguous = false;
    unsafe {
        let mut i = 0usize;
        loop {
            let opt = &*longopts.add(i);
            if opt.name.is_null() {
                break;
            }
            if cstr_eq_len(opt.name, name, name_len) {
                exact = Some(i);
                break;
            }
            if cstr_is_prefix(opt.name, name, name_len) {
                if prefix.is_some() {
                    ambiguous = true;
                } else {
                    prefix = Some(i);
                }
            }
            i = i.saturating_add(1);
            if i > 512 {
                break;
            }
        }
    }
    if exact.is_some() {
        exact
    } else if ambiguous {
        None
    } else {
        prefix
    }
}

unsafe fn take_long_arg(
    argc: c_int,
    argv: *const *mut c_char,
    inline_arg: *mut c_char,
    has_arg: c_int,
    silent: bool,
    argv0: *mut c_char,
) -> Result<*mut c_char, c_int> {
    unsafe {
        if !inline_arg.is_null() && *inline_arg != 0 {
            if has_arg == NO_ARGUMENT {
                if !silent {
                    getopt_err(argv0, b"option doesn't take an argument -- ", b'-');
                }
                return Err(c_int::from(b'?'));
            }
            return Ok(inline_arg);
        }
        if has_arg == REQUIRED_ARGUMENT {
            if optind >= argc {
                if silent {
                    return Err(c_int::from(b':'));
                }
                getopt_err(argv0, b"option requires an argument -- ", b'-');
                return Err(c_int::from(b'?'));
            }
            let a = argv_cstr(argv, optind);
            optind += 1;
            Ok(a)
        } else {
            Ok(core::ptr::null_mut())
        }
    }
}

unsafe fn finish_long(
    opt: &OptionLong,
    arg: *mut c_char,
    longindex: *mut c_int,
    idx: usize,
) -> c_int {
    unsafe {
        optarg = arg;
        if !longindex.is_null() {
            *longindex = c_int::try_from(idx).unwrap_or(0);
        }
        optopt = if opt.flag.is_null() { opt.val } else { 0 };
        if opt.flag.is_null() {
            opt.val
        } else {
            *opt.flag = opt.val;
            0
        }
    }
}

/// Shared `getopt_long` / `getopt_long_only`.
unsafe fn getopt_long_inner(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const OptionLong,
    longindex: *mut c_int,
    long_only: bool,
) -> c_int {
    if argc < 1 || argv.is_null() || optstring.is_null() {
        return -1;
    }
    unsafe {
        if optreset != 0 {
            optreset = 0;
            optind = 1;
            getopt_reset_scan();
        }
        if optind < 1 {
            optind = 1;
            getopt_reset_scan();
        }
        if optind >= argc {
            return -1;
        }
        let arg = argv_cstr(argv, optind);
        if arg.is_null() {
            return -1;
        }
        let b0 = *arg as u8;
        let b1 = *arg.add(1) as u8;
        let silent = *optstring as u8 == b':';
        let a0 = argv_cstr(argv, 0);

        if b0 != b'-' {
            return -1;
        }
        if b1 == 0 {
            return -1;
        }
        if b1 == b'-' && *arg.add(2) == 0 {
            optind += 1;
            getopt_reset_scan();
            return -1;
        }

        let is_double = b1 == b'-';
        let try_long = is_double || long_only;
        if try_long {
            let name = if is_double { arg.add(2) } else { arg.add(1) };
            let mut name_len = 0usize;
            let mut inline_arg: *mut c_char = core::ptr::null_mut();
            loop {
                let c = *name.add(name_len);
                if c == 0 {
                    break;
                }
                if c as u8 == b'=' {
                    inline_arg = name.add(name_len.saturating_add(1));
                    break;
                }
                name_len = name_len.saturating_add(1);
                if name_len > 256 {
                    break;
                }
            }
            // Isolate the name: temporarily not needed — match uses prefix length.
            if let Some(idx) = match_longopt(longopts, name, name_len) {
                let opt = &*longopts.add(idx);
                optind += 1;
                getopt_reset_scan();
                match take_long_arg(argc, argv, inline_arg, opt.has_arg, silent, a0) {
                    Ok(val) => return finish_long(opt, val, longindex, idx),
                    Err(e) => {
                        optopt = if opt.flag.is_null() { opt.val } else { 0 };
                        return e;
                    }
                }
            } else if is_double {
                optind += 1;
                getopt_reset_scan();
                if !silent {
                    getopt_err(a0, b"unrecognized option -- ", b'-');
                }
                return c_int::from(b'?');
            }
            // long_only and no long match → short options below.
        }

        getopt(argc, argv, optstring)
    }
}

/// C `getopt_long` → nlist `_getopt_long` (BSD / GNU; man getopt_long(3)).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getopt_long(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const OptionLong,
    longindex: *mut c_int,
) -> c_int {
    unsafe { getopt_long_inner(argc, argv, optstring, longopts, longindex, false) }
}

/// C `getopt_long_only` → nlist `_getopt_long_only`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getopt_long_only(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const OptionLong,
    longindex: *mut c_int,
) -> c_int {
    unsafe { getopt_long_inner(argc, argv, optstring, longopts, longindex, true) }
}

// ── getbsize / proc_pidinfo ─────────────────────────────────────────────────

const GETBSIZE_DEFAULT: i64 = 512;
static mut GETBSIZE_HDR: [u8; 32] = [0; 32];

fn parse_blocksize(s: *const c_char) -> Option<i64> {
    if s.is_null() {
        return None;
    }
    let mut i = 0_usize;
    let mut n: i64 = 0;
    let mut seen = false;
    loop {
        let b = unsafe { *s.add(i) } as u8;
        if b == 0 {
            break;
        }
        if b.is_ascii_digit() {
            seen = true;
            n = n.saturating_mul(10).saturating_add(i64::from(b - b'0'));
        } else {
            let mul: i64 = match b {
                b'k' | b'K' => 1024,
                b'm' | b'M' => 1024 * 1024,
                b'g' | b'G' => 1024 * 1024 * 1024,
                _ => return None,
            };
            if unsafe { *s.add(i.saturating_add(1)) } != 0 {
                return None;
            }
            n = n.saturating_mul(mul);
            seen = true;
            break;
        }
        i = i.saturating_add(1);
        if i > 16 {
            return None;
        }
    }
    if !seen || n <= 0 {
        None
    } else {
        Some(n)
    }
}

fn write_bsize_hdr(bytes: i64) -> usize {
    let (n, suf): (i64, &[u8]) = if bytes >= 1024 * 1024 * 1024 && bytes % (1024 * 1024 * 1024) == 0
    {
        (bytes / (1024 * 1024 * 1024), b"G-blocks")
    } else if bytes >= 1024 * 1024 && bytes % (1024 * 1024) == 0 {
        (bytes / (1024 * 1024), b"M-blocks")
    } else if bytes >= 1024 && bytes % 1024 == 0 {
        (bytes / 1024, b"K-blocks")
    } else {
        (bytes, b"-blocks")
    };
    let mut tmp = [0_u8; 32];
    let mut val = n;
    let mut digits = [0_u8; 20];
    let mut nd = 0_usize;
    if val == 0 {
        digits[0] = b'0';
        nd = 1;
    } else {
        while val > 0 && nd < digits.len() {
            digits[nd] = b'0' + u8::try_from((val % 10) as u32).unwrap_or(0);
            nd = nd.saturating_add(1);
            val /= 10;
        }
    }
    let mut o = 0_usize;
    while nd > 0 {
        nd -= 1;
        tmp[o] = digits[nd];
        o = o.saturating_add(1);
    }
    for &b in suf {
        if o < tmp.len() {
            tmp[o] = b;
            o = o.saturating_add(1);
        }
    }
    if o < tmp.len() {
        tmp[o] = 0;
    }
    unsafe {
        GETBSIZE_HDR = [0; 32];
        let ncopy = o.saturating_add(1).min(GETBSIZE_HDR.len());
        GETBSIZE_HDR[..ncopy].copy_from_slice(&tmp[..ncopy]);
    }
    o
}

/// C `getbsize` → nlist `_getbsize` (BSD; `ls` / `du` header + block size).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getbsize(
    headerlenp: *mut c_int,
    blocksizep: *mut i64,
) -> *mut c_char {
    let key = b"BLOCKSIZE\0";
    let env = unsafe { getenv(key.as_ptr().cast()) };
    let bytes = parse_blocksize(env).unwrap_or(GETBSIZE_DEFAULT);
    let len = write_bsize_hdr(bytes);
    if !headerlenp.is_null() {
        unsafe {
            *headerlenp = c_int::try_from(len).unwrap_or(0);
        }
    }
    if !blocksizep.is_null() {
        unsafe {
            *blocksizep = bytes;
        }
    }
    unsafe { GETBSIZE_HDR.as_mut_ptr().cast() }
}

const PROC_PIDTASKALLINFO: c_int = 2;
const PROC_PIDTBSDINFO: c_int = 3;
const PROC_PIDTASKINFO: c_int = 4;
const PROC_PIDT_SHORTBSDINFO: c_int = 13;
const PROC_PIDPATHINFO: c_int = 11;
const PROC_PIDVNODEPATHINFO: c_int = 9;
const PROC_FLAG_LP64: u32 = 0x10;
const MAXCOMLEN: usize = 16;
const BSDINFO_SIZE: usize = 136;
const TASKINFO_SIZE: usize = 96;
const SHORTBSD_SIZE: usize = 64;
const MAXPATHLEN: usize = 1024;

fn put_u32_at(buf: &mut [u8], off: usize, v: u32) {
    if let Some(slot) = buf.get_mut(off..off.saturating_add(4)) {
        slot.copy_from_slice(&v.to_le_bytes());
    }
}

fn put_i32_at(buf: &mut [u8], off: usize, v: i32) {
    if let Some(slot) = buf.get_mut(off..off.saturating_add(4)) {
        slot.copy_from_slice(&v.to_le_bytes());
    }
}

unsafe fn fill_comm(dst: &mut [u8]) {
    let name = b"kh-guest";
    let n = name.len().min(dst.len().saturating_sub(1));
    if let Some(slot) = dst.get_mut(..n) {
        slot.copy_from_slice(&name[..n]);
    }
}

unsafe fn fill_bsdinfo(buf: &mut [u8]) {
    let pid = unsafe { getpid() }.cast_unsigned();
    let ppid = unsafe { getppid() }.cast_unsigned();
    let uid = unsafe { getuid() };
    let gid = unsafe { getgid() };
    let euid = unsafe { geteuid() };
    let egid = unsafe { getegid() };
    put_u32_at(buf, 0, PROC_FLAG_LP64);
    put_u32_at(buf, 4, 2);
    put_u32_at(buf, 12, pid);
    put_u32_at(buf, 16, ppid);
    put_u32_at(buf, 20, uid);
    put_u32_at(buf, 24, gid);
    put_u32_at(buf, 28, uid);
    put_u32_at(buf, 32, gid);
    put_u32_at(buf, 36, euid);
    put_u32_at(buf, 40, egid);
    if let Some(comm) = buf.get_mut(48..48 + MAXCOMLEN) {
        unsafe {
            fill_comm(comm);
        }
    }
    if let Some(nm) = buf.get_mut(48 + MAXCOMLEN..48 + MAXCOMLEN * 3) {
        unsafe {
            fill_comm(nm);
        }
    }
    put_u32_at(buf, 96, 3);
    put_u32_at(buf, 100, pid);
}

unsafe fn fill_taskinfo(buf: &mut [u8]) {
    put_i32_at(buf, 80, 1);
    put_i32_at(buf, 84, 1);
}

unsafe fn copy_pidpath(dst: *mut u8, cap: usize) -> usize {
    if dst.is_null() || cap == 0 {
        return 0;
    }
    let ret = unsafe {
        sys::helper2(
            KH_HELPER_EXECUTABLE_PATH,
            ptr_u64(dst.cast()),
            u64::try_from(cap).unwrap_or(0),
        )
    };
    if ret <= 0 {
        let fallback = b"/usr/bin/kh-guest";
        let n = fallback.len().min(cap.saturating_sub(1));
        unsafe {
            core::ptr::copy_nonoverlapping(fallback.as_ptr(), dst, n);
            dst.add(n).write(0);
        }
        return n;
    }
    usize::try_from(ret).unwrap_or(0)
}

/// C `proc_pidinfo` → nlist `_proc_pidinfo` (libproc; `git` process queries).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn proc_pidinfo(
    pid: c_int,
    flavor: c_int,
    _arg: u64,
    buffer: *mut c_void,
    buffersize: c_int,
) -> c_int {
    let self_pid = unsafe { getpid() };
    if pid != 0 && pid != self_pid {
        errno::set_errno(3);
        return 0;
    }
    if buffersize <= 0 {
        let n = match flavor {
            PROC_PIDTBSDINFO => BSDINFO_SIZE,
            PROC_PIDTASKINFO => TASKINFO_SIZE,
            PROC_PIDTASKALLINFO => BSDINFO_SIZE.saturating_add(TASKINFO_SIZE),
            PROC_PIDT_SHORTBSDINFO => SHORTBSD_SIZE,
            PROC_PIDPATHINFO => MAXPATHLEN,
            PROC_PIDVNODEPATHINFO => MAXPATHLEN.saturating_mul(2).saturating_add(4),
            _ => 0,
        };
        return c_int::try_from(n).unwrap_or(0);
    }
    if buffer.is_null() {
        errno::set_errno(14);
        return 0;
    }
    let cap = usize::try_from(buffersize).unwrap_or(0);
    match flavor {
        PROC_PIDTBSDINFO => {
            if cap < BSDINFO_SIZE {
                errno::set_errno(ENOMEM);
                return 0;
            }
            let mut raw = [0_u8; BSDINFO_SIZE];
            unsafe {
                fill_bsdinfo(&mut raw);
                core::ptr::copy_nonoverlapping(raw.as_ptr(), buffer.cast::<u8>(), BSDINFO_SIZE);
            }
            c_int::try_from(BSDINFO_SIZE).unwrap_or(0)
        }
        PROC_PIDTASKINFO => {
            if cap < TASKINFO_SIZE {
                errno::set_errno(ENOMEM);
                return 0;
            }
            let mut raw = [0_u8; TASKINFO_SIZE];
            unsafe {
                fill_taskinfo(&mut raw);
                core::ptr::copy_nonoverlapping(raw.as_ptr(), buffer.cast::<u8>(), TASKINFO_SIZE);
            }
            c_int::try_from(TASKINFO_SIZE).unwrap_or(0)
        }
        PROC_PIDTASKALLINFO => {
            let need = BSDINFO_SIZE.saturating_add(TASKINFO_SIZE);
            if cap < need {
                errno::set_errno(ENOMEM);
                return 0;
            }
            let mut raw = [0_u8; BSDINFO_SIZE + TASKINFO_SIZE];
            unsafe {
                fill_bsdinfo(&mut raw[..BSDINFO_SIZE]);
                fill_taskinfo(&mut raw[BSDINFO_SIZE..]);
                core::ptr::copy_nonoverlapping(raw.as_ptr(), buffer.cast::<u8>(), need);
            }
            c_int::try_from(need).unwrap_or(0)
        }
        PROC_PIDT_SHORTBSDINFO => {
            if cap < SHORTBSD_SIZE {
                errno::set_errno(ENOMEM);
                return 0;
            }
            let mut raw = [0_u8; SHORTBSD_SIZE];
            let p = unsafe { getpid() }.cast_unsigned();
            let pp = unsafe { getppid() }.cast_unsigned();
            put_u32_at(&mut raw, 0, p);
            put_u32_at(&mut raw, 4, pp);
            put_u32_at(&mut raw, 8, p);
            put_u32_at(&mut raw, 12, 2);
            if let Some(comm) = raw.get_mut(16..16 + MAXCOMLEN) {
                unsafe {
                    fill_comm(comm);
                }
            }
            put_u32_at(&mut raw, 32, PROC_FLAG_LP64);
            put_u32_at(&mut raw, 36, unsafe { getuid() });
            put_u32_at(&mut raw, 40, unsafe { getgid() });
            unsafe {
                core::ptr::copy_nonoverlapping(raw.as_ptr(), buffer.cast::<u8>(), SHORTBSD_SIZE);
            }
            c_int::try_from(SHORTBSD_SIZE).unwrap_or(0)
        }
        PROC_PIDPATHINFO => {
            let n = unsafe { copy_pidpath(buffer.cast(), cap) };
            c_int::try_from(n.saturating_add(1)).unwrap_or(0)
        }
        PROC_PIDVNODEPATHINFO => {
            // Soft: zeroed vnodepathinfo; cwd string in the first path slot
            // after `proc_vnodeinfo` (offset 152 on Darwin: two `vnode_info`
            // 152-byte prefixes — write cwd at 152 if the buffer is large).
            unsafe {
                crate::dylib::libsystem_c::stdio::bzero(buffer, cap);
            }
            if cap > 152 {
                let _ = unsafe { copy_pidpath(buffer.cast::<u8>().add(152), cap.saturating_sub(152)) };
            }
            c_int::try_from(cap.min(1024)).unwrap_or(0)
        }
        _ => {
            errno::set_errno(ENOSYS);
            0
        }
    }
}

/// C `proc_pidpath` → nlist `_proc_pidpath`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn proc_pidpath(
    pid: c_int,
    buffer: *mut c_void,
    buffersize: u32,
) -> c_int {
    let self_pid = unsafe { getpid() };
    if pid != 0 && pid != self_pid {
        errno::set_errno(3);
        return 0;
    }
    let cap = usize::try_from(buffersize).unwrap_or(0);
    let n = unsafe { copy_pidpath(buffer.cast(), cap) };
    c_int::try_from(n).unwrap_or(0)
}

/// C `proc_name` → nlist `_proc_name`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn proc_name(
    pid: c_int,
    buffer: *mut c_void,
    buffersize: u32,
) -> c_int {
    let self_pid = unsafe { getpid() };
    if pid != 0 && pid != self_pid {
        errno::set_errno(3);
        return 0;
    }
    if buffer.is_null() || buffersize == 0 {
        return 0;
    }
    let cap = usize::try_from(buffersize).unwrap_or(0);
    let mut tmp = [0_u8; MAXCOMLEN];
    unsafe {
        fill_comm(&mut tmp);
        let n = tmp.iter().position(|&b| b == 0).unwrap_or(tmp.len());
        let copy = n.min(cap.saturating_sub(1));
        core::ptr::copy_nonoverlapping(tmp.as_ptr(), buffer.cast::<u8>(), copy);
        buffer.cast::<u8>().add(copy).write(0);
        c_int::try_from(copy).unwrap_or(0)
    }
}
