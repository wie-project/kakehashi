//! POSIX / BSD file and process surface (syscalls + soft stubs).

use core::ffi::{c_char, c_int, c_void};

use crate::errno;
use crate::heap::{free, malloc};
use crate::sys::{
    self, SYS_ACCESS, SYS_CHDIR, SYS_CLOSE, SYS_DUP, SYS_DUP2, SYS_EXECVE, SYS_FCNTL, SYS_FORK,
    SYS_FSTAT64, SYS_FSTATAT, SYS_FSYNC, SYS_FTRUNCATE, SYS_GETCWD, SYS_GETEGID, SYS_GETEUID,
    SYS_GETGID, SYS_GETPGRP, SYS_GETPID, SYS_GETPPID, SYS_GETTIMEOFDAY, SYS_GETUID, SYS_KILL,
    SYS_LINK, SYS_LSEEK, SYS_LSTAT64, SYS_MKDIR, SYS_MMAP, SYS_MPROTECT, SYS_MUNMAP, SYS_OPEN,
    SYS_OPENAT, SYS_PREAD, SYS_PWRITE, SYS_READ, SYS_READLINK, SYS_RENAME, SYS_RMDIR, SYS_SETPGID,
    SYS_SETSID, SYS_SIGACTION, SYS_SIGPROCMASK, SYS_STAT64, SYS_SYMLINK, SYS_SYSCTL,
    SYS_SYSCTLBYNAME, SYS_UNLINK, SYS_VFORK, SYS_WAIT4,
};
use crate::trace;
use crate::{KH_HELPER_EXECUTABLE_PATH, KH_HELPER_GUEST_HOME, KH_HELPER_NCPU, KH_HELPER_READDIR};

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

/// C `open` → nlist `_open`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn open(path: *const c_char, oflag: c_int, mode: c_int) -> c_int {
    if path.is_null() {
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
    let len = unsafe { crate::stdio::strlen(template) };
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
        let fd = unsafe { open(template, O_RDWR | O_CREAT | O_EXCL, 0o600) };
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

/// C `openat` → nlist `_openat`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn openat(
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
    if buf.is_null() || size == 0 {
        errno::set_errno(22);
        return core::ptr::null_mut();
    }
    let ret = unsafe {
        sys::syscall2(
            SYS_GETCWD,
            ptr_u64(buf.cast()),
            u64::try_from(size).unwrap_or(0),
        )
    };
    if ret < 0 {
        let _ = apply_ret(ret);
        return core::ptr::null_mut();
    }
    buf
}

/// C `chmod` → nlist `_chmod` (soft success; bottle ignores mode bits).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn chmod(_path: *const c_char, _mode: c_int) -> c_int {
    0
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
    let fd = unsafe { open(name, 0, 0) };
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
        crate::stdio::bzero((*d).ent.as_mut_ptr().cast(), (*d).ent.len());
        crate::stdio::bzero(
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
        crate::stdio::bzero(ent.cast(), DIRENT_SIZE);
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

/// C `tcgetpgrp` → soft: report session group (no real tty).
///
/// Observed: Apple `git index-pack -v` probes controlling-terminal pgrp.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcgetpgrp(_fd: c_int) -> c_int {
    // Same as getpgrp when there is no guest tty association.
    unsafe { getpgrp() }
}

/// C `tcsetpgrp` → soft success (no guest tty).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tcsetpgrp(_fd: c_int, _pgrp: c_int) -> c_int {
    0
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

/// Soft: ignore `file_actions` / `attrp` (no chdir/dup2/close list yet).
/// Observed: Apple clang G3 compile path hits `_posix_spawn` after G1 works.
///
/// Contract (POSIX / public man): **0** on success, error number on failure
/// (does not use the `-1` + errno libc pattern).
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
    let child = unsafe { fork() };
    if child < 0 {
        let e = errno::get_errno();
        return if e == 0 {
            11 /* EAGAIN */
        } else {
            e
        };
    }
    if child == 0 {
        // Child: image replace (runtime re-wraps Mach-O as `kh run`).
        let _ = unsafe { execve(path, argv, env) };
        // execve only returns on failure.
        let e = errno::get_errno();
        let code = if e == 0 { 127 } else { e.clamp(1, 127) };
        unsafe { crate::process::exit_now(code) };
    }
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

/// C `isatty` → nlist `_isatty` (false for bottle).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn isatty(_fd: c_int) -> c_int {
    0
}

/// C `ioctl` → nlist `_ioctl` (ENOTTY-ish).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn ioctl(_fd: c_int, _request: u64, _arg: *mut c_void) -> c_int {
    errno::set_errno(25); // ENOTTY
    -1
}

/// C `usleep` → nlist `_usleep` (yield-based soft sleep for curl G3 cleanup).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn usleep(usec: u32) -> c_int {
    // Soft: yield a few times proportional to usec (not wall-accurate).
    let spins = usec.saturating_div(1000).clamp(1, 50);
    for _ in 0..spins {
        let _ = unsafe { sys::helper0(crate::KH_HELPER_YIELD) };
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
    let src_len = unsafe { crate::stdio::strlen(src) };
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

/// C `setlocale` → nlist `_setlocale` (always "C").
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setlocale(_category: c_int, _locale: *const c_char) -> *mut c_char {
    static mut C_LOCALE: [u8; 2] = *b"C\0";
    core::ptr::addr_of_mut!(C_LOCALE).cast()
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
/// Starts null; first `getenv`/`setenv`/`_NSGetEnviron` seeds defaults and
/// points this at [`ENVIRON_PTRS`]. A null value is also safe: git skips the
/// walk when `environ == NULL`.
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
    let path = b"/Library/Developer/CommandLineTools/usr/libexec/git-core:\
/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\0";
    let tmp = b"/tmp\0";
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
        (b"TMPDIR\0".as_slice(), tmp.as_slice()),
        (b"SDKROOT\0".as_slice(), sdkroot.as_slice()),
        (b"DEVELOPER_DIR\0".as_slice(), developer_dir.as_slice()),
    ] {
        let _ = unsafe { soft_env_set(name.as_ptr().cast(), val.as_ptr().cast(), 1) };
    }
    // Nested `kh run` after `execve` inherits host env with GIT_* from the
    // parent guest's soft environ (inject_kh_env). Pull them in so `getenv`
    // / `environ` walks see `GIT_DIR` (required for clone fetch).
    soft_env_seed_git_from_host();
    // Prefer host-inherited SDKROOT/DEVELOPER_DIR when present (nested -cc1).
    soft_env_seed_sdk_from_host();
    soft_env_rebuild_environ();
}

/// Pull SDKROOT / DEVELOPER_DIR from the host process (nested `kh run`).
fn soft_env_seed_sdk_from_host() {
    const KEYS: &[&[u8]] = &[b"SDKROOT\0", b"DEVELOPER_DIR\0"];
    let mut val_buf = [0_u8; SOFT_ENV_WIDTH];
    for key in KEYS {
        let n = unsafe {
            sys::helper3(
                crate::KH_HELPER_GETENV,
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
                crate::KH_HELPER_GETENV,
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

/// C `getpwuid` / `getgrgid` → null (no passwd DB).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpwuid(_uid: u32) -> *mut c_void {
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getgrgid(_gid: u32) -> *mut c_void {
    core::ptr::null_mut()
}

/// C `getpwuid_r` → nlist `_getpwuid_r` (no passwd DB; return 0 with null result).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpwuid_r(
    _uid: u32,
    _pwd: *mut c_void,
    _buf: *mut c_char,
    _buflen: usize,
    result: *mut *mut c_void,
) -> c_int {
    if !result.is_null() {
        unsafe {
            result.write(core::ptr::null_mut());
        }
    }
    0
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
            crate::stdio::bzero(buffer, 32);
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
        || s.addr() < crate::stdio::PAGEZERO_END
        || max == 0
        || format.is_null()
        || format.addr() < crate::stdio::PAGEZERO_END
        || tm.is_null()
        || tm.addr() < crate::stdio::PAGEZERO_END
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
    // Over-allocate and align within the bump block (never free-aligned precisely).
    let need = size.saturating_add(alignment);
    let raw = unsafe { malloc(need) };
    if raw.is_null() {
        return ENOMEM;
    }
    let addr = raw.addr();
    let align_mask = alignment.saturating_sub(1);
    let aligned = addr.saturating_add(align_mask) & !align_mask;
    unsafe {
        memptr.write(core::ptr::with_exposed_provenance_mut::<c_void>(aligned));
    }
    0
}
