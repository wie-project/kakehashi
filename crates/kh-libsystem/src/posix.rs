//! POSIX / BSD file and process surface (syscalls + soft stubs).

use core::ffi::{c_char, c_int, c_void};

use crate::errno;
use crate::heap::{free, malloc};
use crate::sys::{
    self, SYS_CLOSE, SYS_FSTAT64, SYS_FSTATAT, SYS_FSYNC, SYS_FTRUNCATE, SYS_GETPID, SYS_GETPPID,
    SYS_GETTIMEOFDAY, SYS_LSEEK, SYS_LSTAT64, SYS_MKDIR, SYS_OPEN, SYS_OPENAT, SYS_READ, SYS_RENAME,
    SYS_RMDIR, SYS_STAT64, SYS_SYSCTL, SYS_SYSCTLBYNAME, SYS_UNLINK,
};
use crate::trace;

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

#[inline]
fn ret_i64(ret: isize) -> i64 {
    let r = apply_ret(ret);
    i64::try_from(r).unwrap_or(-1)
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
    trace::note(b"[kh-libsystem] open()\n");
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
    apply_ret(ret)
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

/// C `chdir` → nlist `_chdir`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn chdir(_path: *const c_char) -> c_int {
    not_impl(b"[kh-libsystem] chdir ENOSYS\n")
}

/// C `getcwd` → nlist `_getcwd` (returns bottle-ish "/").
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getcwd(buf: *mut c_char, size: usize) -> *mut c_char {
    if buf.is_null() || size == 0 {
        errno::set_errno(22);
        return core::ptr::null_mut();
    }
    if size < 2 {
        errno::set_errno(34); // ERANGE
        return core::ptr::null_mut();
    }
    unsafe {
        buf.write(b'/'.cast_signed());
        buf.add(1).write(0);
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

/// C `link` → nlist `_link`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn link(_path1: *const c_char, _path2: *const c_char) -> c_int {
    not_impl(b"[kh-libsystem] link ENOSYS\n")
}

/// C `symlink` → nlist `_symlink`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn symlink(_path1: *const c_char, _path2: *const c_char) -> c_int {
    not_impl(b"[kh-libsystem] symlink ENOSYS\n")
}

/// C `readlink` → nlist `_readlink`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn readlink(
    _path: *const c_char,
    _buf: *mut c_char,
    _bufsize: usize,
) -> isize {
    let _ = not_impl(b"[kh-libsystem] readlink ENOSYS\n");
    -1
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

// ── dirent ──────────────────────────────────────────────────────────────────
//
// Minimal directory stream: open the path as a directory FD. `readdir` is still
// empty (no getdirentries yet) so recursive tree walks see zero children, but
// single-file archive paths never need readdir — and we no longer hard-fail
// `opendir` with ENOSYS (which some guests treat as fatal).

const DIR_MAGIC: u32 = 0x4B48_4449; // "KHDI"

#[repr(C)]
struct DirStub {
    magic: u32,
    fd: c_int,
    exhausted: c_int,
    /// Darwin `struct dirent` is large; we only need a stable address for soft readdir.
    ent: [u8; 1048],
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
        (*d).exhausted = 0;
        crate::stdio::bzero((*d).ent.as_mut_ptr().cast(), (*d).ent.len());
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
///
/// Soft empty directory: always returns NULL (end of stream). Enough for
/// guests that only open dirs defensively; real listing needs getdirentries.
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
    // End of directory (empty listing).
    core::ptr::null_mut()
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
        6 => 1,          // _SC_JOB_CONTROL
        7 => 1,          // _SC_SAVED_IDS
        8 => 200_809,    // _SC_VERSION
        29 => 16_384,    // _SC_PAGE_SIZE (Darwin arm64 default guest page)
        58 | 84 => 1,    // _SC_NPROCESSORS_ONLN / CONF (soft single-core)
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

/// C `setlocale` → nlist `_setlocale` (always "C").
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setlocale(_category: c_int, _locale: *const c_char) -> *mut c_char {
    static mut C_LOCALE: [u8; 2] = *b"C\0";
    core::ptr::addr_of_mut!(C_LOCALE).cast()
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

unsafe fn fill_tm(clock: *const i64) -> *mut Tm {
    let t = if clock.is_null() {
        0
    } else {
        unsafe { clock.read() }
    };
    // Very rough breakdown (enough for bind + trivial callers).
    let days = t.div_euclid(86_400);
    let sod = t.rem_euclid(86_400);
    unsafe {
        TM_BUF.sec = trunc_i64_to_c_int(sod.rem_euclid(60));
        TM_BUF.min = trunc_i64_to_c_int(sod.div_euclid(60).rem_euclid(60));
        TM_BUF.hour = trunc_i64_to_c_int(sod.div_euclid(3_600));
        TM_BUF.mday = trunc_i64_to_c_int(days.rem_euclid(28).saturating_add(1));
        TM_BUF.mon = 0;
        TM_BUF.year = trunc_i64_to_c_int(70_i64.saturating_add(days.div_euclid(365)));
        TM_BUF.wday = trunc_i64_to_c_int(days.saturating_add(4).rem_euclid(7));
        TM_BUF.yday = trunc_i64_to_c_int(days.rem_euclid(365));
        TM_BUF.isdst = 0;
        TM_BUF.gmtoff = 0;
        TM_BUF.zone = core::ptr::addr_of!(ZONE).cast();
        core::ptr::addr_of_mut!(TM_BUF)
    }
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
