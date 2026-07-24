//! Host OS primitives: the **only** crate-level home for most libc I/O and
//! memory syscalls used by the translator.
//!
//! Call sites should prefer these wrappers so `unsafe` does not scatter across
//! BSD handlers. Each function documents the ownership / validity contract.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::RawFd;
use std::ptr;

/// Linux `MAP_FIXED_NOREPLACE` (do not clobber existing maps).
#[cfg(target_os = "linux")]
pub const MAP_FIXED_NOREPLACE: libc::c_int = 0x100_000;

/// Preferred fixed-map flag for this host.
#[must_use]
pub fn fixed_map_flag() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        MAP_FIXED_NOREPLACE
    }
    #[cfg(not(target_os = "linux"))]
    {
        libc::MAP_FIXED
    }
}

/// Host page size in bytes, or `None` if `sysconf` fails.
#[must_use]
pub fn page_size() -> Option<usize> {
    // SAFETY: `sysconf(_SC_PAGESIZE)` returns a scalar; no memory is touched.
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if raw <= 0 {
        return None;
    }
    usize::try_from(raw).ok()
}

/// Physical page count from `sysconf(_SC_PHYS_PAGES)`, when available.
#[must_use]
pub fn phys_pages() -> Option<u64> {
    // SAFETY: scalar sysconf; no memory is touched.
    let raw = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    if raw <= 0 {
        return None;
    }
    u64::try_from(raw).ok()
}

/// Best-effort host RAM size in bytes.
#[must_use]
pub fn phys_mem_bytes() -> u64 {
    match (phys_pages(), page_size()) {
        (Some(pages), Some(page)) => {
            let s = u64::try_from(page).unwrap_or(0);
            pages.saturating_mul(s).max(64 * 1024 * 1024)
        }
        _ => 8 * 1024 * 1024 * 1024, // 8 GiB fallback
    }
}

/// Close a host file descriptor. Errors are ignored (best-effort cleanup).
pub fn close_fd(fd: RawFd) {
    // SAFETY: caller owned `fd` and will not use it after this call.
    unsafe {
        let _ = libc::close(fd);
    }
}

/// Duplicate a host fd. Returns the new fd or `None` on failure.
#[must_use]
pub fn dup_fd(fd: RawFd) -> Option<RawFd> {
    // SAFETY: `fd` is a live host descriptor.
    let rc = unsafe { libc::dup(fd) };
    if rc < 0 { None } else { Some(rc) }
}

/// `lseek` on a host fd.
pub fn lseek_fd(fd: RawFd, offset: i64, whence: libc::c_int) -> Option<i64> {
    // SAFETY: live fd; whence is a SEEK_* constant.
    let rc = unsafe { libc::lseek(fd, offset, whence) };
    if rc < 0 { None } else { Some(rc) }
}

/// `fcntl` with no extra arg (`F_GETFD` / `F_GETFL`).
pub fn fcntl_get(fd: RawFd, cmd: libc::c_int) -> Option<i32> {
    // SAFETY: live fd; cmd is a valid fcntl command.
    let rc = unsafe { libc::fcntl(fd, cmd) };
    if rc < 0 { None } else { Some(rc) }
}

/// `fcntl` with one integer arg (`F_SETFD` / `F_SETFL` / `F_DUPFD`).
pub fn fcntl_set(fd: RawFd, cmd: libc::c_int, arg: libc::c_int) -> Option<i32> {
    // SAFETY: live fd; cmd/arg match the fcntl ABI.
    let rc = unsafe { libc::fcntl(fd, cmd, arg) };
    if rc < 0 { None } else { Some(rc) }
}

/// `openat(dirfd, path, flags, mode)`.
pub fn openat(
    dirfd: RawFd,
    path: &std::ffi::CStr,
    flags: libc::c_int,
    mode: libc::c_uint,
) -> Option<RawFd> {
    // SAFETY: dirfd live; path is a valid C string for the duration of the call.
    let rc = unsafe { libc::openat(dirfd, path.as_ptr(), flags, mode) };
    if rc < 0 { None } else { Some(rc) }
}

/// Write bytes to a host fd (`write(2)`).
pub fn write_fd(fd: RawFd, data: &[u8]) -> io::Result<usize> {
    if data.is_empty() {
        return Ok(0);
    }
    // SAFETY: fd live; buffer valid for `data.len()` bytes.
    let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(n).map_err(|_| io::Error::other("write returned out-of-range count"))
}

/// Read bytes from a host fd (`read(2)`).
pub fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    // SAFETY: fd live; buffer valid for `buf.len()` bytes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(n).map_err(|_| io::Error::other("read returned out-of-range count"))
}

/// `fstat` into a host `stat` buffer.
pub fn fstat_fd(fd: RawFd) -> Option<libc::stat> {
    // SAFETY: live fd; stack buffer is valid for the duration of the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, std::ptr::addr_of_mut!(st)) };
    if rc == 0 { Some(st) } else { None }
}

/// Host `gettimeofday` (timezone ignored).
pub fn gettimeofday() -> Option<libc::timeval> {
    // SAFETY: stack timeval; null tz pointer is allowed.
    let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::gettimeofday(std::ptr::addr_of_mut!(tv), ptr::null_mut()) };
    if rc == 0 { Some(tv) } else { None }
}

/// Host `clock_gettime`.
pub fn clock_gettime(clock_id: libc::clockid_t) -> Option<libc::timespec> {
    // SAFETY: stack timespec; clock_id is a host constant.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(clock_id, std::ptr::addr_of_mut!(ts)) };
    if rc == 0 { Some(ts) } else { None }
}

/// Anonymous or file-backed `mmap`. Returns host base or `None` on failure.
///
/// When `fixed_addr` is `Some(va)`, the call uses that as the address hint
/// (combine with [`fixed_map_flag`] / `MAP_FIXED` as appropriate).
#[must_use]
pub fn mmap(
    fixed_addr: Option<u64>,
    len: usize,
    prot: libc::c_int,
    flags: libc::c_int,
    fd: RawFd,
    offset: i64,
) -> Option<*mut u8> {
    if len == 0 {
        return None;
    }
    let addr = fixed_addr.map_or(ptr::null_mut(), u64_as_void_ptr);
    // SAFETY: length non-zero; flags/prot valid combinations; fd matches flags;
    // `addr` is either null or a page-aligned VA for fixed placement.
    let raw = unsafe { libc::mmap(addr, len, prot, flags, fd, offset) };
    if raw == libc::MAP_FAILED {
        None
    } else {
        Some(raw.cast())
    }
}

/// `munmap` a mapping previously returned by [`mmap`].
pub fn munmap(ptr: *mut u8, len: usize) -> bool {
    if ptr.is_null() || len == 0 {
        return true;
    }
    // SAFETY: ptr/len came from a successful mmap owned by the caller.
    let rc = unsafe { libc::munmap(ptr.cast(), len) };
    rc == 0
}

/// `mprotect` on a host mapping range.
pub fn mprotect(ptr: *mut u8, len: usize, prot: libc::c_int) -> bool {
    if ptr.is_null() || len == 0 {
        return true;
    }
    // SAFETY: range is a live mapping owned by the caller.
    let rc = unsafe { libc::mprotect(ptr.cast(), len, prot) };
    rc == 0
}

/// `msync` on a host mapping range.
pub fn msync(ptr: *mut u8, len: usize, flags: libc::c_int) -> bool {
    if ptr.is_null() || len == 0 {
        return true;
    }
    // SAFETY: range is a live mapping; flags are MS_* bits.
    let rc = unsafe { libc::msync(ptr.cast(), len, flags) };
    rc == 0
}

/// Pointer address as `u64` (identity guest/host model helpers).
#[must_use]
pub fn ptr_addr_u64(p: *mut u8) -> u64 {
    u64::try_from(p.addr()).unwrap_or(0)
}

/// `u64` address → void pointer (fixed mmap hints).
#[must_use]
pub fn u64_as_void_ptr(addr: u64) -> *mut libc::c_void {
    let u = usize::try_from(addr).unwrap_or(0);
    ptr::with_exposed_provenance_mut::<u8>(u).cast()
}
