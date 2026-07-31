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

fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn socklen_of(len: usize) -> Option<libc::socklen_t> {
    libc::socklen_t::try_from(len).ok()
}

/// `pipe(2)` — returns `(read_fd, write_fd)` or `None` on failure.
///
/// Both ends are set `O_NONBLOCK|O_CLOEXEC`. Darwin guests (curl/c-ares) often
/// assume they can `poll` then `read` the wakeup pipe; a blocking `read` after
/// `poll` timeout=0 deadlocks the freestanding guest when no peer writes.
#[must_use]
pub fn pipe_fds() -> Option<(RawFd, RawFd)> {
    let mut fds = [0_i32; 2];
    // Prefer pipe2 when available (Linux).
    #[cfg(target_os = "linux")]
    {
        // SAFETY: stack buffer of two ints for the kernel to fill.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if rc != 0 {
            return None;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: stack buffer of two ints for the kernel to fill.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if rc != 0 {
            return None;
        }
        for fd in fds {
            // SAFETY: freshly created pipe ends.
            unsafe {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                if fl >= 0 {
                    let _ = libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
                }
                let _ = libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
    }
    match (fds.first().copied(), fds.get(1).copied()) {
        (Some(r), Some(w)) => Some((r, w)),
        _ => None,
    }
}

/// Mark a host fd non-blocking (best-effort).
fn set_nonblock(fd: RawFd) {
    // SAFETY: live fd from socket/accept/pipe.
    unsafe {
        let fl = libc::fcntl(fd, libc::F_GETFL);
        if fl >= 0 {
            let _ = libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
}

/// `socket(domain, type, protocol)` — host libc. Returns host fd or `None`.
///
/// Sockets are forced `O_NONBLOCK`. Curl/c-ares (and the multi interface)
/// expect non-blocking I/O; a blocking `recv` on a keep-alive TCP socket after
/// the response body is complete hangs the guest forever (clean-exit G3).
#[must_use]
pub fn socket(domain: libc::c_int, ty: libc::c_int, protocol: libc::c_int) -> Option<RawFd> {
    // SAFETY: standard socket(2). Strip Darwin-only type flags if any sneak in;
    // Linux SOCK_NONBLOCK/CLOEXEC bits differ and are applied via fcntl below.
    let ty_plain = ty & 0xf;
    let rc = unsafe { libc::socket(domain, ty_plain, protocol) };
    if rc < 0 {
        return None;
    }
    set_nonblock(rc);
    // SAFETY: freshly created socket.
    unsafe {
        let _ = libc::fcntl(rc, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Some(rc)
}

/// `connect(fd, sockaddr_bytes)`.
pub fn connect(fd: RawFd, addr: &[u8]) -> Result<(), i32> {
    let Some(len) = socklen_of(addr.len()) else {
        return Err(libc::EINVAL);
    };
    // SAFETY: `addr` is a valid host buffer for `len` bytes.
    let rc = unsafe { libc::connect(fd, addr.as_ptr().cast(), len) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

/// `bind(fd, sockaddr_bytes)`.
pub fn bind(fd: RawFd, addr: &[u8]) -> Result<(), i32> {
    let Some(len) = socklen_of(addr.len()) else {
        return Err(libc::EINVAL);
    };
    // SAFETY: `addr` is a valid host buffer for `len` bytes.
    let rc = unsafe { libc::bind(fd, addr.as_ptr().cast(), len) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

/// `listen(fd, backlog)`.
pub fn listen(fd: RawFd, backlog: libc::c_int) -> Result<(), i32> {
    // SAFETY: live socket fd.
    let rc = unsafe { libc::listen(fd, backlog) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

/// `accept(fd)` — peer address discarded (curl client path rarely needs it).
pub fn accept(fd: RawFd) -> Result<RawFd, i32> {
    // SAFETY: live listening socket; null addr is allowed by accept(2).
    let rc = unsafe { libc::accept(fd, ptr::null_mut(), ptr::null_mut()) };
    if rc < 0 {
        Err(last_errno())
    } else {
        set_nonblock(rc);
        Ok(rc)
    }
}

/// `accept` with peer sockaddr written into `addr_out` (truncated to buffer len).
///
/// Returns `(new_fd, bytes_written_into_addr_out)`.
pub fn accept_addr(fd: RawFd, addr_out: &mut [u8]) -> Result<(RawFd, usize), i32> {
    let mut alen = socklen_of(addr_out.len()).unwrap_or(0);
    // SAFETY: live socket; `addr_out` is writable for `alen` bytes.
    let rc = unsafe {
        libc::accept(
            fd,
            addr_out.as_mut_ptr().cast(),
            ptr::addr_of_mut!(alen),
        )
    };
    if rc < 0 {
        return Err(last_errno());
    }
    set_nonblock(rc);
    let n = usize::try_from(alen).unwrap_or(0).min(addr_out.len());
    Ok((rc, n))
}

/// `setsockopt(fd, level, optname, value_bytes)`.
pub fn setsockopt(
    fd: RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    value: &[u8],
) -> Result<(), i32> {
    let Some(len) = socklen_of(value.len()) else {
        return Err(libc::EINVAL);
    };
    // SAFETY: live socket; value buffer valid for `len` bytes.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            value.as_ptr().cast(),
            len,
        )
    };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

/// `getsockopt` — writes into `value`, returns updated length.
pub fn getsockopt(
    fd: RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    value: &mut [u8],
) -> Result<usize, i32> {
    let mut len = socklen_of(value.len()).unwrap_or(0);
    // SAFETY: live socket; value buffer writable.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            value.as_mut_ptr().cast(),
            ptr::addr_of_mut!(len),
        )
    };
    if rc == 0 {
        Ok(usize::try_from(len).unwrap_or(0).min(value.len()))
    } else {
        Err(last_errno())
    }
}

/// `shutdown(fd, how)`.
pub fn shutdown(fd: RawFd, how: libc::c_int) -> Result<(), i32> {
    // SAFETY: live socket fd.
    let rc = unsafe { libc::shutdown(fd, how) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

/// `sendto` / `send` — optional peer address bytes.
pub fn sendto(
    fd: RawFd,
    buf: &[u8],
    flags: libc::c_int,
    addr: Option<&[u8]>,
) -> Result<usize, i32> {
    let (ap, alen) = if let Some(a) = addr {
        let Some(len) = socklen_of(a.len()) else {
            return Err(libc::EINVAL);
        };
        (a.as_ptr().cast(), len)
    } else {
        (ptr::null(), 0)
    };
    // SAFETY: live fd; buffer valid; optional sockaddr.
    let n = unsafe { libc::sendto(fd, buf.as_ptr().cast(), buf.len(), flags, ap, alen) };
    if n < 0 {
        Err(last_errno())
    } else {
        usize::try_from(n).map_err(|_| libc::EIO)
    }
}

/// `recvfrom` / `recv` — optional peer address out-buffer.
///
/// Returns `(bytes_read, peer_addr_len)` when `addr_out` is `Some`.
pub fn recvfrom(
    fd: RawFd,
    buf: &mut [u8],
    flags: libc::c_int,
    addr_out: Option<&mut [u8]>,
) -> Result<(usize, usize), i32> {
    let (n, peer_len) = if let Some(a) = addr_out {
        let mut alen = socklen_of(a.len()).unwrap_or(0);
        // SAFETY: live fd; buffers valid.
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                flags,
                a.as_mut_ptr().cast(),
                ptr::addr_of_mut!(alen),
            )
        };
        (n, usize::try_from(alen).unwrap_or(0).min(a.len()))
    } else {
        // SAFETY: live fd; buffer valid; null peer.
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                flags,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        (n, 0)
    };
    if n < 0 {
        Err(last_errno())
    } else {
        let nr = usize::try_from(n).map_err(|_| libc::EIO)?;
        Ok((nr, peer_len))
    }
}

/// `getsockname(fd, addr_out)`.
pub fn getsockname(fd: RawFd, addr_out: &mut [u8]) -> Result<usize, i32> {
    let mut alen = socklen_of(addr_out.len()).unwrap_or(0);
    // SAFETY: live socket; buffer writable for `alen` bytes.
    let rc = unsafe {
        libc::getsockname(fd, addr_out.as_mut_ptr().cast(), ptr::addr_of_mut!(alen))
    };
    if rc == 0 {
        Ok(usize::try_from(alen).unwrap_or(0).min(addr_out.len()))
    } else {
        Err(last_errno())
    }
}

/// `getpeername(fd, addr_out)`.
pub fn getpeername(fd: RawFd, addr_out: &mut [u8]) -> Result<usize, i32> {
    let mut alen = socklen_of(addr_out.len()).unwrap_or(0);
    // SAFETY: live socket; buffer writable for `alen` bytes.
    let rc = unsafe {
        libc::getpeername(fd, addr_out.as_mut_ptr().cast(), ptr::addr_of_mut!(alen))
    };
    if rc == 0 {
        Ok(usize::try_from(alen).unwrap_or(0).min(addr_out.len()))
    } else {
        Err(last_errno())
    }
}

/// `poll(fds, timeout_ms)` — empty slice sleeps / checks timeout only.
pub fn poll(fds: &mut [libc::pollfd], timeout: libc::c_int) -> Result<i32, i32> {
    let nfds = libc::nfds_t::try_from(fds.len()).unwrap_or(0);
    // SAFETY: `fds` is a valid pollfd array of `nfds` entries (or empty).
    let rc = unsafe {
        libc::poll(
            if fds.is_empty() {
                ptr::null_mut()
            } else {
                fds.as_mut_ptr()
            },
            nfds,
            timeout,
        )
    };
    if rc < 0 { Err(last_errno()) } else { Ok(rc) }
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

/// `open(path, flags, mode)` — prefers libc over `std::fs::OpenOptions` so
/// directories open with `O_RDONLY` (archive walks) and we avoid extra syscalls.
pub fn open_path(path: &std::ffi::CStr, flags: libc::c_int, mode: libc::c_uint) -> Option<RawFd> {
    // SAFETY: path is a valid C string for the duration of the call.
    let rc = unsafe { libc::open(path.as_ptr(), flags, mode) };
    if rc < 0 { None } else { Some(rc) }
}

/// Open a directory as `O_RDONLY|O_DIRECTORY|O_CLOEXEC` (bottle root dirfd, B1).
pub fn open_directory(path: &std::ffi::CStr) -> Option<RawFd> {
    open_path(
        path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
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

/// `mkdirat(dirfd, path, mode)` — returns `Ok(())` on success or `EEXIST`.
pub fn mkdirat(dirfd: RawFd, path: &std::ffi::CStr, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: dirfd live; path is a valid C string for the duration of the call.
    let rc = unsafe { libc::mkdirat(dirfd, path.as_ptr(), mode) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(err)
    }
}

/// `fstatat(dirfd, path, …)` — used by B1 bottle-relative `stat`/`lstat`.
pub fn fstatat(dirfd: RawFd, path: &std::ffi::CStr, no_follow: bool) -> Option<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let flags = if no_follow {
        libc::AT_SYMLINK_NOFOLLOW
    } else {
        0
    };
    // SAFETY: dirfd live; path valid C string; stack `stat` buffer.
    let rc = unsafe { libc::fstatat(dirfd, path.as_ptr(), std::ptr::addr_of_mut!(st), flags) };
    if rc == 0 { Some(st) } else { None }
}

/// `faccessat(dirfd, path, F_OK, 0)` — existence check without full path build.
pub fn faccessat_ok(dirfd: RawFd, path: &std::ffi::CStr) -> bool {
    // SAFETY: dirfd live; path valid C string.
    let rc = unsafe { libc::faccessat(dirfd, path.as_ptr(), libc::F_OK, 0) };
    rc == 0
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

/// `ftruncate(fd, length)`.
pub fn ftruncate_fd(fd: RawFd, length: i64) -> Option<()> {
    // SAFETY: live fd.
    let rc = unsafe { libc::ftruncate(fd, length) };
    if rc == 0 { Some(()) } else { None }
}

/// `fsync(fd)`.
pub fn fsync_fd(fd: RawFd) -> Option<()> {
    // SAFETY: live fd.
    let rc = unsafe { libc::fsync(fd) };
    if rc == 0 { Some(()) } else { None }
}

/// `readlink(path)` into `buf` (no trailing NUL). Returns bytes written or host errno.
pub fn readlink_path(path: &std::ffi::CStr, buf: &mut [u8]) -> Result<usize, i32> {
    if buf.is_empty() {
        return Ok(0);
    }
    // SAFETY: path is a valid C string; buffer is writable for `buf.len()`.
    let n = unsafe { libc::readlink(path.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    usize::try_from(n).map_err(|_| libc::EIO)
}

/// `symlink(target, linkpath)`.
pub fn symlink_path(target: &std::ffi::CStr, linkpath: &std::ffi::CStr) -> Result<(), i32> {
    // SAFETY: both are valid C strings for the duration of the call.
    let rc = unsafe { libc::symlink(target.as_ptr(), linkpath.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    }
}

/// `link(existing, newpath)` hard link.
pub fn link_path(existing: &std::ffi::CStr, newpath: &std::ffi::CStr) -> Result<(), i32> {
    // SAFETY: both are valid C strings for the duration of the call.
    let rc = unsafe { libc::link(existing.as_ptr(), newpath.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    }
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

// ── directory streams (for guest readdir) ───────────────────────────────────

/// Opaque host directory stream (`DIR*`).
#[derive(Debug)]
pub struct HostDir {
    ptr: *mut libc::DIR,
}

// SAFETY: process-wide guest model serializes dir mutation under ProcessState
// write lock; readers never touch `HostDir`.
unsafe impl Send for HostDir {}
// SAFETY: same as `Send` — exclusive dir use under write lock only.
unsafe impl Sync for HostDir {}

impl HostDir {
    /// Open a directory stream on a **duplicate** of `host_fd` (does not own `host_fd`).
    pub fn open_dup(host_fd: RawFd) -> Result<Self, i32> {
        // SAFETY: dup of a live host FD.
        let dup = unsafe { libc::dup(host_fd) };
        if dup < 0 {
            return Err(last_errno_i32());
        }
        // SAFETY: fdopendir takes ownership of `dup`.
        let dir = unsafe { libc::fdopendir(dup) };
        if dir.is_null() {
            let err = last_errno_i32();
            // SAFETY: close the unused dup on failure.
            unsafe {
                libc::close(dup);
            }
            return Err(err);
        }
        Ok(Self { ptr: dir })
    }

    /// Next entry: `(name_bytes, d_type)`. `None` at end of stream.
    pub fn read_next(&mut self) -> Option<(Vec<u8>, u8)> {
        use std::ffi::CStr;
        loop {
            // SAFETY: `ptr` from fdopendir; readdir is the iterator.
            let ent = unsafe { libc::readdir(self.ptr) };
            if ent.is_null() {
                return None;
            }
            // SAFETY: ent valid until next readdir/closedir.
            let d_type = unsafe { (*ent).d_type };
            let name_ptr = unsafe { (*ent).d_name.as_ptr() };
            let name = unsafe { CStr::from_ptr(name_ptr) };
            let bytes = name.to_bytes().to_vec();
            if bytes.is_empty() {
                continue;
            }
            return Some((bytes, d_type));
        }
    }
}

impl Drop for HostDir {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: owns DIR* from fdopendir.
            unsafe {
                let _ = libc::closedir(self.ptr);
            }
            self.ptr = ptr::null_mut();
        }
    }
}

fn last_errno_i32() -> i32 {
    let raw = io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(1)
        .unsigned_abs();
    i32::try_from(raw).unwrap_or(1)
}
