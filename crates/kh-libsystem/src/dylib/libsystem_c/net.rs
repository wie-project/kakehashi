//! Socket / DNS surface for curl G3 (trace-first).

use core::ffi::{c_char, c_int, c_void};

use crate::kh_core::errno;
use crate::kh_core::heap::{free, malloc};
use crate::kh_core::sys::{
    self, SYS_ACCEPT, SYS_BIND, SYS_CONNECT, SYS_GETPEERNAME, SYS_GETSOCKNAME, SYS_GETSOCKOPT,
    SYS_LISTEN, SYS_PIPE, SYS_POLL, SYS_RECVFROM, SYS_RECVMSG, SYS_SELECT, SYS_SENDMSG, SYS_SENDTO,
    SYS_SETSOCKOPT, SYS_SHUTDOWN, SYS_SOCKET, SYS_SOCKETPAIR,
};
use crate::kh_core::helpers::KH_HELPER_GETADDRINFO;

const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ENOMEM: i32 = 12;
const EAI_FAIL: i32 = 4;
const EAI_MEMORY: i32 = 6;
const EAI_NONAME: i32 = 8;

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

#[inline]
fn ret_c_int(ret: isize) -> c_int {
    let r = apply_ret(ret);
    if r < 0 {
        -1
    } else {
        c_int::try_from(r).unwrap_or(c_int::MAX)
    }
}

/// POSIX `ssize_t`: success length, error always `-1` + errno (not `-errno`).
#[inline]
fn ret_ssize(ret: isize) -> isize {
    let r = apply_ret(ret);
    if r < 0 {
        -1
    } else {
        r
    }
}


/// Soft PRNG state for `arc4random*` (not crypto-grade; curl init + clang temps).
static mut ARC4_STATE: u64 = 0x4B48_4152_4334_0001;

#[inline]
fn arc4_next_u32() -> u32 {
    // SAFETY: freestanding; races only scramble the stream.
    let mut state = unsafe { core::ptr::addr_of_mut!(ARC4_STATE).read_volatile() };
    if state == 0 {
        state = 0x4B48_4152_4334_0001;
    }
    // xorshift64*
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    unsafe {
        core::ptr::addr_of_mut!(ARC4_STATE).write_volatile(state);
    }
    u32::try_from(state >> 32).unwrap_or_else(|_| u32::try_from(state & 0xffff_ffff).unwrap_or(0))
}

/// C `arc4random` → nlist `_arc4random` (Apple clang temp names).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn arc4random() -> u32 {
    arc4_next_u32()
}

/// C `arc4random_uniform` → nlist `_arc4random_uniform`.
#[unsafe(no_mangle)]
#[allow(clippy::arithmetic_side_effects)] // modular range reduction
pub(crate) unsafe extern "C" fn arc4random_uniform(upper_bound: u32) -> u32 {
    if upper_bound <= 1 {
        return 0;
    }
    let min = upper_bound.wrapping_neg() % upper_bound;
    loop {
        let r = arc4_next_u32();
        if r >= min {
            return r % upper_bound;
        }
    }
}

/// C `arc4random_buf`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn arc4random_buf(buf: *mut c_void, nbytes: usize) {
    if buf.is_null() || nbytes == 0 {
        return;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), nbytes) };
    for b in out.iter_mut() {
        *b = u8::try_from(arc4_next_u32() & 0xff).unwrap_or(0);
    }
}

/// C `gethostname` → `"kakehashi"`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn gethostname(name: *mut c_char, len: usize) -> c_int {
    if name.is_null() || len == 0 {
        errno::set_errno(EFAULT);
        return -1;
    }
    let host = b"kakehashi\0";
    let n = host.len().min(len);
    unsafe {
        core::ptr::copy_nonoverlapping(host.as_ptr(), name.cast::<u8>(), n);
        // ensure NUL if truncated
        *name.add(n.saturating_sub(1)) = 0;
    }
    0
}

/// C `pipe` → nlist `_pipe` (first G3 missing call).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn pipe(fildes: *mut c_int) -> c_int {
    if fildes.is_null() {
        errno::set_errno(EFAULT);
        return -1;
    }
    let ret = unsafe { sys::syscall1(SYS_PIPE, ptr_u64(fildes.cast())) };
    ret_c_int(ret)
}

/// C `socket`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    let ret = unsafe {
        sys::syscall3(
            SYS_SOCKET,
            u64::from(domain.cast_unsigned()),
            u64::from(ty.cast_unsigned()),
            u64::from(protocol.cast_unsigned()),
        )
    };
    ret_c_int(ret)
}

/// C `socketpair`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn socketpair(
    domain: c_int,
    ty: c_int,
    protocol: c_int,
    sv: *mut c_int,
) -> c_int {
    if sv.is_null() {
        errno::set_errno(EFAULT);
        return -1;
    }
    let ret = unsafe {
        sys::syscall6(
            SYS_SOCKETPAIR,
            u64::from(domain.cast_unsigned()),
            u64::from(ty.cast_unsigned()),
            u64::from(protocol.cast_unsigned()),
            ptr_u64(sv.cast()),
            0,
            0,
        )
    };
    ret_c_int(ret)
}

/// C `connect`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn connect(sockfd: c_int, addr: *const c_void, addrlen: u32) -> c_int {
    if addr.is_null() {
        errno::set_errno(EFAULT);
        return -1;
    }
    let ret = unsafe {
        sys::syscall3(
            SYS_CONNECT,
            u64::from(sockfd.cast_unsigned()),
            ptr_u64(addr),
            u64::from(addrlen),
        )
    };
    ret_c_int(ret)
}

/// C `bind`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn bind(sockfd: c_int, addr: *const c_void, addrlen: u32) -> c_int {
    if addr.is_null() {
        errno::set_errno(EFAULT);
        return -1;
    }
    let ret = unsafe {
        sys::syscall3(
            SYS_BIND,
            u64::from(sockfd.cast_unsigned()),
            ptr_u64(addr),
            u64::from(addrlen),
        )
    };
    ret_c_int(ret)
}

/// C `listen`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn listen(sockfd: c_int, backlog: c_int) -> c_int {
    let ret = unsafe {
        sys::syscall2(
            SYS_LISTEN,
            u64::from(sockfd.cast_unsigned()),
            u64::from(backlog.cast_unsigned()),
        )
    };
    ret_c_int(ret)
}

/// C `accept`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn accept(
    sockfd: c_int,
    addr: *mut c_void,
    addrlen: *mut u32,
) -> c_int {
    let ret = unsafe {
        sys::syscall3(
            SYS_ACCEPT,
            u64::from(sockfd.cast_unsigned()),
            ptr_u64(addr),
            ptr_u64(addrlen.cast()),
        )
    };
    ret_c_int(ret)
}

/// C `setsockopt`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn setsockopt(
    sockfd: c_int,
    level: c_int,
    optname: c_int,
    optval: *const c_void,
    optlen: u32,
) -> c_int {
    let ret = unsafe {
        sys::syscall6(
            SYS_SETSOCKOPT,
            u64::from(sockfd.cast_unsigned()),
            u64::from(level.cast_unsigned()),
            u64::from(optname.cast_unsigned()),
            ptr_u64(optval),
            u64::from(optlen),
            0,
        )
    };
    ret_c_int(ret)
}

/// C `getsockopt`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getsockopt(
    sockfd: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut u32,
) -> c_int {
    let ret = unsafe {
        sys::syscall6(
            SYS_GETSOCKOPT,
            u64::from(sockfd.cast_unsigned()),
            u64::from(level.cast_unsigned()),
            u64::from(optname.cast_unsigned()),
            ptr_u64(optval),
            ptr_u64(optlen.cast()),
            0,
        )
    };
    ret_c_int(ret)
}

/// C `shutdown`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn shutdown(sockfd: c_int, how: c_int) -> c_int {
    let ret = unsafe {
        sys::syscall2(
            SYS_SHUTDOWN,
            u64::from(sockfd.cast_unsigned()),
            u64::from(how.cast_unsigned()),
        )
    };
    ret_c_int(ret)
}

/// C `getsockname`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getsockname(
    sockfd: c_int,
    addr: *mut c_void,
    addrlen: *mut u32,
) -> c_int {
    let ret = unsafe {
        sys::syscall3(
            SYS_GETSOCKNAME,
            u64::from(sockfd.cast_unsigned()),
            ptr_u64(addr),
            ptr_u64(addrlen.cast()),
        )
    };
    ret_c_int(ret)
}

/// C `getpeername`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getpeername(
    sockfd: c_int,
    addr: *mut c_void,
    addrlen: *mut u32,
) -> c_int {
    let ret = unsafe {
        sys::syscall3(
            SYS_GETPEERNAME,
            u64::from(sockfd.cast_unsigned()),
            ptr_u64(addr),
            ptr_u64(addrlen.cast()),
        )
    };
    ret_c_int(ret)
}

/// C `sendto`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sendto(
    sockfd: c_int,
    buf: *const c_void,
    len: usize,
    flags: c_int,
    dest: *const c_void,
    addrlen: u32,
) -> isize {
    if buf.is_null() && len > 0 {
        errno::set_errno(EFAULT);
        return -1;
    }
    let ret = unsafe {
        sys::syscall6(
            SYS_SENDTO,
            u64::from(sockfd.cast_unsigned()),
            ptr_u64(buf),
            u64::try_from(len).unwrap_or(0),
            u64::from(flags.cast_unsigned()),
            ptr_u64(dest),
            u64::from(addrlen),
        )
    };
    ret_ssize(ret)
}

/// C `send`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn send(
    sockfd: c_int,
    buf: *const c_void,
    len: usize,
    flags: c_int,
) -> isize {
    unsafe { sendto(sockfd, buf, len, flags, core::ptr::null(), 0) }
}

/// C `sendmsg` → nlist `_sendmsg` (HTTP/3 / UDP paths).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn sendmsg(
    sockfd: c_int,
    msg: *const c_void,
    flags: c_int,
) -> isize {
    if msg.is_null() {
        errno::set_errno(EFAULT);
        return -1;
    }
    let ret = unsafe {
        sys::syscall3(
            SYS_SENDMSG,
            u64::from(sockfd.cast_unsigned()),
            ptr_u64(msg),
            u64::from(flags.cast_unsigned()),
        )
    };
    ret_ssize(ret)
}

/// C `recvmsg` → nlist `_recvmsg`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn recvmsg(sockfd: c_int, msg: *mut c_void, flags: c_int) -> isize {
    if msg.is_null() {
        errno::set_errno(EFAULT);
        return -1;
    }
    let ret = unsafe {
        sys::syscall3(
            SYS_RECVMSG,
            u64::from(sockfd.cast_unsigned()),
            ptr_u64(msg),
            u64::from(flags.cast_unsigned()),
        )
    };
    ret_ssize(ret)
}

/// Darwin `connectx` → fall back to `connect` on the destination endpoint.
///
/// Used by TCP Fast Open / multipath paths; enough for curl `--tcp-fastopen`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn connectx(
    socket: c_int,
    endpoints: *const c_void,
    _associd: u32,
    _flags: u32,
    _iov: *const c_void,
    _iovcnt: u32,
    len: *mut usize,
    _connid: *mut u32,
) -> c_int {
    if endpoints.is_null() {
        errno::set_errno(EINVAL);
        return -1;
    }
    // Darwin sa_endpoints_t (arm64 LP64):
    //   u32 sae_srcif; pad; sockaddr* sae_srcaddr; u32 sae_srcaddrlen; pad;
    //   sockaddr* sae_dstaddr; u32 sae_dstaddrlen; pad;
    // Offsets: dstaddr @ 24, dstlen @ 32.
    let base = endpoints.cast::<u8>();
    // SAFETY: guest endpoints buffer; read unaligned pointer + length.
    let dst = unsafe {
        let mut raw = [0_u8; 8];
        core::ptr::copy_nonoverlapping(base.add(24), raw.as_mut_ptr(), 8);
        let addr = usize::from_le_bytes(raw);
        core::ptr::with_exposed_provenance::<c_void>(addr)
    };
    let dstlen = unsafe {
        let mut raw = [0_u8; 4];
        core::ptr::copy_nonoverlapping(base.add(32), raw.as_mut_ptr(), 4);
        u32::from_le_bytes(raw)
    };
    if dst.is_null() || dstlen == 0 {
        errno::set_errno(EINVAL);
        return -1;
    }
    let rc = unsafe { connect(socket, dst, dstlen) };
    if rc == 0 && !len.is_null() {
        unsafe {
            len.write(0);
        }
    }
    rc
}

// getifaddrs: one lo0 node + name + sockaddr_in + netmask.
const IFADDRS_NODE: usize = 56;
const IFADDRS_NAME: &[u8] = b"lo0\0";

/// C `getifaddrs` → nlist `_getifaddrs` (single loopback entry for `--interface`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getifaddrs(ifap: *mut *mut c_void) -> c_int {
    if ifap.is_null() {
        errno::set_errno(EFAULT);
        return -1;
    }
    // sockaddr_in: len=16, family=2, port=0, addr=127.0.0.1
    let mut sin = [0_u8; 16];
    if let Some(s) = sin.get_mut(0) {
        *s = 16;
    }
    if let Some(s) = sin.get_mut(1) {
        *s = 2; // AF_INET
    }
    if let Some(s) = sin.get_mut(4) {
        *s = 127;
    }
    if let Some(s) = sin.get_mut(7) {
        *s = 1;
    }
    let mut mask = [0_u8; 16];
    if let Some(s) = mask.get_mut(0) {
        *s = 16;
    }
    if let Some(s) = mask.get_mut(1) {
        *s = 2;
    }
    if let Some(s) = mask.get_mut(4) {
        *s = 255;
    }
    let total = IFADDRS_NODE
        .saturating_add(IFADDRS_NAME.len())
        .saturating_add(sin.len())
        .saturating_add(mask.len());
    let raw = unsafe { malloc(total) };
    if raw.is_null() {
        errno::set_errno(ENOMEM);
        return -1;
    }
    unsafe {
        crate::dylib::libsystem_c::stdio::bzero(raw, total);
        let base = raw.cast::<u8>();
        let name_off = IFADDRS_NODE;
        let addr_off = name_off.saturating_add(IFADDRS_NAME.len());
        let mask_off = addr_off.saturating_add(sin.len());
        let mut i = 0_usize;
        while i < IFADDRS_NAME.len() {
            if let Some(&b) = IFADDRS_NAME.get(i) {
                base.add(name_off.saturating_add(i)).write(b);
            }
            i = i.saturating_add(1);
        }
        i = 0;
        while i < sin.len() {
            if let Some(&b) = sin.get(i) {
                base.add(addr_off.saturating_add(i)).write(b);
            }
            if let Some(&b) = mask.get(i) {
                base.add(mask_off.saturating_add(i)).write(b);
            }
            i = i.saturating_add(1);
        }
        write_ptr_field(base, 8, base.add(name_off));
        // ifa_flags = IFF_UP|IFF_LOOPBACK|IFF_RUNNING (0x1|0x8|0x40)
        write_u32_field(base, 16, 0x49);
        write_ptr_field(base, 24, base.add(addr_off));
        write_ptr_field(base, 32, base.add(mask_off));
        ifap.write(raw);
    }
    0
}

#[inline]
unsafe fn write_ptr_field(base: *mut u8, off: usize, ptr: *mut u8) {
    let bytes = ptr.addr().to_le_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(off), 8);
    }
}

#[inline]
unsafe fn write_u32_field(base: *mut u8, off: usize, v: u32) {
    let bytes = v.to_le_bytes();
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(off), 4);
    }
}

/// C `freeifaddrs`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn freeifaddrs(ifa: *mut c_void) {
    if !ifa.is_null() {
        unsafe {
            free(ifa);
        }
    }
}

/// C `if_nametoindex` → nlist `_if_nametoindex` (lo0 → 1).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn if_nametoindex(name: *const c_char) -> u32 {
    if name.is_null() {
        return 0;
    }
    // Match "lo0" / "lo"
    unsafe {
        let b0 = name.read().cast_unsigned();
        let b1 = name.add(1).read().cast_unsigned();
        if b0 == b'l' && b1 == b'o' {
            return 1;
        }
    }
    0
}

/// C `if_indextoname` → nlist `_if_indextoname`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn if_indextoname(ifindex: u32, ifname: *mut c_char) -> *mut c_char {
    if ifname.is_null() || ifindex == 0 {
        return core::ptr::null_mut();
    }
    if ifindex == 1 {
        unsafe {
            ifname.write(b'l'.cast_signed());
            ifname.add(1).write(b'o'.cast_signed());
            ifname.add(2).write(b'0'.cast_signed());
            ifname.add(3).write(0);
        }
        return ifname;
    }
    core::ptr::null_mut()
}

/// C `recvfrom`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn recvfrom(
    sockfd: c_int,
    buf: *mut c_void,
    len: usize,
    flags: c_int,
    src: *mut c_void,
    addrlen: *mut u32,
) -> isize {
    if buf.is_null() && len > 0 {
        errno::set_errno(EFAULT);
        return -1;
    }
    let ret = unsafe {
        sys::syscall6(
            SYS_RECVFROM,
            u64::from(sockfd.cast_unsigned()),
            ptr_u64(buf),
            u64::try_from(len).unwrap_or(0),
            u64::from(flags.cast_unsigned()),
            ptr_u64(src),
            ptr_u64(addrlen.cast()),
        )
    };
    ret_ssize(ret)
}

/// C `recv`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn recv(
    sockfd: c_int,
    buf: *mut c_void,
    len: usize,
    flags: c_int,
) -> isize {
    unsafe {
        recvfrom(
            sockfd,
            buf,
            len,
            flags,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }
}

/// C `poll`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn poll(fds: *mut c_void, nfds: u32, timeout: c_int) -> c_int {
    let ret = unsafe {
        sys::syscall3(
            SYS_POLL,
            ptr_u64(fds),
            u64::from(nfds),
            u64::from(timeout.cast_unsigned()),
        )
    };
    ret_c_int(ret)
}

/// C `select`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn select(
    nfds: c_int,
    readfds: *mut c_void,
    writefds: *mut c_void,
    exceptfds: *mut c_void,
    timeout: *mut c_void,
) -> c_int {
    let ret = unsafe {
        sys::syscall6(
            SYS_SELECT,
            u64::from(nfds.cast_unsigned()),
            ptr_u64(readfds),
            ptr_u64(writefds),
            ptr_u64(exceptfds),
            ptr_u64(timeout),
            0,
        )
    };
    ret_c_int(ret)
}

/// Darwin `select$DARWIN_EXTSN` alias.
#[unsafe(export_name = "select$DARWIN_EXTSN")]
pub(crate) unsafe extern "C" fn select_darwin_extsn(
    nfds: c_int,
    readfds: *mut c_void,
    writefds: *mut c_void,
    exceptfds: *mut c_void,
    timeout: *mut c_void,
) -> c_int {
    unsafe { select(nfds, readfds, writefds, exceptfds, timeout) }
}

// ── getaddrinfo (host helper fills packed addrs; guest builds Darwin list) ──

/// Darwin `struct addrinfo` (64-bit).
#[repr(C)]
struct DarwinAddrinfo {
    ai_flags: c_int,
    ai_family: c_int,
    ai_socktype: c_int,
    ai_protocol: c_int,
    ai_addrlen: u32,
    _pad: u32,
    ai_canonname: *mut c_char,
    ai_addr: *mut c_void,
    ai_next: *mut DarwinAddrinfo,
}

/// Packed record from host helper (fixed 40 bytes).
const PACKED_REC: usize = 40;
const PACKED_MAX: usize = 16;
const PACKED_BUF: usize = 4_usize.saturating_add(PACKED_MAX.saturating_mul(PACKED_REC));

/// # Safety
/// `p` must point to at least 4 readable bytes.
unsafe fn read_u32_le(p: *const u8) -> u32 {
    let mut b = [0_u8; 4];
    // SAFETY: caller guarantees 4 readable bytes at `p`.
    unsafe {
        core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 4);
    }
    u32::from_le_bytes(b)
}

/// C `getaddrinfo`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const c_void,
    res: *mut *mut c_void,
) -> c_int {
    if res.is_null() {
        return EAI_FAIL;
    }
    unsafe {
        res.write(core::ptr::null_mut());
    }

    let mut family: c_int = 0;
    let mut socktype: c_int = 1;
    let mut protocol: c_int = 0;
    if !hints.is_null() {
        let h = hints.cast::<c_int>();
        unsafe {
            family = h.add(1).read();
            socktype = h.add(2).read();
            protocol = h.add(3).read();
            if socktype == 0 {
                socktype = 1;
            }
        }
    }

    let buf = unsafe { malloc(PACKED_BUF) };
    if buf.is_null() {
        return EAI_MEMORY;
    }
    unsafe {
        crate::dylib::libsystem_c::stdio::bzero(buf, PACKED_BUF);
    }

    let ret = unsafe {
        sys::syscall6(
            KH_HELPER_GETADDRINFO,
            ptr_u64(node.cast()),
            ptr_u64(service.cast()),
            u64::from(family.cast_unsigned()),
            ptr_u64(buf),
            u64::try_from(PACKED_BUF).unwrap_or(0),
            u64::from(socktype.cast_unsigned()),
        )
    };
    if ret < 0 {
        unsafe {
            free(buf);
        }
        let e = i32::try_from(ret.saturating_neg()).unwrap_or(EAI_FAIL);
        return if e == 0 { EAI_FAIL } else { e };
    }

    let count_u = unsafe { read_u32_le(buf.cast::<u8>()) };
    let Ok(count) = usize::try_from(count_u) else {
        unsafe {
            free(buf);
        }
        return EAI_FAIL;
    };
    if count == 0 {
        unsafe {
            free(buf);
        }
        return EAI_NONAME;
    }

    let mut head: *mut DarwinAddrinfo = core::ptr::null_mut();
    let mut prev: *mut DarwinAddrinfo = core::ptr::null_mut();
    let n = count.min(PACKED_MAX);

    for i in 0..n {
        let rec_off = 4_usize.saturating_add(i.saturating_mul(PACKED_REC));
        let rec = unsafe { buf.cast::<u8>().add(rec_off) };
        let fam = c_int::try_from(unsafe { read_u32_le(rec) }).unwrap_or(0);
        let st = c_int::try_from(unsafe { read_u32_le(rec.add(4)) }).unwrap_or(0);
        let proto = c_int::try_from(unsafe { read_u32_le(rec.add(8)) }).unwrap_or(0);
        let alen_u = unsafe { read_u32_le(rec.add(12)) };
        let alen = usize::try_from(alen_u).unwrap_or(0).min(24);

        let ai_raw = unsafe { malloc(core::mem::size_of::<DarwinAddrinfo>()) };
        let addr_raw = unsafe { malloc(alen.max(16)) };
        if ai_raw.is_null() || addr_raw.is_null() {
            unsafe {
                if !ai_raw.is_null() {
                    free(ai_raw);
                }
                if !addr_raw.is_null() {
                    free(addr_raw);
                }
                freeaddrinfo(head.cast());
                free(buf);
            }
            return EAI_MEMORY;
        }
        unsafe {
            crate::dylib::libsystem_c::stdio::bzero(ai_raw, core::mem::size_of::<DarwinAddrinfo>());
            crate::dylib::libsystem_c::stdio::bzero(addr_raw, alen.max(16));
            core::ptr::copy_nonoverlapping(rec.add(16), addr_raw.cast::<u8>(), alen);
        }
        let ai = ai_raw.cast::<DarwinAddrinfo>();
        unsafe {
            (*ai).ai_flags = 0;
            (*ai).ai_family = fam;
            (*ai).ai_socktype = if st != 0 { st } else { socktype };
            (*ai).ai_protocol = if proto != 0 { proto } else { protocol };
            (*ai).ai_addrlen = u32::try_from(alen).unwrap_or(16);
            (*ai).ai_canonname = core::ptr::null_mut();
            (*ai).ai_addr = addr_raw;
            (*ai).ai_next = core::ptr::null_mut();
            if head.is_null() {
                head = ai;
            } else {
                (*prev).ai_next = ai;
            }
            prev = ai;
        }
    }

    unsafe {
        free(buf);
        res.write(head.cast());
    }
    0
}

/// C `freeaddrinfo`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn freeaddrinfo(res: *mut c_void) {
    let mut cur = res.cast::<DarwinAddrinfo>();
    while !cur.is_null() {
        unsafe {
            let next = (*cur).ai_next;
            if !(*cur).ai_addr.is_null() {
                free((*cur).ai_addr);
            }
            if !(*cur).ai_canonname.is_null() {
                free((*cur).ai_canonname.cast());
            }
            free(cur.cast());
            cur = next;
        }
    }
}

/// C `gai_strerror` (static strings).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn gai_strerror(errcode: c_int) -> *const c_char {
    let s: &[u8] = match errcode {
        0 => b"Success\0",
        EAI_NONAME => b"nodename nor servname provided, or not known\0",
        EAI_MEMORY => b"Memory allocation failure\0",
        EAI_FAIL => b"Non-recoverable failure in name resolution\0",
        _ => b"Unknown error\0",
    };
    s.as_ptr().cast()
}

// ── inet_pton / inet_ntop (pure guest; curl G3 after pipe) ───────────────────

const AF_INET: c_int = 2;
const AF_INET6: c_int = 30;

fn cstr_bytes(src: *const c_char) -> Option<&'static [u8]> {
    if src.is_null() {
        return None;
    }
    let mut len = 0_usize;
    // SAFETY: caller guarantees a readable C string (bounded).
    unsafe {
        while *src.add(len) != 0 {
            len = len.saturating_add(1);
            if len > 128 {
                return None;
            }
        }
        Some(core::slice::from_raw_parts(src.cast::<u8>(), len))
    }
}

fn parse_ipv4(s: &[u8], out: &mut [u8; 4]) -> bool {
    let mut idx = 0_usize;
    let mut cur: Option<u32> = None;
    let mut saw_dot = false;
    for &b in s {
        if b == b'.' {
            let Some(v) = cur else {
                return false;
            };
            if v > 255 || idx >= 4 {
                return false;
            }
            if let Some(slot) = out.get_mut(idx) {
                *slot = u8::try_from(v).unwrap_or(0);
            }
            idx = idx.saturating_add(1);
            cur = None;
            saw_dot = true;
            continue;
        }
        if !b.is_ascii_digit() {
            return false;
        }
        saw_dot = false;
        let d = u32::from(b.wrapping_sub(b'0'));
        let next = cur.unwrap_or(0).saturating_mul(10).saturating_add(d);
        if next > 255 {
            return false;
        }
        cur = Some(next);
    }
    let _ = saw_dot;
    let Some(v) = cur else {
        return false;
    };
    if v > 255 || idx != 3 {
        return false;
    }
    if let Some(slot) = out.get_mut(3) {
        *slot = u8::try_from(v).unwrap_or(0);
    }
    true
}

fn parse_hex4(s: &[u8]) -> Option<u16> {
    if s.is_empty() || s.len() > 4 {
        return None;
    }
    let mut v = 0_u16;
    for &b in s {
        let d = match b {
            b'0'..=b'9' => b.wrapping_sub(b'0'),
            b'a'..=b'f' => b.wrapping_sub(b'a').saturating_add(10),
            b'A'..=b'F' => b.wrapping_sub(b'A').saturating_add(10),
            _ => return None,
        };
        v = v.checked_mul(16)?.checked_add(u16::from(d))?;
    }
    Some(v)
}

fn put_be_u16(out: &mut [u8; 16], hextet_idx: usize, v: u16) {
    let base = hextet_idx.saturating_mul(2);
    let bytes = v.to_be_bytes();
    if let Some(slot) = out.get_mut(base) {
        *slot = *bytes.first().unwrap_or(&0);
    }
    if let Some(slot) = out.get_mut(base.saturating_add(1)) {
        *slot = *bytes.get(1).unwrap_or(&0);
    }
}

/// Minimal IPv6 text parser (covers common forms; enough for curl/c-ares).
fn parse_ipv6(s: &[u8], out: &mut [u8; 16]) -> bool {
    let mut hextets = [0_u16; 8];
    let mut hi = 0_usize;
    let mut compress: Option<usize> = None;
    let mut i = 0_usize;
    if s.first() == Some(&b':') {
        if s.get(1) != Some(&b':') {
            return false;
        }
        compress = Some(0);
        i = 2;
    }
    while i < s.len() && hi < 8 {
        if s.get(i) == Some(&b':') {
            if compress.is_some() {
                return false;
            }
            compress = Some(hi);
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        let mut v4_tail = false;
        while i < s.len() {
            match s.get(i).copied() {
                Some(b':') | None => break,
                Some(b'.') => {
                    v4_tail = true;
                    break;
                }
                Some(_) => i = i.saturating_add(1),
            }
        }
        if v4_tail {
            let Some(tail) = s.get(start..) else {
                return false;
            };
            let mut v4 = [0_u8; 4];
            if !parse_ipv4(tail, &mut v4) || hi > 6 {
                return false;
            }
            let h0 =
                (u16::from(*v4.first().unwrap_or(&0)) << 8) | u16::from(*v4.get(1).unwrap_or(&0));
            let h1 =
                (u16::from(*v4.get(2).unwrap_or(&0)) << 8) | u16::from(*v4.get(3).unwrap_or(&0));
            if let Some(slot) = hextets.get_mut(hi) {
                *slot = h0;
            }
            if let Some(slot) = hextets.get_mut(hi.saturating_add(1)) {
                *slot = h1;
            }
            hi = hi.saturating_add(2);
            break;
        }
        if i == start && compress.is_none() {
            return false;
        }
        if i > start {
            let Some(chunk) = s.get(start..i) else {
                return false;
            };
            let Some(v) = parse_hex4(chunk) else {
                return false;
            };
            if let Some(slot) = hextets.get_mut(hi) {
                *slot = v;
            }
            hi = hi.saturating_add(1);
        }
        if s.get(i) == Some(&b':') {
            i = i.saturating_add(1);
        }
    }
    if let Some(c) = compress {
        let used = hi;
        let zeros = 8_usize.saturating_sub(used);
        if zeros == 0 {
            return false;
        }
        let mut full = [0_u16; 8];
        let mut w = 0_usize;
        for j in 0..c {
            if let (Some(dst), Some(src)) = (full.get_mut(w), hextets.get(j)) {
                *dst = *src;
            }
            w = w.saturating_add(1);
        }
        w = w.saturating_add(zeros);
        for j in c..used {
            if w >= 8 {
                return false;
            }
            if let (Some(dst), Some(src)) = (full.get_mut(w), hextets.get(j)) {
                *dst = *src;
            }
            w = w.saturating_add(1);
        }
        hextets = full;
    } else if hi != 8 {
        return false;
    }
    for j in 0..8 {
        if let Some(v) = hextets.get(j).copied() {
            put_be_u16(out, j, v);
        }
    }
    true
}

fn push_byte(buf: &mut [u8; 64], o: &mut usize, b: u8) -> bool {
    if let Some(slot) = buf.get_mut(*o) {
        *slot = b;
        *o = o.saturating_add(1);
        true
    } else {
        false
    }
}

fn push_u8_dec(buf: &mut [u8; 64], o: &mut usize, mut v: u32) -> bool {
    if v >= 100 {
        let h = v.saturating_div(100);
        if !push_byte(buf, o, b'0'.saturating_add(u8::try_from(h).unwrap_or(0))) {
            return false;
        }
        v %= 100;
        let t = v.saturating_div(10);
        if !push_byte(buf, o, b'0'.saturating_add(u8::try_from(t).unwrap_or(0))) {
            return false;
        }
        let o1 = v % 10;
        push_byte(buf, o, b'0'.saturating_add(u8::try_from(o1).unwrap_or(0)))
    } else if v >= 10 {
        let t = v.saturating_div(10);
        if !push_byte(buf, o, b'0'.saturating_add(u8::try_from(t).unwrap_or(0))) {
            return false;
        }
        let o1 = v % 10;
        push_byte(buf, o, b'0'.saturating_add(u8::try_from(o1).unwrap_or(0)))
    } else {
        push_byte(buf, o, b'0'.saturating_add(u8::try_from(v).unwrap_or(0)))
    }
}

/// C `inet_pton` → nlist `_inet_pton`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn inet_pton(
    af: c_int,
    src: *const c_char,
    dst: *mut c_void,
) -> c_int {
    if src.is_null() || dst.is_null() {
        errno::set_errno(EFAULT);
        return -1;
    }
    let Some(s) = cstr_bytes(src) else {
        return 0;
    };
    match af {
        AF_INET => {
            let mut out = [0_u8; 4];
            if parse_ipv4(s, &mut out) {
                unsafe {
                    core::ptr::copy_nonoverlapping(out.as_ptr(), dst.cast::<u8>(), 4);
                }
                1
            } else {
                0
            }
        }
        AF_INET6 => {
            let mut out = [0_u8; 16];
            if parse_ipv6(s, &mut out) {
                unsafe {
                    core::ptr::copy_nonoverlapping(out.as_ptr(), dst.cast::<u8>(), 16);
                }
                1
            } else {
                0
            }
        }
        _ => {
            errno::set_errno(47); // EAFNOSUPPORT
            -1
        }
    }
}

/// C `inet_ntop` → nlist `_inet_ntop`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn inet_ntop(
    af: c_int,
    src: *const c_void,
    dst: *mut c_char,
    size: u32,
) -> *const c_char {
    if src.is_null() || dst.is_null() || size == 0 {
        errno::set_errno(EFAULT);
        return core::ptr::null();
    }
    let mut buf = [0_u8; 64];
    let mut o = 0_usize;
    let ok = match af {
        AF_INET => {
            let mut ip = [0_u8; 4];
            unsafe {
                core::ptr::copy_nonoverlapping(src.cast::<u8>(), ip.as_mut_ptr(), 4);
            }
            let mut good = true;
            for (i, b) in ip.iter().enumerate() {
                if i > 0 {
                    good = good && push_byte(&mut buf, &mut o, b'.');
                }
                good = good && push_u8_dec(&mut buf, &mut o, u32::from(*b));
            }
            good
        }
        AF_INET6 => {
            let mut ip = [0_u8; 16];
            unsafe {
                core::ptr::copy_nonoverlapping(src.cast::<u8>(), ip.as_mut_ptr(), 16);
            }
            let hex = b"0123456789abcdef";
            let mut good = true;
            for i in 0_usize..8 {
                if i > 0 {
                    good = good && push_byte(&mut buf, &mut o, b':');
                }
                let b0 = *ip.get(i.saturating_mul(2)).unwrap_or(&0);
                let b1 = *ip.get(i.saturating_mul(2).saturating_add(1)).unwrap_or(&0);
                let v = (u16::from(b0) << 8) | u16::from(b1);
                if v == 0 {
                    good = good && push_byte(&mut buf, &mut o, b'0');
                } else {
                    let mut started = false;
                    for shift in [12_u32, 8, 4, 0] {
                        let nibble = usize::from((v >> shift) & 0xf);
                        if nibble != 0 || started || shift == 0 {
                            let ch = *hex.get(nibble).unwrap_or(&b'0');
                            good = good && push_byte(&mut buf, &mut o, ch);
                            started = true;
                        }
                    }
                }
            }
            good
        }
        _ => {
            errno::set_errno(47);
            return core::ptr::null();
        }
    };
    if !ok {
        errno::set_errno(28);
        return core::ptr::null();
    }
    let need = o.saturating_add(1);
    if u32::try_from(need).unwrap_or(u32::MAX) > size {
        errno::set_errno(28); // ENOSPC
        return core::ptr::null();
    }
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), dst.cast::<u8>(), o);
        *dst.add(o) = 0;
    }
    dst.cast_const()
}
