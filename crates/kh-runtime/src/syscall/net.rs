//! BSD socket / poll surface for curl G3 (trace-first).
//!
//! Darwin sockaddr_in uses `sa_len` + `sa_family` (bytes 0–1). Linux uses
//! `sa_family_t` (u16) at offset 0. AF_INET6 numbers also differ (Darwin 30 vs
//! Linux 10). Option numbers are translated for the common curl set.

use crate::host;
use crate::mem::registry_check_range;

use super::common::{
    EBADF, EFAULT, EINVAL, ENOMEM, EPERM, SyscallArgs, SyscallResult, guest_slice, guest_slice_mut,
    guest_write, guest_write_u32, reg_as_i32,
};
use super::fd::{alloc_guest_fd, guest_to_host_fd};

/// Darwin `AF_*` (subset).
const DARWIN_AF_UNIX: i32 = 1;
const DARWIN_AF_INET: i32 = 2;
const DARWIN_AF_INET6: i32 = 30;

/// Darwin `SOCK_*` (match Linux for stream/dgram/raw).
const DARWIN_SOCK_STREAM: i32 = 1;
const DARWIN_SOCK_DGRAM: i32 = 2;
const DARWIN_SOCK_RAW: i32 = 3;
/// Darwin `SOCK_NONBLOCK` (not Linux `04000`).
const DARWIN_SOCK_NONBLOCK: i32 = 0x2000_0000;

/// Darwin `SOL_SOCKET`.
const DARWIN_SOL_SOCKET: i32 = 0xffff;

/// Common Darwin `SO_*` (subset used by curl).
const DARWIN_SO_REUSEADDR: i32 = 0x0004;
const DARWIN_SO_KEEPALIVE: i32 = 0x0008;
const DARWIN_SO_LINGER: i32 = 0x0080;
const DARWIN_SO_NOSIGPIPE: i32 = 0x1022;
const DARWIN_SO_RCVTIMEO: i32 = 0x1006;
const DARWIN_SO_SNDTIMEO: i32 = 0x1005;
const DARWIN_SO_ERROR: i32 = 0x1007;
const DARWIN_SO_TYPE: i32 = 0x1008;
const DARWIN_SO_RCVBUF: i32 = 0x1002;
const DARWIN_SO_SNDBUF: i32 = 0x1001;

/// Darwin `IPPROTO_*` / TCP.
const DARWIN_IPPROTO_TCP: i32 = 6;
const DARWIN_IPPROTO_IP: i32 = 0;
const DARWIN_IPPROTO_IPV6: i32 = 41;
const DARWIN_TCP_NODELAY: i32 = 0x01;
const DARWIN_IP_TOS: i32 = 3;
const DARWIN_IPV6_TCLASS: i32 = 36;

fn net_log(msg: &str) {
    // Success-path chatter only at debug (`kh -vv` / `KAKEHASHI_LOG=debug`).
    tracing::debug!(target: "kh_runtime::syscall::net", "{msg}");
}

/// Soft Darwin errno constants we return for network failures.
const DARWIN_EAGAIN: i64 = 35;
const DARWIN_EINPROGRESS: i64 = 36;
const DARWIN_ECONNREFUSED: i64 = 61;
const DARWIN_ENETUNREACH: i64 = 51;
const DARWIN_EHOSTUNREACH: i64 = 65;
const DARWIN_ETIMEDOUT: i64 = 60;
const DARWIN_ECONNRESET: i64 = 54;
const DARWIN_EPIPE: i64 = 32;
const DARWIN_EADDRINUSE: i64 = 48;
const DARWIN_EISCONN: i64 = 56;
const DARWIN_ENOTCONN: i64 = 57;
const DARWIN_EAFNOSUPPORT: i64 = 47;

/// Host errno → Darwin positive errno (subset).
fn host_errno_to_darwin(e: i32) -> i64 {
    if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
        return DARWIN_EAGAIN;
    }
    if e == libc::EINPROGRESS {
        return DARWIN_EINPROGRESS;
    }
    if e == libc::ECONNREFUSED {
        return DARWIN_ECONNREFUSED;
    }
    if e == libc::ENETUNREACH {
        return DARWIN_ENETUNREACH;
    }
    if e == libc::EHOSTUNREACH {
        return DARWIN_EHOSTUNREACH;
    }
    if e == libc::ETIMEDOUT {
        return DARWIN_ETIMEDOUT;
    }
    if e == libc::ECONNRESET {
        return DARWIN_ECONNRESET;
    }
    if e == libc::EPIPE {
        return DARWIN_EPIPE;
    }
    if e == libc::EADDRINUSE {
        return DARWIN_EADDRINUSE;
    }
    if e == libc::EISCONN {
        return DARWIN_EISCONN;
    }
    if e == libc::ENOTCONN {
        return DARWIN_ENOTCONN;
    }
    if e == libc::EAFNOSUPPORT {
        return DARWIN_EAFNOSUPPORT;
    }
    i64::from(e).abs().max(1)
}

fn darwin_af_to_host(af: i32) -> Option<libc::c_int> {
    match af {
        0 => Some(libc::AF_UNSPEC),
        DARWIN_AF_UNIX => Some(libc::AF_UNIX),
        DARWIN_AF_INET => Some(libc::AF_INET),
        DARWIN_AF_INET6 => Some(libc::AF_INET6),
        _ => None,
    }
}

fn host_af_to_darwin(af: i32) -> i32 {
    if af == libc::AF_INET {
        DARWIN_AF_INET
    } else if af == libc::AF_INET6 {
        DARWIN_AF_INET6
    } else if af == libc::AF_UNIX {
        DARWIN_AF_UNIX
    } else if af == libc::AF_UNSPEC {
        0
    } else {
        af
    }
}

fn darwin_socktype_to_host(ty: i32) -> Option<libc::c_int> {
    let base = ty & 0xff;
    match base {
        DARWIN_SOCK_STREAM => Some(libc::SOCK_STREAM),
        DARWIN_SOCK_DGRAM => Some(libc::SOCK_DGRAM),
        DARWIN_SOCK_RAW => Some(libc::SOCK_RAW),
        0 => Some(0),
        _ => None,
    }
}

fn put_u8(buf: &mut [u8], idx: usize, v: u8) {
    if let Some(slot) = buf.get_mut(idx) {
        *slot = v;
    }
}

fn copy_range(dst: &mut [u8], dst_off: usize, src: &[u8]) {
    if let Some(d) = dst.get_mut(dst_off..dst_off.saturating_add(src.len()))
        && d.len() == src.len()
    {
        d.copy_from_slice(src);
    }
}

/// Translate Darwin sockaddr bytes for host libc (AF rewrite).
///
/// May **grow** `buf` for `AF_UNIX` so bottle path translation is not truncated.
fn darwin_sockaddr_to_host(buf: &mut Vec<u8>) -> Result<(), i64> {
    if buf.len() < 2 {
        return Err(EINVAL);
    }
    // XNU: byte0 = sa_len, byte1 = sa_family.
    let sa_family = i32::from(*buf.get(1).unwrap_or(&0));
    match sa_family {
        DARWIN_AF_INET if buf.len() >= 8 => {
            let port = [*buf.get(2).unwrap_or(&0), *buf.get(3).unwrap_or(&0)];
            let addr = [
                *buf.get(4).unwrap_or(&0),
                *buf.get(5).unwrap_or(&0),
                *buf.get(6).unwrap_or(&0),
                *buf.get(7).unwrap_or(&0),
            ];
            buf.fill(0);
            let fam = u16::try_from(libc::AF_INET).unwrap_or(2).to_ne_bytes();
            put_u8(buf, 0, *fam.first().unwrap_or(&0));
            put_u8(buf, 1, *fam.get(1).unwrap_or(&0));
            put_u8(buf, 2, port[0]);
            put_u8(buf, 3, port[1]);
            put_u8(buf, 4, addr[0]);
            put_u8(buf, 5, addr[1]);
            put_u8(buf, 6, addr[2]);
            put_u8(buf, 7, addr[3]);
            Ok(())
        }
        DARWIN_AF_INET6 if buf.len() >= 28 => {
            let port = [*buf.get(2).unwrap_or(&0), *buf.get(3).unwrap_or(&0)];
            let flow = [
                *buf.get(4).unwrap_or(&0),
                *buf.get(5).unwrap_or(&0),
                *buf.get(6).unwrap_or(&0),
                *buf.get(7).unwrap_or(&0),
            ];
            let mut addr = [0_u8; 16];
            if let Some(src) = buf.get(8..24) {
                addr.copy_from_slice(src);
            }
            let scope = [
                *buf.get(24).unwrap_or(&0),
                *buf.get(25).unwrap_or(&0),
                *buf.get(26).unwrap_or(&0),
                *buf.get(27).unwrap_or(&0),
            ];
            buf.fill(0);
            let fam = u16::try_from(libc::AF_INET6).unwrap_or(10).to_ne_bytes();
            put_u8(buf, 0, *fam.first().unwrap_or(&0));
            put_u8(buf, 1, *fam.get(1).unwrap_or(&0));
            put_u8(buf, 2, port[0]);
            put_u8(buf, 3, port[1]);
            copy_range(buf, 4, &flow);
            copy_range(buf, 8, &addr);
            copy_range(buf, 24, &scope);
            Ok(())
        }
        DARWIN_AF_UNIX | 0 => {
            // Darwin: sa_len @0, sa_family @1, sun_path @2…
            // Linux:  sa_family u16 @0, sun_path @2…
            // Note: some guests leave sun_len=0 and pass the real size as
            // connect()'s addrlen only — prefer buffer length then.
            let sa_len = usize::from(*buf.first().unwrap_or(&0));
            let path_end = if sa_len > 2 {
                sa_len.min(buf.len())
            } else {
                buf.len()
            };
            let path_bytes = buf.get(2..path_end).unwrap_or(&[]).to_vec();
            // NUL-terminated guest path (may be abstract if first byte is 0).
            let is_abstract = path_bytes.first().copied() == Some(0);
            let host_path = if is_abstract {
                path_bytes
            } else {
                let cstr_end = path_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(path_bytes.len());
                let guest = String::from_utf8_lossy(path_bytes.get(..cstr_end).unwrap_or(&[]));
                if let Ok(p) = crate::bottle::translate_path(guest.as_ref()) {
                    let mut b = p.into_os_string().into_encoded_bytes();
                    b.push(0);
                    b
                } else {
                    let mut b = path_bytes;
                    if !b.ends_with(&[0]) {
                        b.push(0);
                    }
                    b
                }
            };
            // Linux sockaddr_un is typically 110 bytes; **grow** the buffer so
            // translated bottle paths are not truncated to Darwin sa_len.
            let need = 2usize
                .saturating_add(host_path.len())
                .max(buf.len())
                .min(110);
            let mut out = vec![0_u8; need];
            let fam = u16::try_from(libc::AF_UNIX).unwrap_or(1).to_ne_bytes();
            put_u8(&mut out, 0, *fam.first().unwrap_or(&0));
            put_u8(&mut out, 1, *fam.get(1).unwrap_or(&0));
            let copy_n = host_path.len().min(out.len().saturating_sub(2));
            if let Some(dst) = out.get_mut(2..2usize.saturating_add(copy_n)) {
                dst.copy_from_slice(host_path.get(..copy_n).unwrap_or(&[]));
            }
            *buf = out;
            Ok(())
        }
        _ => Err(EPERM),
    }
}

// Keep a thin wrapper for call sites that still pass a fixed guest slice
// through a temporary Vec (connect/bind/sendmsg).

/// After [`host_sockaddr_to_darwin`], prefer Darwin `sa_len` (16 / 28).
fn darwin_socklen(buf: &[u8], fallback: usize) -> usize {
    let sa_len = usize::from(*buf.first().unwrap_or(&0));
    let fam = i32::from(*buf.get(1).unwrap_or(&0));
    if fam == DARWIN_AF_INET && sa_len == 16 {
        16
    } else if fam == DARWIN_AF_INET6 && sa_len == 28 {
        28
    } else {
        fallback
    }
}

fn host_sockaddr_to_darwin(buf: &mut [u8]) {
    if buf.len() < 2 {
        return;
    }
    let host_af = i32::from(u16::from_ne_bytes([
        *buf.first().unwrap_or(&0),
        *buf.get(1).unwrap_or(&0),
    ]));
    let darwin_af = host_af_to_darwin(host_af);
    if darwin_af == DARWIN_AF_INET && buf.len() >= 8 {
        let port = [*buf.get(2).unwrap_or(&0), *buf.get(3).unwrap_or(&0)];
        let addr = [
            *buf.get(4).unwrap_or(&0),
            *buf.get(5).unwrap_or(&0),
            *buf.get(6).unwrap_or(&0),
            *buf.get(7).unwrap_or(&0),
        ];
        buf.fill(0);
        put_u8(buf, 0, 16); // sa_len
        put_u8(buf, 1, u8::try_from(DARWIN_AF_INET).unwrap_or(2));
        put_u8(buf, 2, port[0]);
        put_u8(buf, 3, port[1]);
        put_u8(buf, 4, addr[0]);
        put_u8(buf, 5, addr[1]);
        put_u8(buf, 6, addr[2]);
        put_u8(buf, 7, addr[3]);
    } else if darwin_af == DARWIN_AF_INET6 && buf.len() >= 28 {
        let port = [*buf.get(2).unwrap_or(&0), *buf.get(3).unwrap_or(&0)];
        let flow = [
            *buf.get(4).unwrap_or(&0),
            *buf.get(5).unwrap_or(&0),
            *buf.get(6).unwrap_or(&0),
            *buf.get(7).unwrap_or(&0),
        ];
        let mut addr = [0_u8; 16];
        if let Some(src) = buf.get(8..24) {
            addr.copy_from_slice(src);
        }
        let scope = [
            *buf.get(24).unwrap_or(&0),
            *buf.get(25).unwrap_or(&0),
            *buf.get(26).unwrap_or(&0),
            *buf.get(27).unwrap_or(&0),
        ];
        buf.fill(0);
        put_u8(buf, 0, 28);
        put_u8(buf, 1, u8::try_from(DARWIN_AF_INET6).unwrap_or(30));
        put_u8(buf, 2, port[0]);
        put_u8(buf, 3, port[1]);
        copy_range(buf, 4, &flow);
        copy_range(buf, 8, &addr);
        copy_range(buf, 24, &scope);
    }
}

fn map_sockopt(level: i32, optname: i32) -> Option<(libc::c_int, libc::c_int)> {
    if level == DARWIN_SOL_SOCKET {
        let host_opt = match optname {
            DARWIN_SO_REUSEADDR => libc::SO_REUSEADDR,
            DARWIN_SO_KEEPALIVE => libc::SO_KEEPALIVE,
            DARWIN_SO_LINGER => libc::SO_LINGER,
            DARWIN_SO_RCVTIMEO => libc::SO_RCVTIMEO,
            DARWIN_SO_SNDTIMEO => libc::SO_SNDTIMEO,
            DARWIN_SO_ERROR => libc::SO_ERROR,
            DARWIN_SO_TYPE => libc::SO_TYPE,
            DARWIN_SO_RCVBUF => libc::SO_RCVBUF,
            DARWIN_SO_SNDBUF => libc::SO_SNDBUF,
            DARWIN_SO_NOSIGPIPE => return None, // Darwin-only soft-ok
            _ => return Some((libc::SOL_SOCKET, optname)),
        };
        return Some((libc::SOL_SOCKET, host_opt));
    }
    if level == DARWIN_IPPROTO_TCP {
        if optname == DARWIN_TCP_NODELAY {
            return Some((libc::IPPROTO_TCP, libc::TCP_NODELAY));
        }
        return Some((libc::IPPROTO_TCP, optname));
    }
    if level == DARWIN_IPPROTO_IP {
        if optname == DARWIN_IP_TOS {
            return Some((libc::IPPROTO_IP, libc::IP_TOS));
        }
        return Some((libc::IPPROTO_IP, optname));
    }
    if level == DARWIN_IPPROTO_IPV6 {
        if optname == DARWIN_IPV6_TCLASS {
            #[cfg(target_os = "linux")]
            {
                return Some((libc::IPPROTO_IPV6, libc::IPV6_TCLASS));
            }
            #[cfg(not(target_os = "linux"))]
            {
                return None;
            }
        }
        return Some((libc::IPPROTO_IPV6, optname));
    }
    Some((level, optname))
}

fn process_close_orphan(gfd: i32, host_fd: std::os::fd::RawFd) {
    let _ = crate::process::fd_take(gfd);
    host::close_fd(host_fd);
}

/// `pipe` — fildes pointer in `x0` (two `int`s).
pub(crate) fn handle_pipe(args: SyscallArgs) -> SyscallResult {
    let name = "pipe";
    net_log("pipe");
    if args.x0 == 0 || !registry_check_range(args.x0, 8, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some((r, w)) = host::pipe_fds() else {
        return SyscallResult::err(name, EPERM);
    };
    let Some(gr) = alloc_guest_fd(r) else {
        host::close_fd(r);
        host::close_fd(w);
        return SyscallResult::err(name, ENOMEM);
    };
    let Some(gw) = alloc_guest_fd(w) else {
        host::close_fd(w);
        process_close_orphan(gr, r);
        return SyscallResult::err(name, ENOMEM);
    };
    guest_write_u32(args.x0, gr.cast_unsigned());
    guest_write_u32(args.x0.wrapping_add(4), gw.cast_unsigned());
    net_log(&format!("pipe -> gfd {gr},{gw}"));
    SyscallResult::ok(name, 0)
}

/// `socketpair` — domain, type, protocol, int sv[2] out.
pub(crate) fn handle_socketpair(args: SyscallArgs) -> SyscallResult {
    let name = "socketpair";
    let domain = reg_as_i32(args.x0);
    let ty = reg_as_i32(args.x1);
    let protocol = reg_as_i32(args.x2);
    net_log(&format!(
        "socketpair domain={domain} ty={ty} proto={protocol}"
    ));
    if args.x3 == 0 || !registry_check_range(args.x3, 8, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(host_af) = darwin_af_to_host(domain) else {
        return SyscallResult::err(name, DARWIN_EAFNOSUPPORT);
    };
    let Some(host_ty) = darwin_socktype_to_host(ty) else {
        return SyscallResult::err(name, EINVAL);
    };
    let Some((a, b)) = host::socketpair(host_af, host_ty, protocol) else {
        return SyscallResult::err(name, EPERM);
    };
    let Some(ga) = alloc_guest_fd(a) else {
        host::close_fd(a);
        host::close_fd(b);
        return SyscallResult::err(name, ENOMEM);
    };
    let Some(gb) = alloc_guest_fd(b) else {
        host::close_fd(b);
        process_close_orphan(ga, a);
        return SyscallResult::err(name, ENOMEM);
    };
    // Host forces O_NONBLOCK; guest must see nonblock so keep-alive EAGAIN
    // is not turned into an infinite blocking wait.
    crate::process::fd_set_guest_nonblock(ga, true);
    crate::process::fd_set_guest_nonblock(gb, true);
    guest_write_u32(args.x3, ga.cast_unsigned());
    guest_write_u32(args.x3.wrapping_add(4), gb.cast_unsigned());
    net_log(&format!("socketpair -> gfd {ga},{gb}"));
    SyscallResult::ok(name, 0)
}

/// `socket` — domain, type, protocol.
pub(crate) fn handle_socket(args: SyscallArgs) -> SyscallResult {
    let name = "socket";
    let domain = reg_as_i32(args.x0);
    let ty = reg_as_i32(args.x1);
    let protocol = reg_as_i32(args.x2);
    net_log(&format!("socket domain={domain} ty={ty} proto={protocol}"));
    let Some(host_af) = darwin_af_to_host(domain) else {
        return SyscallResult::err(name, DARWIN_EAFNOSUPPORT);
    };
    let Some(host_ty) = darwin_socktype_to_host(ty) else {
        return SyscallResult::err(name, EINVAL);
    };
    let Some(hfd) = host::socket(host_af, host_ty, protocol) else {
        return SyscallResult::err(name, EPERM);
    };
    if let Some(g) = alloc_guest_fd(hfd) {
        // Darwin sockets start blocking. Host fd is O_NONBLOCK; read/write
        // emulate blocking until the guest fcntl's O_NONBLOCK (curl multi).
        // rustup/rust std uses blocking `connect` — do not advertise
        // O_NONBLOCK here or F_GETFL + EINPROGRESS fails without kevent.
        let guest_nb = ty & DARWIN_SOCK_NONBLOCK != 0;
        crate::process::fd_set_guest_nonblock(g, guest_nb);
        net_log(&format!("socket -> gfd {g}"));
        SyscallResult::ok(name, u64::try_from(g).unwrap_or(0))
    } else {
        host::close_fd(hfd);
        SyscallResult::err(name, ENOMEM)
    }
}

fn with_translated_sockaddr(
    name: &'static str,
    ptr: u64,
    len: usize,
    f: impl FnOnce(&[u8]) -> Result<(), i32>,
) -> SyscallResult {
    if len == 0 || len > 256 {
        return SyscallResult::err(name, EINVAL);
    }
    if ptr == 0 || !registry_check_range(ptr, len, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let mut buf = guest_slice(ptr, len).to_vec();
    if let Err(e) = darwin_sockaddr_to_host(&mut buf) {
        return SyscallResult::err(name, e);
    }
    match f(&buf) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

/// `connect`.
pub(crate) fn handle_connect(args: SyscallArgs) -> SyscallResult {
    let name = "connect";
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        net_log("connect EBADF");
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EINVAL);
    };
    net_log(&format!("connect hfd={hfd} len={len}"));
    crate::process::set_last_tcp_gfd(reg_as_i32(args.x0));
    let r = with_translated_sockaddr(name, args.x1, len, |addr| host::connect(hfd, addr));
    net_log(&format!("connect done err={} ret={:?}", r.error, r.retval));
    let gfd = reg_as_i32(args.x0);
    if r.error
        && r.retval == Some(DARWIN_EINPROGRESS.unsigned_abs())
        && !crate::process::fd_guest_nonblock(gfd)
    {
        return complete_blocking_connect(name, hfd);
    }
    r
}

/// Host sockets are O_NONBLOCK; a blocking guest `connect` must wait out
/// `EINPROGRESS` (rustup / rust std) instead of returning it as a hard error.
fn complete_blocking_connect(name: &'static str, hfd: std::os::fd::RawFd) -> SyscallResult {
    if !host::poll_fd_writable(hfd, -1) {
        return SyscallResult::err(name, DARWIN_ETIMEDOUT);
    }
    let mut errbuf = [0_u8; 4];
    match host::getsockopt(hfd, libc::SOL_SOCKET, libc::SO_ERROR, &mut errbuf) {
        Ok(_) => {
            let e = i32::from_le_bytes(errbuf);
            if e == 0 || e == libc::EISCONN {
                net_log("connect blocking complete ok");
                SyscallResult::ok(name, 0)
            } else {
                net_log(&format!("connect blocking so_error={e}"));
                SyscallResult::err(name, host_errno_to_darwin(e))
            }
        }
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

/// `bind`.
pub(crate) fn handle_bind(args: SyscallArgs) -> SyscallResult {
    let name = "bind";
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EINVAL);
    };
    with_translated_sockaddr(name, args.x1, len, |addr| host::bind(hfd, addr))
}

/// `listen`.
pub(crate) fn handle_listen(args: SyscallArgs) -> SyscallResult {
    let name = "listen";
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let backlog = reg_as_i32(args.x1);
    match host::listen(hfd, backlog) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

/// `accept` — optional sockaddr out in x1, len ptr in x2.
pub(crate) fn handle_accept(args: SyscallArgs) -> SyscallResult {
    let name = "accept";
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };

    let result = if args.x1 != 0 && args.x2 != 0 {
        if !registry_check_range(args.x2, 4, true) {
            return SyscallResult::err(name, EFAULT);
        }
        let guest_len =
            u32::from_le_bytes(guest_slice(args.x2, 4).try_into().unwrap_or([0, 0, 0, 0]));
        let max = usize::try_from(guest_len).unwrap_or(0).min(128);
        if max == 0 || !registry_check_range(args.x1, max, true) {
            return SyscallResult::err(name, EFAULT);
        }
        let mut addr_buf = vec![0_u8; max];
        match host::accept_addr(hfd, &mut addr_buf) {
            Ok((new_h, n)) => {
                let n = n.min(addr_buf.len());
                if let Some(slice) = addr_buf.get_mut(..n) {
                    host_sockaddr_to_darwin(slice);
                    guest_write(args.x1, slice);
                }
                guest_write_u32(args.x2, u32::try_from(n).unwrap_or(0));
                Ok(new_h)
            }
            Err(e) => Err(e),
        }
    } else {
        host::accept(hfd)
    };

    match result {
        Ok(new_h) => {
            if let Some(g) = alloc_guest_fd(new_h) {
                crate::process::fd_set_guest_nonblock(g, false);
                SyscallResult::ok(name, u64::try_from(g).unwrap_or(0))
            } else {
                host::close_fd(new_h);
                SyscallResult::err(name, ENOMEM)
            }
        }
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

/// `setsockopt`.
pub(crate) fn handle_setsockopt(args: SyscallArgs) -> SyscallResult {
    let name = "setsockopt";
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let level = reg_as_i32(args.x1);
    let optname = reg_as_i32(args.x2);
    let Ok(optlen) = usize::try_from(args.x4) else {
        return SyscallResult::err(name, EINVAL);
    };
    match map_sockopt(level, optname) {
        None => SyscallResult::ok(name, 0),
        Some((hl, ho)) => {
            let value: &[u8] = if optlen == 0 || args.x3 == 0 {
                &[]
            } else {
                if !registry_check_range(args.x3, optlen, false) {
                    return SyscallResult::err(name, EFAULT);
                }
                guest_slice(args.x3, optlen)
            };
            match host::setsockopt(hfd, hl, ho, value) {
                Ok(()) => SyscallResult::ok(name, 0),
                Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
            }
        }
    }
}

/// `getsockopt`.
pub(crate) fn handle_getsockopt(args: SyscallArgs) -> SyscallResult {
    let name = "getsockopt";
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let level = reg_as_i32(args.x1);
    let optname = reg_as_i32(args.x2);
    if args.x4 == 0 || !registry_check_range(args.x4, 4, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let optlen = u32::from_le_bytes(guest_slice(args.x4, 4).try_into().unwrap_or([0, 0, 0, 0]));
    let Ok(len_us) = usize::try_from(optlen) else {
        return SyscallResult::err(name, EINVAL);
    };
    if args.x3 == 0 || !registry_check_range(args.x3, len_us.max(1), true) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some((hl, ho)) = map_sockopt(level, optname) else {
        if len_us >= 4 {
            guest_write_u32(args.x3, 0);
            guest_write_u32(args.x4, 4);
        }
        return SyscallResult::ok(name, 0);
    };
    let buf = guest_slice_mut(args.x3, len_us);
    match host::getsockopt(hfd, hl, ho, buf) {
        Ok(n) => {
            // Linux `SO_ERROR` is a host errno; guests compare Darwin numbers
            // (`EINPROGRESS` 36 vs Linux 115).
            if ho == libc::SO_ERROR
                && n >= 4
                && let Some(raw) = buf.get(..4)
            {
                let host_e = i32::from_ne_bytes(raw.try_into().unwrap_or([0; 4]));
                if host_e != 0 {
                    let dar = i32::try_from(host_errno_to_darwin(host_e)).unwrap_or(host_e);
                    guest_write(args.x3, &dar.to_ne_bytes());
                    net_log(&format!("SO_ERROR host={host_e} darwin={dar}"));
                } else {
                    net_log("SO_ERROR 0");
                }
            }
            guest_write_u32(args.x4, u32::try_from(n).unwrap_or(0));
            net_log(&format!("getsockopt level={level} opt={optname} n={n}"));
            SyscallResult::ok(name, 0)
        }
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

/// `shutdown`.
pub(crate) fn handle_shutdown(args: SyscallArgs) -> SyscallResult {
    let name = "shutdown";
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let how = reg_as_i32(args.x1);
    match host::shutdown(hfd, how) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

fn handle_sockname(
    name: &'static str,
    args: SyscallArgs,
    op: impl FnOnce(std::os::fd::RawFd, &mut [u8]) -> Result<usize, i32>,
) -> SyscallResult {
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    if args.x1 == 0 || args.x2 == 0 || !registry_check_range(args.x2, 4, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let alen = u32::from_le_bytes(guest_slice(args.x2, 4).try_into().unwrap_or([0, 0, 0, 0]));
    let max = usize::try_from(alen).unwrap_or(0).min(128);
    if max == 0 || !registry_check_range(args.x1, max, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let mut buf = vec![0_u8; max];
    match op(hfd, &mut buf) {
        Ok(n) => {
            let n = n.min(buf.len());
            let out_len = if let Some(slice) = buf.get_mut(..n) {
                host_sockaddr_to_darwin(slice);
                guest_write(args.x1, slice);
                darwin_socklen(slice, n)
            } else {
                n
            };
            guest_write_u32(args.x2, u32::try_from(out_len).unwrap_or(0));
            net_log(&format!("{name} ok n={out_len}"));
            SyscallResult::ok(name, 0)
        }
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

/// `getsockname`.
pub(crate) fn handle_getsockname(args: SyscallArgs) -> SyscallResult {
    handle_sockname("getsockname", args, host::getsockname)
}

/// `getpeername`.
pub(crate) fn handle_getpeername(args: SyscallArgs) -> SyscallResult {
    handle_sockname("getpeername", args, host::getpeername)
}

/// `sendto` (also used for send with addr=null).
pub(crate) fn handle_sendto(args: SyscallArgs) -> SyscallResult {
    let name = "sendto";
    net_log(&format!(
        "sendto gfd={} len={} flags={:#x} alen={}",
        reg_as_i32(args.x0),
        args.x2,
        args.x3,
        args.x5
    ));
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EINVAL);
    };
    if len > 0 && (args.x1 == 0 || !registry_check_range(args.x1, len, false)) {
        return SyscallResult::err(name, EFAULT);
    }
    let flags = reg_as_i32(args.x3);
    // Strip unknown high bits (Darwin may set MSG_* we do not map).
    let host_flags = flags & !0x0008_0000;
    let buf = if len == 0 {
        &[][..]
    } else {
        guest_slice(args.x1, len)
    };
    let Ok(alen) = usize::try_from(args.x5) else {
        return SyscallResult::err(name, EINVAL);
    };
    let result = if args.x4 != 0 && alen > 0 {
        if !registry_check_range(args.x4, alen, false) {
            return SyscallResult::err(name, EFAULT);
        }
        let mut abuf = guest_slice(args.x4, alen).to_vec();
        if let Err(e) = darwin_sockaddr_to_host(&mut abuf) {
            return SyscallResult::err(name, e);
        }
        host::sendto(hfd, buf, host_flags, Some(abuf.as_slice()))
    } else {
        host::sendto(hfd, buf, host_flags, None)
    };
    match result {
        Ok(n) => {
            net_log(&format!("sendto -> n={n}"));
            SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
        }
        Err(e) => {
            net_log(&format!("sendto err={e}"));
            SyscallResult::err(name, host_errno_to_darwin(e))
        }
    }
}

/// `recvfrom`.
pub(crate) fn handle_recvfrom(args: SyscallArgs) -> SyscallResult {
    let name = "recvfrom";
    net_log(&format!(
        "recvfrom gfd={} len={} flags={:#x}",
        reg_as_i32(args.x0),
        args.x2,
        args.x3
    ));
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let Ok(len) = usize::try_from(args.x2) else {
        return SyscallResult::err(name, EINVAL);
    };
    if len > 0 && (args.x1 == 0 || !registry_check_range(args.x1, len, true)) {
        return SyscallResult::err(name, EFAULT);
    }
    let flags = reg_as_i32(args.x3);
    let buf = if len == 0 {
        &mut [][..]
    } else {
        guest_slice_mut(args.x1, len)
    };

    if args.x4 != 0 && args.x5 != 0 {
        if !registry_check_range(args.x5, 4, true) {
            return SyscallResult::err(name, EFAULT);
        }
        let alen = u32::from_le_bytes(guest_slice(args.x5, 4).try_into().unwrap_or([0, 0, 0, 0]));
        let max = usize::try_from(alen).unwrap_or(0).min(128);
        if max == 0 || !registry_check_range(args.x4, max, true) {
            return SyscallResult::err(name, EFAULT);
        }
        let mut abuf = vec![0_u8; max];
        match host::recvfrom(hfd, buf, flags, Some(abuf.as_mut_slice())) {
            Ok((n, naddr)) => {
                let naddr = naddr.min(abuf.len());
                let out_len = if let Some(slice) = abuf.get_mut(..naddr) {
                    host_sockaddr_to_darwin(slice);
                    guest_write(args.x4, slice);
                    darwin_socklen(slice, naddr)
                } else {
                    naddr
                };
                guest_write_u32(args.x5, u32::try_from(out_len).unwrap_or(0));
                SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
            }
            Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
        }
    } else {
        match host::recvfrom(hfd, buf, flags, None) {
            Ok((n, _)) => {
                net_log(&format!("recvfrom -> n={n}"));
                SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
            }
            Err(e) => {
                net_log(&format!("recvfrom err={e}"));
                SyscallResult::err(name, host_errno_to_darwin(e))
            }
        }
    }
}

/// Darwin arm64 `struct msghdr` size / field offsets (LP64).
const MSGHDR_SIZE: usize = 48;
const MSG_NAME_OFF: usize = 0;
const MSG_NAMELEN_OFF: usize = 8;
const MSG_IOV_OFF: usize = 16;
const MSG_IOVLEN_OFF: usize = 24;
// control / flags reserved for later ancillary support

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    let b = buf.get(off..off.saturating_add(4)).unwrap_or(&[0; 4]);
    u32::from_le_bytes(b.try_into().unwrap_or([0; 4]))
}

fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    let b = buf.get(off..off.saturating_add(8)).unwrap_or(&[0; 8]);
    u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
}

fn read_i32_le(buf: &[u8], off: usize) -> i32 {
    let b = buf.get(off..off.saturating_add(4)).unwrap_or(&[0; 4]);
    i32::from_le_bytes(b.try_into().unwrap_or([0; 4]))
}

/// Gather guest iovec into a host buffer (cap 256 KiB for HTTP/3 datagrams).
fn gather_iov(iov_ptr: u64, iovlen: i32) -> Result<Vec<u8>, i64> {
    if iovlen < 0 {
        return Err(EINVAL);
    }
    if iovlen == 0 || iov_ptr == 0 {
        return Ok(Vec::new());
    }
    let n = usize::try_from(iovlen).unwrap_or(0);
    let bytes = n.saturating_mul(16);
    if !registry_check_range(iov_ptr, bytes, false) {
        return Err(EFAULT);
    }
    let iov = guest_slice(iov_ptr, bytes);
    let mut out = Vec::new();
    for i in 0..n {
        let base_off = i.saturating_mul(16);
        let base = read_u64_le(iov, base_off);
        let len = read_u64_le(iov, base_off.saturating_add(8));
        let Ok(l) = usize::try_from(len) else {
            return Err(EINVAL);
        };
        if l == 0 {
            continue;
        }
        if out.len().saturating_add(l) > 256 * 1024 {
            return Err(ENOMEM);
        }
        if base == 0 || !registry_check_range(base, l, false) {
            return Err(EFAULT);
        }
        out.extend_from_slice(guest_slice(base, l));
    }
    Ok(out)
}

/// Scatter host buffer into guest iovec; returns bytes written.
fn scatter_iov(iov_ptr: u64, iovlen: i32, data: &[u8]) -> Result<usize, i64> {
    if iovlen < 0 {
        return Err(EINVAL);
    }
    if iovlen == 0 || iov_ptr == 0 || data.is_empty() {
        return Ok(0);
    }
    let n = usize::try_from(iovlen).unwrap_or(0);
    let bytes = n.saturating_mul(16);
    if !registry_check_range(iov_ptr, bytes, false) {
        return Err(EFAULT);
    }
    let iov = guest_slice(iov_ptr, bytes);
    let mut copied = 0_usize;
    for i in 0..n {
        if copied >= data.len() {
            break;
        }
        let base_off = i.saturating_mul(16);
        let base = read_u64_le(iov, base_off);
        let len = read_u64_le(iov, base_off.saturating_add(8));
        let Ok(l) = usize::try_from(len) else {
            return Err(EINVAL);
        };
        if l == 0 || base == 0 {
            continue;
        }
        if !registry_check_range(base, l, true) {
            return Err(EFAULT);
        }
        let take = l.min(data.len().saturating_sub(copied));
        if let Some(chunk) = data.get(copied..copied.saturating_add(take)) {
            guest_write(base, chunk);
            copied = copied.saturating_add(take);
        }
    }
    Ok(copied)
}

/// `sendmsg` — gather iov, optional name → host `sendto` (ancillary ignored).
pub(crate) fn handle_sendmsg(args: SyscallArgs) -> SyscallResult {
    let name = "sendmsg";
    net_log(&format!("sendmsg gfd={}", reg_as_i32(args.x0)));
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    if args.x1 == 0 || !registry_check_range(args.x1, MSGHDR_SIZE, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let hdr = guest_slice(args.x1, MSGHDR_SIZE);
    let msg_name = read_u64_le(hdr, MSG_NAME_OFF);
    let msg_namelen = read_u32_le(hdr, MSG_NAMELEN_OFF);
    let msg_iov = read_u64_le(hdr, MSG_IOV_OFF);
    let msg_iovlen = read_i32_le(hdr, MSG_IOVLEN_OFF);
    let flags = reg_as_i32(args.x2) & !0x0008_0000;

    let body = match gather_iov(msg_iov, msg_iovlen) {
        Ok(b) => b,
        Err(e) => return SyscallResult::err(name, e),
    };

    let result = if msg_name != 0 && msg_namelen > 0 {
        let Ok(alen) = usize::try_from(msg_namelen) else {
            return SyscallResult::err(name, EINVAL);
        };
        if !registry_check_range(msg_name, alen, false) {
            return SyscallResult::err(name, EFAULT);
        }
        let mut abuf = guest_slice(msg_name, alen).to_vec();
        if let Err(e) = darwin_sockaddr_to_host(&mut abuf) {
            return SyscallResult::err(name, e);
        }
        host::sendto(hfd, &body, flags, Some(abuf.as_slice()))
    } else {
        host::sendto(hfd, &body, flags, None)
    };
    match result {
        Ok(n) => {
            net_log(&format!("sendmsg -> n={n}"));
            SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
        }
        Err(e) => {
            net_log(&format!("sendmsg err={e}"));
            SyscallResult::err(name, host_errno_to_darwin(e))
        }
    }
}

/// `recvmsg` — host `recvfrom` into gather buffer, scatter to iov, optional name.
pub(crate) fn handle_recvmsg(args: SyscallArgs) -> SyscallResult {
    let name = "recvmsg";
    net_log(&format!("recvmsg gfd={}", reg_as_i32(args.x0)));
    let Some(hfd) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    if args.x1 == 0 || !registry_check_range(args.x1, MSGHDR_SIZE, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let hdr = guest_slice(args.x1, MSGHDR_SIZE);
    let msg_name = read_u64_le(hdr, MSG_NAME_OFF);
    let msg_namelen = read_u32_le(hdr, MSG_NAMELEN_OFF);
    let msg_iov = read_u64_le(hdr, MSG_IOV_OFF);
    let msg_iovlen = read_i32_le(hdr, MSG_IOVLEN_OFF);
    let flags = reg_as_i32(args.x2);

    // Total capacity from iov (cap 256 KiB).
    let mut cap = 0_usize;
    if msg_iovlen > 0 && msg_iov != 0 {
        let n = usize::try_from(msg_iovlen).unwrap_or(0);
        let bytes = n.saturating_mul(16);
        if registry_check_range(msg_iov, bytes, false) {
            let iov = guest_slice(msg_iov, bytes);
            for i in 0..n {
                let l = read_u64_le(iov, i.saturating_mul(16).saturating_add(8));
                cap = cap.saturating_add(usize::try_from(l).unwrap_or(0));
            }
        }
    }
    cap = cap.clamp(1, 256 * 1024);
    let mut buf = vec![0_u8; cap];
    let namelen_addr = args
        .x1
        .saturating_add(u64::try_from(MSG_NAMELEN_OFF).unwrap_or(0));

    let result = if msg_name != 0 && msg_namelen > 0 {
        let Ok(alen) = usize::try_from(msg_namelen) else {
            return SyscallResult::err(name, EINVAL);
        };
        if !registry_check_range(msg_name, alen, true) {
            return SyscallResult::err(name, EFAULT);
        }
        let mut abuf = vec![0_u8; alen.min(128)];
        match host::recvfrom(hfd, &mut buf, flags, Some(abuf.as_mut_slice())) {
            Ok((n, naddr)) => {
                let naddr = naddr.min(abuf.len()).min(alen);
                if let Some(slice) = abuf.get_mut(..naddr) {
                    host_sockaddr_to_darwin(slice);
                    guest_write(msg_name, slice);
                }
                // Update msg_namelen in guest msghdr.
                guest_write_u32(namelen_addr, u32::try_from(naddr).unwrap_or(0));
                Ok(n)
            }
            Err(e) => Err(e),
        }
    } else {
        host::recvfrom(hfd, &mut buf, flags, None).map(|(n, _)| n)
    };

    match result {
        Ok(n) => {
            let data = buf.get(..n).unwrap_or(&[]);
            match scatter_iov(msg_iov, msg_iovlen, data) {
                Ok(_) => {
                    net_log(&format!("recvmsg -> n={n}"));
                    SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
                }
                Err(e) => SyscallResult::err(name, e),
            }
        }
        Err(e) => {
            net_log(&format!("recvmsg err={e}"));
            SyscallResult::err(name, host_errno_to_darwin(e))
        }
    }
}

/// Darwin `struct pollfd` matches Linux: `{ int fd; short events; short revents; }`.
pub(crate) fn handle_poll(args: SyscallArgs) -> SyscallResult {
    let name = "poll";
    let nfds = reg_as_i32(args.x1);
    if nfds < 0 {
        return SyscallResult::err(name, EINVAL);
    }
    let timeout = reg_as_i32(args.x2);
    net_log(&format!("poll nfds={nfds} timeout={timeout}"));
    if nfds == 0 {
        return match host::poll(&mut [], timeout) {
            Ok(n) => SyscallResult::ok(name, u64::try_from(n).unwrap_or(0)),
            Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
        };
    }
    let Ok(n_us) = usize::try_from(nfds) else {
        return SyscallResult::err(name, EINVAL);
    };
    let bytes = n_us.saturating_mul(8);
    if args.x0 == 0 || !registry_check_range(args.x0, bytes, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let guest = guest_slice_mut(args.x0, bytes);
    let mut host_fds = Vec::with_capacity(n_us);
    let mut guest_fds = Vec::with_capacity(n_us);
    for i in 0..n_us {
        let off = i.saturating_mul(8);
        let gfd_bytes = guest.get(off..off.saturating_add(4)).unwrap_or(&[0; 4][..]);
        let gfd = i32::from_le_bytes(gfd_bytes.try_into().unwrap_or([0; 4]));
        let ev_bytes = guest
            .get(off.saturating_add(4)..off.saturating_add(6))
            .unwrap_or(&[0; 2][..]);
        let events = i16::from_le_bytes(ev_bytes.try_into().unwrap_or([0; 2]));
        let host_fd = guest_to_host_fd(u64::from(gfd.cast_unsigned())).unwrap_or(-1);
        net_log(&format!(
            "poll[{i}] gfd={gfd} hfd={host_fd} events={events:#x}"
        ));
        guest_fds.push(gfd);
        host_fds.push(libc::pollfd {
            fd: host_fd,
            events,
            revents: 0,
        });
    }
    match host::poll(&mut host_fds, timeout) {
        Ok(n) => {
            for (i, h) in host_fds.iter().enumerate() {
                let off = i.saturating_mul(8).saturating_add(6);
                let rev = h.revents.to_le_bytes();
                if let Some(slot) = guest.get_mut(off) {
                    *slot = *rev.first().unwrap_or(&0);
                }
                if let Some(slot) = guest.get_mut(off.saturating_add(1)) {
                    *slot = *rev.get(1).unwrap_or(&0);
                }
                if h.revents != 0 {
                    net_log(&format!(
                        "poll revents gfd={} rev={:#x}",
                        guest_fds.get(i).copied().unwrap_or(-1),
                        h.revents
                    ));
                }
            }
            net_log(&format!("poll -> n={n}"));
            SyscallResult::ok(name, u64::try_from(n).unwrap_or(0))
        }
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

/// Minimal `select` via `poll` (guest FDs are not host FDs).
pub(crate) fn handle_select(args: SyscallArgs) -> SyscallResult {
    let name = "select";
    let nfds = reg_as_i32(args.x0);
    net_log(&format!("select nfds={nfds}"));
    if nfds < 0 {
        return SyscallResult::err(name, EINVAL);
    }
    let timeout_ms = timeval_to_ms(args.x4);
    if nfds == 0 {
        return match host::poll(&mut [], timeout_ms) {
            Ok(n) => SyscallResult::ok(name, u64::try_from(n).unwrap_or(0)),
            Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
        };
    }

    let set_bytes = usize::try_from(nfds)
        .unwrap_or(0)
        .saturating_add(31)
        .saturating_div(32)
        .saturating_mul(4);
    let read_bits = read_fdset(args.x1, set_bytes);
    let write_bits = read_fdset(args.x2, set_bytes);
    let except_bits = read_fdset(args.x3, set_bytes);

    let mut pollfds = Vec::new();
    let mut map: Vec<(i32, i16)> = Vec::new();
    for g in 0..nfds {
        let mut ev: i16 = 0;
        if bit_set(&read_bits, g) {
            ev |= libc::POLLIN;
        }
        if bit_set(&write_bits, g) {
            ev |= libc::POLLOUT;
        }
        if bit_set(&except_bits, g) {
            ev |= libc::POLLPRI;
        }
        if ev == 0 {
            continue;
        }
        let host_fd = guest_to_host_fd(u64::from(g.cast_unsigned())).unwrap_or(-1);
        pollfds.push(libc::pollfd {
            fd: host_fd,
            events: ev,
            revents: 0,
        });
        map.push((g, ev));
    }

    match host::poll(&mut pollfds, timeout_ms) {
        Ok(_n) => {
            clear_fdset(args.x1, set_bytes);
            clear_fdset(args.x2, set_bytes);
            clear_fdset(args.x3, set_bytes);
            let mut ready = 0_i32;
            let polhin = libc::POLLIN | libc::POLLHUP | libc::POLLERR;
            let polhout = libc::POLLOUT;
            let polhpri = libc::POLLPRI | libc::POLLERR;
            for (i, h) in pollfds.iter().enumerate() {
                if h.revents == 0 {
                    continue;
                }
                let Some(&(g, _)) = map.get(i) else {
                    continue;
                };
                if h.revents & polhin != 0 && bit_set(&read_bits, g) {
                    set_bit(args.x1, g);
                    ready = ready.saturating_add(1);
                }
                if h.revents & polhout != 0 && bit_set(&write_bits, g) {
                    set_bit(args.x2, g);
                    ready = ready.saturating_add(1);
                }
                if h.revents & polhpri != 0 && bit_set(&except_bits, g) {
                    set_bit(args.x3, g);
                    ready = ready.saturating_add(1);
                }
            }
            SyscallResult::ok(name, u64::try_from(ready).unwrap_or(0))
        }
        Err(e) => SyscallResult::err(name, host_errno_to_darwin(e)),
    }
}

fn read_fdset(ptr: u64, bytes: usize) -> Vec<u8> {
    if ptr == 0 || bytes == 0 || !registry_check_range(ptr, bytes, false) {
        return Vec::new();
    }
    guest_slice(ptr, bytes).to_vec()
}

fn clear_fdset(ptr: u64, bytes: usize) {
    if ptr == 0 || bytes == 0 || !registry_check_range(ptr, bytes, true) {
        return;
    }
    guest_slice_mut(ptr, bytes).fill(0);
}

fn bit_set(bits: &[u8], fd: i32) -> bool {
    if fd < 0 || bits.is_empty() {
        return false;
    }
    let Ok(u) = usize::try_from(fd) else {
        return false;
    };
    let byte = u >> 3;
    let bit = u & 7;
    bits.get(byte).is_some_and(|b| {
        b & (1_u8
            .checked_shl(u32::try_from(bit).unwrap_or(0))
            .unwrap_or(0))
            != 0
    })
}

fn set_bit(ptr: u64, fd: i32) {
    if ptr == 0 || fd < 0 {
        return;
    }
    let Ok(u) = usize::try_from(fd) else {
        return;
    };
    let byte = u >> 3;
    let bit = u & 7;
    let Ok(byte_u64) = u64::try_from(byte) else {
        return;
    };
    let va = ptr.wrapping_add(byte_u64);
    if !registry_check_range(va, 1, true) {
        return;
    }
    let p = guest_slice_mut(va, 1);
    if let Some(slot) = p.first_mut() {
        *slot |= 1_u8
            .checked_shl(u32::try_from(bit).unwrap_or(0))
            .unwrap_or(0);
    }
}

fn timeval_to_ms(ptr: u64) -> i32 {
    if ptr == 0 {
        return -1; // infinite
    }
    if !registry_check_range(ptr, 16, false) {
        return 0;
    }
    // Darwin timeval: time_t (i64) + suseconds_t (i32) + pad → 16 bytes on arm64.
    let sec = i64::from_le_bytes(guest_slice(ptr, 8).try_into().unwrap_or([0; 8]));
    let usec = i32::from_le_bytes(
        guest_slice(ptr.wrapping_add(8), 4)
            .try_into()
            .unwrap_or([0; 4]),
    );
    let ms = sec
        .saturating_mul(1000)
        .saturating_add(i64::from(usec).saturating_div(1000));
    i32::try_from(ms).unwrap_or(i32::MAX)
}
