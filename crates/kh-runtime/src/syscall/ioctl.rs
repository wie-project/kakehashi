//! Darwin `ioctl` (54 / `ioctl_nocancel`) — tty + a few fd ioctls.
#![allow(unsafe_code)]
// zeroed host `termios` / `winsize` before fill
// Flag / `c_cc` tables are applied on Linux; macOS uses native termios.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
//!
//! Guest request numbers and `struct termios` follow public Darwin headers.
//! On Linux the flag bits, `c_cc` indices, and baud encoding differ, so
//! termios is translated. Window size and integer ioctls share layout.

use crate::host;
use crate::mem::registry_check_range;
use crate::process;

use super::common::{
    EBADF, EFAULT, EINVAL, ENOTTY, EPERM, SyscallArgs, SyscallResult, guest_read_i32, guest_write,
    guest_write_u32, reg_as_i32,
};
use super::fd::guest_to_host_fd;

/// Darwin arm64 `struct termios` size (`4*u64 + 20 + pad4 + 2*u64`).
const DARWIN_TERMIOS_LEN: usize = 72;
const DARWIN_WINSIZE_LEN: usize = 8;
const DARWIN_NCCS: usize = 20;

/// Darwin `c_cc` indices (public `sys/termios.h`).
const D_VEOF: usize = 0;
const D_VEOL: usize = 1;
const D_VEOL2: usize = 2;
const D_VERASE: usize = 3;
const D_VWERASE: usize = 4;
const D_VKILL: usize = 5;
const D_VREPRINT: usize = 6;
const D_VINTR: usize = 8;
const D_VQUIT: usize = 9;
const D_VSUSP: usize = 10;
const D_VSTART: usize = 12;
const D_VSTOP: usize = 13;
const D_VLNEXT: usize = 14;
const D_VDISCARD: usize = 15;
const D_VMIN: usize = 16;
const D_VTIME: usize = 17;

const POSIX_VDISABLE: u8 = 0xff;

/// Darwin input flags used by interactive guests.
const D_IGNBRK: u64 = 0x0000_0001;
const D_BRKINT: u64 = 0x0000_0002;
const D_IGNPAR: u64 = 0x0000_0004;
const D_PARMRK: u64 = 0x0000_0008;
const D_INPCK: u64 = 0x0000_0010;
const D_ISTRIP: u64 = 0x0000_0020;
const D_INLCR: u64 = 0x0000_0040;
const D_IGNCR: u64 = 0x0000_0080;
const D_ICRNL: u64 = 0x0000_0100;
const D_IXON: u64 = 0x0000_0200;
const D_IXOFF: u64 = 0x0000_0400;
const D_IXANY: u64 = 0x0000_0800;
const D_IMAXBEL: u64 = 0x0000_2000;
const D_IUTF8: u64 = 0x0000_4000;

const D_OPOST: u64 = 0x0000_0001;
const D_ONLCR: u64 = 0x0000_0002;
const D_OXTABS: u64 = 0x0000_0004;
const D_OCRNL: u64 = 0x0000_0010;
const D_ONOCR: u64 = 0x0000_0020;
const D_ONLRET: u64 = 0x0000_0040;

const D_CSIZE: u64 = 0x0000_0300;
const D_CS5: u64 = 0x0000_0000;
const D_CS6: u64 = 0x0000_0100;
const D_CS7: u64 = 0x0000_0200;
const D_CS8: u64 = 0x0000_0300;
const D_CSTOPB: u64 = 0x0000_0400;
const D_CREAD: u64 = 0x0000_0800;
const D_PARENB: u64 = 0x0000_1000;
const D_PARODD: u64 = 0x0000_2000;
const D_HUPCL: u64 = 0x0000_4000;
const D_CLOCAL: u64 = 0x0000_8000;
const D_CRTSCTS: u64 = 0x0003_0000;

const D_ECHOKE: u64 = 0x0000_0001;
const D_ECHOE: u64 = 0x0000_0002;
const D_ECHOK: u64 = 0x0000_0004;
const D_ECHO: u64 = 0x0000_0008;
const D_ECHONL: u64 = 0x0000_0010;
const D_ECHOPRT: u64 = 0x0000_0020;
const D_ECHOCTL: u64 = 0x0000_0040;
const D_ISIG: u64 = 0x0000_0080;
const D_ICANON: u64 = 0x0000_0100;
const D_IEXTEN: u64 = 0x0000_0400;
const D_EXTPROC: u64 = 0x0000_0800;
const D_TOSTOP: u64 = 0x0040_0000;
const D_FLUSHO: u64 = 0x0080_0000;
const D_PENDIN: u64 = 0x2000_0000;
const D_NOFLSH: u64 = 0x8000_0000;

/// Packed Darwin `struct termios` (arm64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::struct_field_names)] // C field names (`c_iflag`, …)
struct DarwinTermios {
    c_iflag: u64,
    c_oflag: u64,
    c_cflag: u64,
    c_lflag: u64,
    c_cc: [u8; DARWIN_NCCS],
    c_ispeed: u64,
    c_ospeed: u64,
}

impl DarwinTermios {
    fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() < DARWIN_TERMIOS_LEN {
            return None;
        }
        Some(Self {
            c_iflag: u64_at(raw, 0)?,
            c_oflag: u64_at(raw, 8)?,
            c_cflag: u64_at(raw, 16)?,
            c_lflag: u64_at(raw, 24)?,
            c_cc: {
                let mut cc = [0_u8; DARWIN_NCCS];
                let src = raw.get(32..32_usize.saturating_add(DARWIN_NCCS))?;
                cc.copy_from_slice(src);
                cc
            },
            c_ispeed: u64_at(raw, 56)?,
            c_ospeed: u64_at(raw, 64)?,
        })
    }

    fn to_bytes(self) -> [u8; DARWIN_TERMIOS_LEN] {
        let mut out = [0_u8; DARWIN_TERMIOS_LEN];
        put_u64(&mut out, 0, self.c_iflag);
        put_u64(&mut out, 8, self.c_oflag);
        put_u64(&mut out, 16, self.c_cflag);
        put_u64(&mut out, 24, self.c_lflag);
        if let Some(dst) = out.get_mut(32..32_usize.saturating_add(DARWIN_NCCS)) {
            dst.copy_from_slice(&self.c_cc);
        }
        put_u64(&mut out, 56, self.c_ispeed);
        put_u64(&mut out, 64, self.c_ospeed);
        out
    }
}

fn u64_at(raw: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let bytes = raw.get(off..end)?;
    let mut le = [0_u8; 8];
    le.copy_from_slice(bytes);
    Some(u64::from_le_bytes(le))
}

fn put_u64(out: &mut [u8], off: usize, v: u64) {
    let end = off.saturating_add(8);
    if let Some(dst) = out.get_mut(off..end) {
        dst.copy_from_slice(&v.to_le_bytes());
    }
}

/// `ioctl` — fd `x0`, Darwin request `x1`, optional arg pointer `x2`.
pub(crate) fn handle_ioctl(args: SyscallArgs) -> SyscallResult {
    let name = "ioctl";
    let Some(h) = guest_to_host_fd(args.x0) else {
        return SyscallResult::err(name, EBADF);
    };
    let req = u32::try_from(args.x1 & 0xFFFF_FFFF).unwrap_or(0);
    let group = u8::try_from((req >> 8) & 0xff).unwrap_or(0);
    let num = u8::try_from(req & 0xff).unwrap_or(0);
    match (group, num) {
        (b't', 19) => ioctl_get_termios(name, h, args.x2),
        (b't', 20) => ioctl_set_termios(name, h, args.x2, libc::TCSANOW),
        (b't', 21) => ioctl_set_termios(name, h, args.x2, libc::TCSADRAIN),
        (b't', 22) => ioctl_set_termios(name, h, args.x2, libc::TCSAFLUSH),
        (b't', 104) => ioctl_get_winsize(name, h, args.x2),
        (b't', 103) => ioctl_set_winsize(name, h, args.x2),
        (b't', 119) => ioctl_get_int(name, h, args.x2, libc::TIOCGPGRP),
        (b't', 118) => ioctl_set_int(name, h, args.x2, libc::TIOCSPGRP),
        (b't', 94) => match host::tcdrain(h) {
            Ok(()) => SyscallResult::ok(name, 0),
            Err(e) => SyscallResult::err(name, map_host_errno(e)),
        },
        (b't', 16) => ioctl_flush(name, h, args.x2),
        (b't', 115) => ioctl_get_int(name, h, args.x2, libc::TIOCOUTQ),
        (b'f', 127) => ioctl_get_int(name, h, args.x2, libc::FIONREAD),
        (b'f', 126) => ioctl_fionbio(name, h, args.x0, args.x2),
        (b'f', 1) => match host::fcntl_set(h, libc::F_SETFD, libc::FD_CLOEXEC) {
            Some(_) => SyscallResult::ok(name, 0),
            None => SyscallResult::err(name, EBADF),
        },
        (b'f', 2) => match host::fcntl_set(h, libc::F_SETFD, 0) {
            Some(_) => SyscallResult::ok(name, 0),
            None => SyscallResult::err(name, EBADF),
        },
        _ => {
            tracing::debug!(req, group, num, "ioctl ENOTTY (unmapped)");
            SyscallResult::err(name, ENOTTY)
        }
    }
}

fn ioctl_get_termios(name: &'static str, h: i32, buf: u64) -> SyscallResult {
    if !registry_check_range(buf, DARWIN_TERMIOS_LEN, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let host_t = match host::tcgetattr(h) {
        Ok(t) => t,
        Err(e) => return SyscallResult::err(name, map_host_errno(e)),
    };
    let darwin = host_to_darwin_termios(&host_t);
    guest_write(buf, &darwin.to_bytes());
    SyscallResult::ok(name, 0)
}

fn ioctl_set_termios(name: &'static str, h: i32, buf: u64, actions: libc::c_int) -> SyscallResult {
    if !registry_check_range(buf, DARWIN_TERMIOS_LEN, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let raw = super::common::guest_slice(buf, DARWIN_TERMIOS_LEN);
    let Some(darwin) = DarwinTermios::from_bytes(raw) else {
        return SyscallResult::err(name, EFAULT);
    };
    let host_t = darwin_to_host_termios(&darwin);
    match host::tcsetattr(h, actions, &host_t) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) => SyscallResult::err(name, map_host_errno(e)),
    }
}

fn ioctl_get_winsize(name: &'static str, h: i32, buf: u64) -> SyscallResult {
    if !registry_check_range(buf, DARWIN_WINSIZE_LEN, true) {
        return SyscallResult::err(name, EFAULT);
    }
    match host::tiocgwinsz(h) {
        Ok(ws) => {
            let mut raw = [0_u8; DARWIN_WINSIZE_LEN];
            put_u16(&mut raw, 0, ws.ws_row);
            put_u16(&mut raw, 2, ws.ws_col);
            put_u16(&mut raw, 4, ws.ws_xpixel);
            put_u16(&mut raw, 6, ws.ws_ypixel);
            guest_write(buf, &raw);
            SyscallResult::ok(name, 0)
        }
        Err(e) => SyscallResult::err(name, map_host_errno(e)),
    }
}

fn ioctl_set_winsize(name: &'static str, h: i32, buf: u64) -> SyscallResult {
    if !registry_check_range(buf, DARWIN_WINSIZE_LEN, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let raw = super::common::guest_slice(buf, DARWIN_WINSIZE_LEN);
    let ws = libc::winsize {
        ws_row: u16_at(raw, 0).unwrap_or(0),
        ws_col: u16_at(raw, 2).unwrap_or(0),
        ws_xpixel: u16_at(raw, 4).unwrap_or(0),
        ws_ypixel: u16_at(raw, 6).unwrap_or(0),
    };
    match host::tiocswinsz(h, &ws) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) => SyscallResult::err(name, map_host_errno(e)),
    }
}

fn ioctl_get_int(name: &'static str, h: i32, buf: u64, host_req: libc::c_ulong) -> SyscallResult {
    if !registry_check_range(buf, 4, true) {
        return SyscallResult::err(name, EFAULT);
    }
    match host::ioctl_get_int(h, host_req) {
        Ok(v) => {
            guest_write_u32(buf, u32::from_ne_bytes(v.to_ne_bytes()));
            SyscallResult::ok(name, 0)
        }
        Err(e) => SyscallResult::err(name, map_host_errno(e)),
    }
}

fn ioctl_set_int(name: &'static str, h: i32, buf: u64, host_req: libc::c_ulong) -> SyscallResult {
    if !registry_check_range(buf, 4, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let v = guest_read_i32(buf);
    match host::ioctl_set_int(h, host_req, v) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) => SyscallResult::err(name, map_host_errno(e)),
    }
}

fn ioctl_flush(name: &'static str, h: i32, buf: u64) -> SyscallResult {
    let which = if buf == 0 {
        0
    } else if registry_check_range(buf, 4, false) {
        guest_read_i32(buf)
    } else {
        return SyscallResult::err(name, EFAULT);
    };
    let host_q = match which {
        1 => libc::TCIFLUSH,
        2 => libc::TCOFLUSH,
        _ => libc::TCIOFLUSH,
    };
    match host::tcflush(h, host_q) {
        Ok(()) => SyscallResult::ok(name, 0),
        Err(e) => SyscallResult::err(name, map_host_errno(e)),
    }
}

fn ioctl_fionbio(name: &'static str, h: i32, x0: u64, buf: u64) -> SyscallResult {
    if !registry_check_range(buf, 4, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let on = guest_read_i32(buf) != 0;
    let gfd = reg_as_i32(x0);
    process::fd_set_guest_nonblock(gfd, on);
    let Some(cur) = host::fcntl_get(h, libc::F_GETFL) else {
        return SyscallResult::err(name, EBADF);
    };
    let mut fl = cur;
    if on {
        fl |= libc::O_NONBLOCK;
    } else {
        fl &= !libc::O_NONBLOCK;
    }
    match host::fcntl_set(h, libc::F_SETFL, fl) {
        Some(_) => SyscallResult::ok(name, 0),
        None => SyscallResult::err(name, EBADF),
    }
}

fn put_u16(out: &mut [u8], off: usize, v: u16) {
    let end = off.saturating_add(2);
    if let Some(dst) = out.get_mut(off..end) {
        dst.copy_from_slice(&v.to_le_bytes());
    }
}

fn u16_at(raw: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let bytes = raw.get(off..end)?;
    let mut le = [0_u8; 2];
    le.copy_from_slice(bytes);
    Some(u16::from_le_bytes(le))
}

fn map_host_errno(e: i32) -> i64 {
    if e == libc::EBADF {
        EBADF
    } else if e == libc::EFAULT {
        EFAULT
    } else if e == libc::EINVAL {
        EINVAL
    } else if e == libc::ENOTTY {
        ENOTTY
    } else if e == libc::EPERM {
        EPERM
    } else {
        ENOTTY
    }
}

fn map_bits(src: u64, pairs: &[(u64, u64)]) -> u64 {
    let mut out = 0_u64;
    for &(from, to) in pairs {
        if src & from != 0 {
            out |= to;
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn host_flag(v: libc::tcflag_t) -> u64 {
    u64::from(v)
}

#[cfg(target_os = "linux")]
fn to_tcflag(v: u64) -> libc::tcflag_t {
    libc::tcflag_t::try_from(v).unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn host_to_darwin_termios(host: &libc::termios) -> DarwinTermios {
    let iflag = map_bits(
        host_flag(host.c_iflag),
        &[
            (host_flag(libc::IGNBRK), D_IGNBRK),
            (host_flag(libc::BRKINT), D_BRKINT),
            (host_flag(libc::IGNPAR), D_IGNPAR),
            (host_flag(libc::PARMRK), D_PARMRK),
            (host_flag(libc::INPCK), D_INPCK),
            (host_flag(libc::ISTRIP), D_ISTRIP),
            (host_flag(libc::INLCR), D_INLCR),
            (host_flag(libc::IGNCR), D_IGNCR),
            (host_flag(libc::ICRNL), D_ICRNL),
            (host_flag(libc::IXON), D_IXON),
            (host_flag(libc::IXOFF), D_IXOFF),
            (host_flag(libc::IXANY), D_IXANY),
            (host_flag(libc::IMAXBEL), D_IMAXBEL),
            (host_flag(libc::IUTF8), D_IUTF8),
        ],
    );
    let oflag = map_bits(
        host_flag(host.c_oflag),
        &[
            (host_flag(libc::OPOST), D_OPOST),
            (host_flag(libc::ONLCR), D_ONLCR),
            (host_flag(libc::OCRNL), D_OCRNL),
            (host_flag(libc::ONOCR), D_ONOCR),
            (host_flag(libc::ONLRET), D_ONLRET),
            (host_flag(libc::TAB3), D_OXTABS),
        ],
    );
    let mut cflag = map_bits(
        host_flag(host.c_cflag),
        &[
            (host_flag(libc::CSTOPB), D_CSTOPB),
            (host_flag(libc::CREAD), D_CREAD),
            (host_flag(libc::PARENB), D_PARENB),
            (host_flag(libc::PARODD), D_PARODD),
            (host_flag(libc::HUPCL), D_HUPCL),
            (host_flag(libc::CLOCAL), D_CLOCAL),
            (host_flag(libc::CRTSCTS), D_CRTSCTS),
        ],
    );
    let csize = host_flag(host.c_cflag) & host_flag(libc::CSIZE);
    cflag |= if csize == host_flag(libc::CS6) {
        D_CS6
    } else if csize == host_flag(libc::CS7) {
        D_CS7
    } else if csize == host_flag(libc::CS8) {
        D_CS8
    } else {
        D_CS5
    };
    let lflag = map_bits(
        host_flag(host.c_lflag),
        &[
            (host_flag(libc::ECHOKE), D_ECHOKE),
            (host_flag(libc::ECHOE), D_ECHOE),
            (host_flag(libc::ECHOK), D_ECHOK),
            (host_flag(libc::ECHO), D_ECHO),
            (host_flag(libc::ECHONL), D_ECHONL),
            (host_flag(libc::ECHOPRT), D_ECHOPRT),
            (host_flag(libc::ECHOCTL), D_ECHOCTL),
            (host_flag(libc::ISIG), D_ISIG),
            (host_flag(libc::ICANON), D_ICANON),
            (host_flag(libc::IEXTEN), D_IEXTEN),
            (host_flag(libc::EXTPROC), D_EXTPROC),
            (host_flag(libc::TOSTOP), D_TOSTOP),
            (host_flag(libc::FLUSHO), D_FLUSHO),
            (host_flag(libc::PENDIN), D_PENDIN),
            (host_flag(libc::NOFLSH), D_NOFLSH),
        ],
    );
    let mut cc = [POSIX_VDISABLE; DARWIN_NCCS];
    copy_cc(host.c_cc.as_ref(), libc::VEOF, &mut cc, D_VEOF);
    copy_cc(host.c_cc.as_ref(), libc::VEOL, &mut cc, D_VEOL);
    copy_cc(host.c_cc.as_ref(), libc::VEOL2, &mut cc, D_VEOL2);
    copy_cc(host.c_cc.as_ref(), libc::VERASE, &mut cc, D_VERASE);
    copy_cc(host.c_cc.as_ref(), libc::VWERASE, &mut cc, D_VWERASE);
    copy_cc(host.c_cc.as_ref(), libc::VKILL, &mut cc, D_VKILL);
    copy_cc(host.c_cc.as_ref(), libc::VREPRINT, &mut cc, D_VREPRINT);
    copy_cc(host.c_cc.as_ref(), libc::VINTR, &mut cc, D_VINTR);
    copy_cc(host.c_cc.as_ref(), libc::VQUIT, &mut cc, D_VQUIT);
    copy_cc(host.c_cc.as_ref(), libc::VSUSP, &mut cc, D_VSUSP);
    copy_cc(host.c_cc.as_ref(), libc::VSTART, &mut cc, D_VSTART);
    copy_cc(host.c_cc.as_ref(), libc::VSTOP, &mut cc, D_VSTOP);
    copy_cc(host.c_cc.as_ref(), libc::VLNEXT, &mut cc, D_VLNEXT);
    copy_cc(host.c_cc.as_ref(), libc::VDISCARD, &mut cc, D_VDISCARD);
    copy_cc(host.c_cc.as_ref(), libc::VMIN, &mut cc, D_VMIN);
    copy_cc(host.c_cc.as_ref(), libc::VTIME, &mut cc, D_VTIME);
    DarwinTermios {
        c_iflag: iflag,
        c_oflag: oflag,
        c_cflag: cflag,
        c_lflag: lflag,
        c_cc: cc,
        c_ispeed: linux_speed_to_baud(host::cfgetispeed(host)),
        c_ospeed: linux_speed_to_baud(host::cfgetospeed(host)),
    }
}

#[cfg(not(target_os = "linux"))]
fn host_to_darwin_termios(host: &libc::termios) -> DarwinTermios {
    let mut cc = [POSIX_VDISABLE; DARWIN_NCCS];
    for (i, slot) in cc.iter_mut().enumerate() {
        if let Some(v) = host.c_cc.get(i) {
            *slot = *v;
        }
    }
    DarwinTermios {
        c_iflag: host.c_iflag,
        c_oflag: host.c_oflag,
        c_cflag: host.c_cflag,
        c_lflag: host.c_lflag,
        c_cc: cc,
        c_ispeed: host.c_ispeed,
        c_ospeed: host.c_ospeed,
    }
}

#[cfg(target_os = "linux")]
fn darwin_to_host_termios(d: &DarwinTermios) -> libc::termios {
    let mut host: libc::termios = unsafe { core::mem::zeroed() };
    host.c_iflag = to_tcflag(map_bits(
        d.c_iflag,
        &[
            (D_IGNBRK, host_flag(libc::IGNBRK)),
            (D_BRKINT, host_flag(libc::BRKINT)),
            (D_IGNPAR, host_flag(libc::IGNPAR)),
            (D_PARMRK, host_flag(libc::PARMRK)),
            (D_INPCK, host_flag(libc::INPCK)),
            (D_ISTRIP, host_flag(libc::ISTRIP)),
            (D_INLCR, host_flag(libc::INLCR)),
            (D_IGNCR, host_flag(libc::IGNCR)),
            (D_ICRNL, host_flag(libc::ICRNL)),
            (D_IXON, host_flag(libc::IXON)),
            (D_IXOFF, host_flag(libc::IXOFF)),
            (D_IXANY, host_flag(libc::IXANY)),
            (D_IMAXBEL, host_flag(libc::IMAXBEL)),
            (D_IUTF8, host_flag(libc::IUTF8)),
        ],
    ));
    host.c_oflag = to_tcflag(map_bits(
        d.c_oflag,
        &[
            (D_OPOST, host_flag(libc::OPOST)),
            (D_ONLCR, host_flag(libc::ONLCR)),
            (D_OCRNL, host_flag(libc::OCRNL)),
            (D_ONOCR, host_flag(libc::ONOCR)),
            (D_ONLRET, host_flag(libc::ONLRET)),
            (D_OXTABS, host_flag(libc::TAB3)),
        ],
    ));
    let mut cflag = map_bits(
        d.c_cflag,
        &[
            (D_CSTOPB, host_flag(libc::CSTOPB)),
            (D_CREAD, host_flag(libc::CREAD)),
            (D_PARENB, host_flag(libc::PARENB)),
            (D_PARODD, host_flag(libc::PARODD)),
            (D_HUPCL, host_flag(libc::HUPCL)),
            (D_CLOCAL, host_flag(libc::CLOCAL)),
            (D_CRTSCTS, host_flag(libc::CRTSCTS)),
        ],
    );
    cflag |= match d.c_cflag & D_CSIZE {
        D_CS6 => host_flag(libc::CS6),
        D_CS7 => host_flag(libc::CS7),
        D_CS8 => host_flag(libc::CS8),
        _ => host_flag(libc::CS5),
    };
    host.c_cflag = to_tcflag(cflag);
    host.c_lflag = to_tcflag(map_bits(
        d.c_lflag,
        &[
            (D_ECHOKE, host_flag(libc::ECHOKE)),
            (D_ECHOE, host_flag(libc::ECHOE)),
            (D_ECHOK, host_flag(libc::ECHOK)),
            (D_ECHO, host_flag(libc::ECHO)),
            (D_ECHONL, host_flag(libc::ECHONL)),
            (D_ECHOPRT, host_flag(libc::ECHOPRT)),
            (D_ECHOCTL, host_flag(libc::ECHOCTL)),
            (D_ISIG, host_flag(libc::ISIG)),
            (D_ICANON, host_flag(libc::ICANON)),
            (D_IEXTEN, host_flag(libc::IEXTEN)),
            (D_EXTPROC, host_flag(libc::EXTPROC)),
            (D_TOSTOP, host_flag(libc::TOSTOP)),
            (D_FLUSHO, host_flag(libc::FLUSHO)),
            (D_PENDIN, host_flag(libc::PENDIN)),
            (D_NOFLSH, host_flag(libc::NOFLSH)),
        ],
    ));
    host.c_line = 0;
    set_cc(host.c_cc.as_mut(), libc::VEOF, d.c_cc, D_VEOF);
    set_cc(host.c_cc.as_mut(), libc::VEOL, d.c_cc, D_VEOL);
    set_cc(host.c_cc.as_mut(), libc::VEOL2, d.c_cc, D_VEOL2);
    set_cc(host.c_cc.as_mut(), libc::VERASE, d.c_cc, D_VERASE);
    set_cc(host.c_cc.as_mut(), libc::VWERASE, d.c_cc, D_VWERASE);
    set_cc(host.c_cc.as_mut(), libc::VKILL, d.c_cc, D_VKILL);
    set_cc(host.c_cc.as_mut(), libc::VREPRINT, d.c_cc, D_VREPRINT);
    set_cc(host.c_cc.as_mut(), libc::VINTR, d.c_cc, D_VINTR);
    set_cc(host.c_cc.as_mut(), libc::VQUIT, d.c_cc, D_VQUIT);
    set_cc(host.c_cc.as_mut(), libc::VSUSP, d.c_cc, D_VSUSP);
    set_cc(host.c_cc.as_mut(), libc::VSTART, d.c_cc, D_VSTART);
    set_cc(host.c_cc.as_mut(), libc::VSTOP, d.c_cc, D_VSTOP);
    set_cc(host.c_cc.as_mut(), libc::VLNEXT, d.c_cc, D_VLNEXT);
    set_cc(host.c_cc.as_mut(), libc::VDISCARD, d.c_cc, D_VDISCARD);
    set_cc(host.c_cc.as_mut(), libc::VMIN, d.c_cc, D_VMIN);
    set_cc(host.c_cc.as_mut(), libc::VTIME, d.c_cc, D_VTIME);
    let _ = host::cfsetispeed(&mut host, baud_to_linux_speed(d.c_ispeed));
    let _ = host::cfsetospeed(&mut host, baud_to_linux_speed(d.c_ospeed));
    host
}

#[cfg(not(target_os = "linux"))]
fn darwin_to_host_termios(d: &DarwinTermios) -> libc::termios {
    let mut host: libc::termios = unsafe { core::mem::zeroed() };
    host.c_iflag = d.c_iflag;
    host.c_oflag = d.c_oflag;
    host.c_cflag = d.c_cflag;
    host.c_lflag = d.c_lflag;
    for (i, slot) in host.c_cc.iter_mut().enumerate() {
        if let Some(v) = d.c_cc.get(i) {
            *slot = *v;
        }
    }
    host.c_ispeed = d.c_ispeed;
    host.c_ospeed = d.c_ospeed;
    host
}

#[cfg(target_os = "linux")]
fn copy_cc(src: &[u8], src_idx: usize, dst: &mut [u8], dst_idx: usize) {
    if let (Some(v), Some(slot)) = (src.get(src_idx), dst.get_mut(dst_idx)) {
        *slot = *v;
    }
}

#[cfg(target_os = "linux")]
fn set_cc(dst: &mut [u8], dst_idx: usize, src: [u8; DARWIN_NCCS], src_idx: usize) {
    if let (Some(v), Some(slot)) = (src.get(src_idx), dst.get_mut(dst_idx)) {
        *slot = *v;
    }
}

#[cfg(target_os = "linux")]
fn linux_speed_to_baud(speed: libc::speed_t) -> u64 {
    #[allow(clippy::unreadable_literal)]
    match speed {
        libc::B0 => 0,
        libc::B50 => 50,
        libc::B75 => 75,
        libc::B110 => 110,
        libc::B134 => 134,
        libc::B150 => 150,
        libc::B200 => 200,
        libc::B300 => 300,
        libc::B600 => 600,
        libc::B1200 => 1200,
        libc::B1800 => 1800,
        libc::B2400 => 2400,
        libc::B4800 => 4800,
        libc::B9600 => 9600,
        libc::B19200 => 19_200,
        libc::B38400 => 38_400,
        libc::B57600 => 57_600,
        libc::B115200 => 115_200,
        libc::B230400 => 230_400,
        other => u64::from(other),
    }
}

#[cfg(target_os = "linux")]
fn baud_to_linux_speed(baud: u64) -> libc::speed_t {
    match baud {
        0 => libc::B0,
        50 => libc::B50,
        75 => libc::B75,
        110 => libc::B110,
        134 => libc::B134,
        150 => libc::B150,
        200 => libc::B200,
        300 => libc::B300,
        600 => libc::B600,
        1200 => libc::B1200,
        1800 => libc::B1800,
        2400 => libc::B2400,
        4800 => libc::B4800,
        9600 => libc::B9600,
        19_200 => libc::B19200,
        38_400 => libc::B38400,
        57_600 => libc::B57600,
        115_200 => libc::B115200,
        230_400 => libc::B230400,
        other => libc::speed_t::try_from(other).unwrap_or(libc::B9600),
    }
}

impl DarwinTermios {
    #[cfg(test)]
    fn raw_roundtrip(self) -> bool {
        Self::from_bytes(&self.to_bytes()) == Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn darwin_termios_size_and_roundtrip() {
        let t = DarwinTermios {
            c_iflag: D_ICRNL | D_IXON,
            c_oflag: D_OPOST | D_ONLCR,
            c_cflag: D_CS8 | D_CREAD | D_CLOCAL,
            c_lflag: D_ISIG | D_ICANON | D_ECHO | D_ECHOE | D_IEXTEN,
            c_cc: {
                let mut cc = [POSIX_VDISABLE; DARWIN_NCCS];
                if let Some(s) = cc.get_mut(D_VMIN) {
                    *s = 1;
                }
                if let Some(s) = cc.get_mut(D_VINTR) {
                    *s = 0x03;
                }
                cc
            },
            c_ispeed: 9600,
            c_ospeed: 9600,
        };
        assert!(t.raw_roundtrip());
        assert_eq!(t.to_bytes().len(), 72);
    }

    #[test]
    fn ioctl_group_num_tty_geta() {
        // `_IOR('t', 19, 72)` = 0x40487413
        let req: u32 = 0x4048_7413;
        assert_eq!(u8::try_from((req >> 8) & 0xff).unwrap_or(0), b't');
        assert_eq!(u8::try_from(req & 0xff).unwrap_or(0), 19);
    }

    #[test]
    fn ioctl_group_num_winsz() {
        let req: u32 = 0x4008_7468;
        assert_eq!(u8::try_from((req >> 8) & 0xff).unwrap_or(0), b't');
        assert_eq!(u8::try_from(req & 0xff).unwrap_or(0), 104);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn iflag_ixon_not_confused_with_iuclc() {
        let d = DarwinTermios {
            c_iflag: D_IXON | D_ICRNL,
            c_oflag: 0,
            c_cflag: D_CS8,
            c_lflag: 0,
            c_cc: [POSIX_VDISABLE; DARWIN_NCCS],
            c_ispeed: 9600,
            c_ospeed: 9600,
        };
        let host = darwin_to_host_termios(&d);
        assert_eq!(
            host_flag(host.c_iflag) & host_flag(libc::IXON),
            host_flag(libc::IXON)
        );
        assert_eq!(
            host_flag(host.c_iflag) & host_flag(libc::ICRNL),
            host_flag(libc::ICRNL)
        );
        let back = host_to_darwin_termios(&host);
        assert_eq!(back.c_iflag & D_IXON, D_IXON);
        assert_eq!(back.c_iflag & D_ICRNL, D_ICRNL);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lflag_echo_icanon_roundtrip() {
        let d = DarwinTermios {
            c_iflag: 0,
            c_oflag: D_OPOST | D_ONLCR,
            c_cflag: D_CS8 | D_CREAD,
            c_lflag: D_ECHO | D_ICANON | D_ISIG | D_IEXTEN,
            c_cc: [POSIX_VDISABLE; DARWIN_NCCS],
            c_ispeed: 115_200,
            c_ospeed: 115_200,
        };
        let host = darwin_to_host_termios(&d);
        let back = host_to_darwin_termios(&host);
        assert_eq!(back.c_lflag & D_ECHO, D_ECHO);
        assert_eq!(back.c_lflag & D_ICANON, D_ICANON);
        assert_eq!(back.c_lflag & D_ISIG, D_ISIG);
        assert_eq!(back.c_oflag & D_ONLCR, D_ONLCR);
        assert_eq!(back.c_ispeed, 115_200);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn speed_tables() {
        assert_eq!(linux_speed_to_baud(libc::B9600), 9600);
        assert_eq!(baud_to_linux_speed(9600), libc::B9600);
        assert_eq!(baud_to_linux_speed(115_200), libc::B115200);
    }
}
