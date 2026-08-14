//! DNS name helpers (getnameinfo soft / hostent).

#![allow(unused_imports, dead_code)]
#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::bool_to_int_with_if,
    clippy::manual_c_str_literals,
    clippy::manual_is_ascii_check,
    clippy::many_single_char_names,
    clippy::used_underscore_binding
)]

use core::ffi::{c_char, c_int, c_void};

use crate::dylib::libsystem_c::stdio::strlen;
use crate::dylib::libsystem_c::string::{strcmp, strcpy};
use crate::kh_core::errno;
use crate::kh_core::heap::{free, malloc};

const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const ENOSYS: i32 = 78;
const EAI_NONAME: i32 = 8;
const EAI_FAMILY: i32 = 1;

/// C `getnameinfo` → numeric host/service when possible.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getnameinfo(
    sa: *const c_void,
    salen: u32,
    host: *mut c_char,
    hostlen: u32,
    serv: *mut c_char,
    servlen: u32,
    flags: c_int,
) -> c_int {
    let _ = flags;
    if sa.is_null() || salen < 2 {
        return EAI_FAMILY;
    }
    let family = unsafe { sa.cast::<u8>().add(1).read() }; // Darwin sa_family at byte 1
    if family == 2 && salen >= 8 {
        // AF_INET sockaddr_in: port @2, addr @4
        let base = sa.cast::<u8>();
        if !host.is_null() && hostlen > 0 {
            let a = unsafe {
                [
                    base.add(4).read(),
                    base.add(5).read(),
                    base.add(6).read(),
                    base.add(7).read(),
                ]
            };
            write_ipv4(host, hostlen, a);
        }
        if !serv.is_null() && servlen > 0 {
            let port = u16::from_be_bytes(unsafe { [base.add(2).read(), base.add(3).read()] });
            write_u16_dec(serv, servlen, port);
        }
        return 0;
    }
    EAI_NONAME
}

fn write_ipv4(dst: *mut c_char, dstlen: u32, a: [u8; 4]) {
    let mut buf = [0_u8; 16];
    let mut o = 0_usize;
    for (i, b) in a.iter().enumerate() {
        if i > 0 {
            if let Some(s) = buf.get_mut(o) {
                *s = b'.';
            }
            o = o.saturating_add(1);
        }
        let mut v = u32::from(*b);
        let mut tmp = [0_u8; 3];
        let mut t = 0_usize;
        if v == 0 {
            tmp[0] = b'0';
            t = 1;
        } else {
            while v > 0 && t < 3 {
                tmp[t] = b'0' + u8::try_from(v % 10).unwrap_or(0);
                v /= 10;
                t = t.saturating_add(1);
            }
        }
        while t > 0 {
            t = t.saturating_sub(1);
            if let Some(s) = buf.get_mut(o) {
                *s = tmp[t];
            }
            o = o.saturating_add(1);
        }
    }
    let max = usize::try_from(dstlen).unwrap_or(0);
    if max == 0 {
        return;
    }
    let n = o.min(max.saturating_sub(1));
    unsafe {
        let mut i = 0_usize;
        while i < n {
            dst.add(i)
                .write(buf.get(i).copied().unwrap_or(0).cast_signed());
            i = i.saturating_add(1);
        }
        dst.add(n).write(0);
    }
}

fn write_u16_dec(dst: *mut c_char, dstlen: u32, mut v: u16) {
    let mut tmp = [0_u8; 5];
    let mut t = 0_usize;
    if v == 0 {
        tmp[0] = b'0';
        t = 1;
    } else {
        while v > 0 && t < 5 {
            tmp[t] = b'0' + u8::try_from(v % 10).unwrap_or(0);
            v /= 10;
            t = t.saturating_add(1);
        }
    }
    let max = usize::try_from(dstlen).unwrap_or(0);
    if max == 0 {
        return;
    }
    let mut o = 0_usize;
    while t > 0 && o + 1 < max {
        t = t.saturating_sub(1);
        unsafe {
            dst.add(o).write(tmp[t].cast_signed());
        }
        o = o.saturating_add(1);
    }
    unsafe {
        dst.add(o).write(0);
    }
}

/// C `gethostbyname` → null (prefer getaddrinfo).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn gethostbyname(_name: *const c_char) -> *mut c_void {
    core::ptr::null_mut()
}

/// Static servent for common services.
#[repr(C)]
struct Servent {
    name: *const c_char,
    aliases: *mut *mut c_char,
    port: c_int, // network byte order
    proto: *const c_char,
}

static mut NULL_ALIAS: *mut c_char = core::ptr::null_mut();
static mut SERVENT: Servent = Servent {
    name: core::ptr::null(),
    aliases: core::ptr::null_mut(),
    port: 0,
    proto: core::ptr::null(),
};
static mut SERV_NAME: [u8; 16] = [0; 16];
static mut SERV_PROTO: [u8; 8] = [0; 8];

unsafe fn fill_servent(name: &[u8], port_host: u16, proto: &[u8]) -> *mut Servent {
    unsafe {
        SERVENT.aliases = core::ptr::addr_of_mut!(NULL_ALIAS);
        SERVENT.port = c_int::from(port_host.to_be());
        let mut i = 0_usize;
        while i < 15 {
            let b = name.get(i).copied().unwrap_or(0);
            SERV_NAME[i] = b;
            if b == 0 {
                break;
            }
            i = i.saturating_add(1);
        }
        SERV_NAME[15] = 0;
        i = 0;
        while i < 7 {
            let b = proto.get(i).copied().unwrap_or(0);
            SERV_PROTO[i] = b;
            if b == 0 {
                break;
            }
            i = i.saturating_add(1);
        }
        SERV_PROTO[7] = 0;
        SERVENT.name = core::ptr::addr_of!(SERV_NAME).cast();
        SERVENT.proto = core::ptr::addr_of!(SERV_PROTO).cast();
        core::ptr::addr_of_mut!(SERVENT)
    }
}

/// C `getservbyname`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getservbyname(
    name: *const c_char,
    proto: *const c_char,
) -> *mut c_void {
    if name.is_null() {
        return core::ptr::null_mut();
    }
    let p = if proto.is_null() {
        b"tcp\0".as_ptr()
    } else {
        proto.cast()
    };
    let n = unsafe {
        if strcmp(name, c"http".as_ptr()) == 0 {
            Some((b"http\0".as_slice(), 80_u16))
        } else if strcmp(name, c"https".as_ptr()) == 0 {
            Some((b"https\0".as_slice(), 443))
        } else if strcmp(name, c"ftp".as_ptr()) == 0 {
            Some((b"ftp\0".as_slice(), 21))
        } else if strcmp(name, c"ssh".as_ptr()) == 0 {
            Some((b"ssh\0".as_slice(), 22))
        } else if strcmp(name, c"smtp".as_ptr()) == 0 {
            Some((b"smtp\0".as_slice(), 25))
        } else {
            None
        }
    };
    let Some((nm, port)) = n else {
        return core::ptr::null_mut();
    };
    let _ = p;
    unsafe { fill_servent(nm, port, b"tcp\0").cast() }
}

/// C `getservbyport` (port in network order).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn getservbyport(port: c_int, _proto: *const c_char) -> *mut c_void {
    let host = u16::from_be(u16::try_from(port.cast_unsigned() & 0xffff).unwrap_or(0));
    let (nm, p) = match host {
        80 => (b"http\0".as_slice(), 80_u16),
        443 => (b"https\0".as_slice(), 443),
        21 => (b"ftp\0".as_slice(), 21),
        22 => (b"ssh\0".as_slice(), 22),
        25 => (b"smtp\0".as_slice(), 25),
        _ => return core::ptr::null_mut(),
    };
    unsafe { fill_servent(nm, p, b"tcp\0").cast() }
}
