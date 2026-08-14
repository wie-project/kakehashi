//! Soft termcap surface (`libncurses.5.4.dylib` / `libtermcap`).
//!
//! Apple `bash` / `csh` / `zsh` import `tgetent` and friends from ncurses.
//! Contracts from public `tgetent(3)` / `tgoto(3)` / `tputs(3)`.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    static_mut_refs
)]

use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::dylib::libsystem_c::posix::getenv;
use crate::dylib::libsystem_c::stdio::strlen;

static TERMCAP_OK: AtomicBool = AtomicBool::new(false);
static DUMB: AtomicBool = AtomicBool::new(false);

#[repr(C)]
struct Cap {
    id: [u8; 2],
    num: i32,
    flag: i8,
    s: *const u8,
}

// Termcap strings (xterm / vt100 class). Public sequences only.
const S_CM: &[u8] = b"\x1b[%i%d;%dH\0";
const S_CE: &[u8] = b"\x1b[K\0";
const S_CL: &[u8] = b"\x1b[H\x1b[2J\0";
const S_CD: &[u8] = b"\x1b[J\0";
const S_HO: &[u8] = b"\x1b[H\0";
const S_UP: &[u8] = b"\x1b[A\0";
const S_DO: &[u8] = b"\n\0";
const S_ND: &[u8] = b"\x1b[C\0";
const S_LE: &[u8] = b"\x08\0";
const S_BC: &[u8] = b"\x08\0";
const S_KB: &[u8] = b"\x7f\0";
const S_CR: &[u8] = b"\r\0";
const S_BL: &[u8] = b"\x07\0";
const S_KS: &[u8] = b"\x1b[?1h\x1b=\0";
const S_KE: &[u8] = b"\x1b[?1l\x1b>\0";
const S_KU: &[u8] = b"\x1bOA\0";
const S_KD: &[u8] = b"\x1bOB\0";
const S_KR: &[u8] = b"\x1bOC\0";
const S_KL: &[u8] = b"\x1bOD\0";
const S_KH: &[u8] = b"\x1bOH\0";
const S_KEND: &[u8] = b"\x1bOF\0";
const S_KN: &[u8] = b"\x1b[6~\0";
const S_KP: &[u8] = b"\x1b[5~\0";
const S_KDEL: &[u8] = b"\x1b[3~\0";
const S_KINS: &[u8] = b"\x1b[2~\0";
const S_SO: &[u8] = b"\x1b[7m\0";
const S_SE: &[u8] = b"\x1b[27m\0";
const S_US: &[u8] = b"\x1b[4m\0";
const S_UE: &[u8] = b"\x1b[24m\0";
const S_MD: &[u8] = b"\x1b[1m\0";
const S_ME: &[u8] = b"\x1b[0m\0";
const S_MB: &[u8] = b"\x1b[5m\0";
const S_MR: &[u8] = b"\x1b[7m\0";
const S_VE: &[u8] = b"\x1b[?25h\0";
const S_VI: &[u8] = b"\x1b[?25l\0";
const S_DC: &[u8] = b"\x1b[P\0";
const S_IC: &[u8] = b"\x1b[@\0";
const S_IM: &[u8] = b"\x1b[4h\0";
const S_EI: &[u8] = b"\x1b[4l\0";
const S_AL: &[u8] = b"\x1b[L\0";
const S_DL: &[u8] = b"\x1b[M\0";
const S_CS: &[u8] = b"\x1b[%i%d;%dr\0";
const S_AF: &[u8] = b"\x1b[3%dm\0";
const S_AB: &[u8] = b"\x1b[4%dm\0";

const CAPS: &[Cap] = &[
    Cap {
        id: *b"co",
        num: 80,
        flag: 0,
        s: core::ptr::null(),
    },
    Cap {
        id: *b"li",
        num: 24,
        flag: 0,
        s: core::ptr::null(),
    },
    Cap {
        id: *b"it",
        num: 8,
        flag: 0,
        s: core::ptr::null(),
    },
    Cap {
        id: *b"Co",
        num: 256,
        flag: 0,
        s: core::ptr::null(),
    },
    Cap {
        id: *b"pa",
        num: 32767,
        flag: 0,
        s: core::ptr::null(),
    },
    Cap {
        id: *b"am",
        num: -1,
        flag: 1,
        s: core::ptr::null(),
    },
    Cap {
        id: *b"bs",
        num: -1,
        flag: 1,
        s: core::ptr::null(),
    },
    Cap {
        id: *b"xn",
        num: -1,
        flag: 1,
        s: core::ptr::null(),
    },
    Cap {
        id: *b"ms",
        num: -1,
        flag: 1,
        s: core::ptr::null(),
    },
    Cap {
        id: *b"km",
        num: -1,
        flag: 1,
        s: core::ptr::null(),
    },
    Cap {
        id: *b"cm",
        num: -1,
        flag: 0,
        s: S_CM.as_ptr(),
    },
    Cap {
        id: *b"ce",
        num: -1,
        flag: 0,
        s: S_CE.as_ptr(),
    },
    Cap {
        id: *b"cl",
        num: -1,
        flag: 0,
        s: S_CL.as_ptr(),
    },
    Cap {
        id: *b"cd",
        num: -1,
        flag: 0,
        s: S_CD.as_ptr(),
    },
    Cap {
        id: *b"ho",
        num: -1,
        flag: 0,
        s: S_HO.as_ptr(),
    },
    Cap {
        id: *b"up",
        num: -1,
        flag: 0,
        s: S_UP.as_ptr(),
    },
    Cap {
        id: *b"do",
        num: -1,
        flag: 0,
        s: S_DO.as_ptr(),
    },
    Cap {
        id: *b"nd",
        num: -1,
        flag: 0,
        s: S_ND.as_ptr(),
    },
    Cap {
        id: *b"le",
        num: -1,
        flag: 0,
        s: S_LE.as_ptr(),
    },
    Cap {
        id: *b"bc",
        num: -1,
        flag: 0,
        s: S_BC.as_ptr(),
    },
    Cap {
        id: *b"kb",
        num: -1,
        flag: 0,
        s: S_KB.as_ptr(),
    },
    Cap {
        id: *b"cr",
        num: -1,
        flag: 0,
        s: S_CR.as_ptr(),
    },
    Cap {
        id: *b"bl",
        num: -1,
        flag: 0,
        s: S_BL.as_ptr(),
    },
    Cap {
        id: *b"ks",
        num: -1,
        flag: 0,
        s: S_KS.as_ptr(),
    },
    Cap {
        id: *b"ke",
        num: -1,
        flag: 0,
        s: S_KE.as_ptr(),
    },
    Cap {
        id: *b"ku",
        num: -1,
        flag: 0,
        s: S_KU.as_ptr(),
    },
    Cap {
        id: *b"kd",
        num: -1,
        flag: 0,
        s: S_KD.as_ptr(),
    },
    Cap {
        id: *b"kr",
        num: -1,
        flag: 0,
        s: S_KR.as_ptr(),
    },
    Cap {
        id: *b"kl",
        num: -1,
        flag: 0,
        s: S_KL.as_ptr(),
    },
    Cap {
        id: *b"kh",
        num: -1,
        flag: 0,
        s: S_KH.as_ptr(),
    },
    Cap {
        id: *b"@7",
        num: -1,
        flag: 0,
        s: S_KEND.as_ptr(),
    },
    Cap {
        id: *b"kN",
        num: -1,
        flag: 0,
        s: S_KN.as_ptr(),
    },
    Cap {
        id: *b"kP",
        num: -1,
        flag: 0,
        s: S_KP.as_ptr(),
    },
    Cap {
        id: *b"kD",
        num: -1,
        flag: 0,
        s: S_KDEL.as_ptr(),
    },
    Cap {
        id: *b"kI",
        num: -1,
        flag: 0,
        s: S_KINS.as_ptr(),
    },
    Cap {
        id: *b"so",
        num: -1,
        flag: 0,
        s: S_SO.as_ptr(),
    },
    Cap {
        id: *b"se",
        num: -1,
        flag: 0,
        s: S_SE.as_ptr(),
    },
    Cap {
        id: *b"us",
        num: -1,
        flag: 0,
        s: S_US.as_ptr(),
    },
    Cap {
        id: *b"ue",
        num: -1,
        flag: 0,
        s: S_UE.as_ptr(),
    },
    Cap {
        id: *b"md",
        num: -1,
        flag: 0,
        s: S_MD.as_ptr(),
    },
    Cap {
        id: *b"me",
        num: -1,
        flag: 0,
        s: S_ME.as_ptr(),
    },
    Cap {
        id: *b"mb",
        num: -1,
        flag: 0,
        s: S_MB.as_ptr(),
    },
    Cap {
        id: *b"mr",
        num: -1,
        flag: 0,
        s: S_MR.as_ptr(),
    },
    Cap {
        id: *b"ve",
        num: -1,
        flag: 0,
        s: S_VE.as_ptr(),
    },
    Cap {
        id: *b"vi",
        num: -1,
        flag: 0,
        s: S_VI.as_ptr(),
    },
    Cap {
        id: *b"dc",
        num: -1,
        flag: 0,
        s: S_DC.as_ptr(),
    },
    Cap {
        id: *b"ic",
        num: -1,
        flag: 0,
        s: S_IC.as_ptr(),
    },
    Cap {
        id: *b"im",
        num: -1,
        flag: 0,
        s: S_IM.as_ptr(),
    },
    Cap {
        id: *b"ei",
        num: -1,
        flag: 0,
        s: S_EI.as_ptr(),
    },
    Cap {
        id: *b"al",
        num: -1,
        flag: 0,
        s: S_AL.as_ptr(),
    },
    Cap {
        id: *b"dl",
        num: -1,
        flag: 0,
        s: S_DL.as_ptr(),
    },
    Cap {
        id: *b"cs",
        num: -1,
        flag: 0,
        s: S_CS.as_ptr(),
    },
    Cap {
        id: *b"AF",
        num: -1,
        flag: 0,
        s: S_AF.as_ptr(),
    },
    Cap {
        id: *b"AB",
        num: -1,
        flag: 0,
        s: S_AB.as_ptr(),
    },
];

fn id_eq(id: *const c_char, want: [u8; 2]) -> bool {
    if id.is_null() {
        return false;
    }
    unsafe { *id == want[0].cast_signed() && *id.add(1) == want[1].cast_signed() }
}

fn find_cap(id: *const c_char) -> Option<&'static Cap> {
    CAPS.iter().find(|c| id_eq(id, c.id))
}

fn cstr_eq_ignore_case(p: *const c_char, lit: &[u8]) -> bool {
    if p.is_null() {
        return false;
    }
    let mut i = 0_usize;
    loop {
        let b = unsafe { (*p.add(i)).cast_unsigned() };
        let want = lit.get(i).copied().unwrap_or(0);
        if b == 0 || want == 0 {
            return b == 0 && want == 0;
        }
        let bl = if b.is_ascii_uppercase() { b + 32 } else { b };
        let wl = if want.is_ascii_uppercase() {
            want + 32
        } else {
            want
        };
        if bl != wl {
            return false;
        }
        i = i.saturating_add(1);
        if i > 64 {
            return false;
        }
    }
}

fn env_i32(key: *const c_char, fallback: i32) -> i32 {
    let p = unsafe { getenv(key) };
    if p.is_null() {
        return fallback;
    }
    let mut n: i32 = 0;
    let mut i = 0_usize;
    let mut any = false;
    loop {
        let b = unsafe { (*p.add(i)).cast_unsigned() };
        if b == 0 {
            break;
        }
        if b.is_ascii_digit() {
            any = true;
            n = n.saturating_mul(10).saturating_add(i32::from(b - b'0'));
        } else {
            break;
        }
        i = i.saturating_add(1);
        if i > 8 {
            break;
        }
    }
    if any { n } else { fallback }
}

/// C `tgetent` → nlist `_tgetent`.
///
/// Returns `1` when a capability set is installed, `0` if `name` is empty.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tgetent(_bp: *mut c_char, name: *const c_char) -> c_int {
    let term = if name.is_null() || unsafe { *name } == 0 {
        unsafe { getenv(c"TERM".as_ptr()) }
    } else {
        name
    };
    // No TERM (guest env did not forward it): still install the xterm set.
    // Returning 0 made Apple zsh treat the tty as dumb — Backspace printed
    // spaces and refresh showed WEOF (`?<ffffffff>`).
    let missing = term.is_null() || unsafe { *term } == 0;
    let dumb = !missing
        && (cstr_eq_ignore_case(term, b"dumb") || cstr_eq_ignore_case(term, b"unknown"));
    DUMB.store(dumb, Ordering::Relaxed);
    TERMCAP_OK.store(true, Ordering::Relaxed);
    1
}

/// C `tgetnum` → nlist `_tgetnum`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tgetnum(id: *const c_char) -> c_int {
    if !TERMCAP_OK.load(Ordering::Relaxed) {
        return -1;
    }
    if id_eq(id, *b"co") {
        return env_i32(c"COLUMNS".as_ptr(), 80);
    }
    if id_eq(id, *b"li") {
        return env_i32(c"LINES".as_ptr(), 24);
    }
    match find_cap(id) {
        Some(c) if c.num >= 0 => c.num,
        _ => -1,
    }
}

/// C `tgetflag` → nlist `_tgetflag`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tgetflag(id: *const c_char) -> c_int {
    if !TERMCAP_OK.load(Ordering::Relaxed) || DUMB.load(Ordering::Relaxed) {
        return 0;
    }
    match find_cap(id) {
        Some(c) if c.flag != 0 => 1,
        _ => 0,
    }
}

/// C `tgetstr` → nlist `_tgetstr`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tgetstr(id: *const c_char, area: *mut *mut c_char) -> *mut c_char {
    if !TERMCAP_OK.load(Ordering::Relaxed) || DUMB.load(Ordering::Relaxed) {
        return core::ptr::null_mut();
    }
    let Some(c) = find_cap(id) else {
        return core::ptr::null_mut();
    };
    if c.s.is_null() {
        return core::ptr::null_mut();
    }
    let src = c.s;
    let n = unsafe { strlen(src.cast()) }.saturating_add(1);
    if !area.is_null() {
        let dst = unsafe { *area };
        if !dst.is_null() {
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst.cast::<u8>(), n);
                *area = dst.add(n);
            }
            return dst;
        }
    }
    src.cast_mut().cast()
}

static mut TGOTO_BUF: [u8; 64] = [0; 64];

/// C `tgoto` → nlist `_tgoto` (subset: `%i` `%d` `%r` `%%` `%+x`).
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tgoto(cap: *const c_char, col: c_int, row: c_int) -> *mut c_char {
    if cap.is_null() {
        return core::ptr::null_mut();
    }
    let mut first = row;
    let mut second = col;
    let mut out = [0_u8; 64];
    let mut off = 0_usize;
    let mut idx = 0_usize;
    loop {
        let ch = unsafe { (*cap.add(idx)).cast_unsigned() };
        if ch == 0 {
            break;
        }
        if ch != b'%' {
            if off < out.len().saturating_sub(1) {
                out[off] = ch;
                off = off.saturating_add(1);
            }
            idx = idx.saturating_add(1);
            continue;
        }
        idx = idx.saturating_add(1);
        let spec = unsafe { (*cap.add(idx)).cast_unsigned() };
        idx = idx.saturating_add(1);
        match spec {
            b'%' => {
                if off < out.len().saturating_sub(1) {
                    out[off] = b'%';
                    off = off.saturating_add(1);
                }
            }
            b'i' => {
                first = first.saturating_add(1);
                second = second.saturating_add(1);
            }
            b'r' => {
                core::mem::swap(&mut first, &mut second);
            }
            b'd' => {
                off = write_dec(&mut out, off, first);
                core::mem::swap(&mut first, &mut second);
            }
            b'+' => {
                let add = unsafe { (*cap.add(idx)).cast_unsigned() };
                idx = idx.saturating_add(1);
                let val = first.saturating_add(c_int::from(add));
                if off < out.len().saturating_sub(1) {
                    out[off] = u8::try_from(val & 0xff).unwrap_or(0);
                    off = off.saturating_add(1);
                }
                core::mem::swap(&mut first, &mut second);
            }
            _ => {}
        }
    }
    if off < out.len() {
        out[off] = 0;
    }
    unsafe {
        TGOTO_BUF = out;
        TGOTO_BUF.as_mut_ptr().cast()
    }
}

fn write_dec(out: &mut [u8], mut o: usize, n: c_int) -> usize {
    let mut v = if n < 0 { 0_u32 } else { n.cast_unsigned() };
    let mut tmp = [0_u8; 10];
    let mut nd = 0_usize;
    if v == 0 {
        tmp[0] = b'0';
        nd = 1;
    } else {
        while v > 0 && nd < tmp.len() {
            tmp[nd] = b'0' + u8::try_from(v % 10).unwrap_or(0);
            nd = nd.saturating_add(1);
            v /= 10;
        }
    }
    while nd > 0 {
        nd -= 1;
        if o < out.len().saturating_sub(1) {
            out[o] = tmp[nd];
            o = o.saturating_add(1);
        }
    }
    o
}

/// C `tputs` → nlist `_tputs`.
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn tputs(
    s: *const c_char,
    _affcnt: c_int,
    putc: Option<unsafe extern "C" fn(c_int) -> c_int>,
) -> c_int {
    let Some(putc) = putc else {
        return -1;
    };
    if s.is_null() {
        return 0;
    }
    let mut i = 0_usize;
    loop {
        let ch = unsafe { (*s.add(i)).cast_unsigned() };
        if ch == 0 {
            break;
        }
        // Skip termcap padding `$<digits>`.
        if ch == b'$' && unsafe { (*s.add(i.saturating_add(1))).cast_unsigned() } == b'<' {
            i = i.saturating_add(2);
            while {
                let c = unsafe { (*s.add(i)).cast_unsigned() };
                c != 0 && c != b'>'
            } {
                i = i.saturating_add(1);
            }
            if unsafe { (*s.add(i)).cast_unsigned() } == b'>' {
                i = i.saturating_add(1);
            }
            continue;
        }
        let _ = unsafe { putc(c_int::from(ch)) };
        i = i.saturating_add(1);
    }
    0
}
