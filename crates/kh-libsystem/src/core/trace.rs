//! Call tracing to guest stderr (fd 2) via Darwin `write`.

use crate::kh_core::sys::{self, SYS_WRITE};

/// Off by default: every note is a Darwin `write` and burns the host
/// `max_syscalls` budget (real guests allocate heavily in static ctors).
static TRACE_ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Always write `msg` to guest stderr (fd 2). Use for fatal abort notes so
/// curl G1 can report the first missing import even when verbose trace is off.
#[inline]
pub(crate) fn force_note(msg: &[u8]) {
    if msg.is_empty() {
        return;
    }
    let ptr = u64::try_from(msg.as_ptr().addr()).unwrap_or(0);
    let len = u64::try_from(msg.len()).unwrap_or(0);
    // SAFETY: buffer live for the syscall; fd 2 = stderr.
    let _ = unsafe { sys::syscall3(SYS_WRITE, 2, ptr, len) };
}

/// Writes `msg` to fd 2 when tracing is enabled.
#[inline]
pub(crate) fn note(msg: &[u8]) {
    if !TRACE_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    force_note(msg);
}

/// `[kh-libsystem] name(size)\n`
pub(crate) fn note_size(name: &[u8], size: usize) {
    if !TRACE_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let mut buf = [0_u8; 96];
    let mut n = 0_usize;
    n = append(&mut buf, n, b"[kh-libsystem] ");
    n = append(&mut buf, n, name);
    n = append(&mut buf, n, b"(");
    n = append_dec(&mut buf, n, size);
    n = append(&mut buf, n, b")\n");
    if let Some(slice) = buf.get(..n) {
        note(slice);
    }
}

/// `[kh-libsystem] name(0x…)\n`
pub(crate) fn note_ptr(name: &[u8], ptr: usize) {
    if !TRACE_ENABLED.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let mut buf = [0_u8; 96];
    let mut n = 0_usize;
    n = append(&mut buf, n, b"[kh-libsystem] ");
    n = append(&mut buf, n, name);
    n = append(&mut buf, n, b"(0x");
    n = append_hex(&mut buf, n, ptr);
    n = append(&mut buf, n, b")\n");
    if let Some(slice) = buf.get(..n) {
        note(slice);
    }
}

fn append(buf: &mut [u8], off: usize, bytes: &[u8]) -> usize {
    let mut o = off;
    for &b in bytes {
        if let Some(slot) = buf.get_mut(o) {
            *slot = b;
            o = o.saturating_add(1);
        } else {
            break;
        }
    }
    o
}

fn append_dec(buf: &mut [u8], off: usize, mut value: usize) -> usize {
    if value == 0 {
        return append(buf, off, b"0");
    }
    let mut tmp = [0_u8; 20];
    let mut i = 0_usize;
    while value > 0 {
        if let Some(slot) = tmp.get_mut(i) {
            let digit = value % 10;
            *slot = b'0'.saturating_add(u8::try_from(digit).unwrap_or(0));
            i = i.saturating_add(1);
            value /= 10;
        } else {
            break;
        }
    }
    let mut o = off;
    while i > 0 {
        i = i.saturating_sub(1);
        if let (Some(slot), Some(&d)) = (buf.get_mut(o), tmp.get(i)) {
            *slot = d;
            o = o.saturating_add(1);
        }
    }
    o
}

fn append_hex(buf: &mut [u8], off: usize, mut value: usize) -> usize {
    if value == 0 {
        return append(buf, off, b"0");
    }
    let mut tmp = [0_u8; 16];
    let mut i = 0_usize;
    while value > 0 {
        if let Some(slot) = tmp.get_mut(i) {
            let nibble = value & 0xf;
            *slot = if nibble < 10 {
                b'0'.saturating_add(u8::try_from(nibble).unwrap_or(0))
            } else {
                b'a'.saturating_add(u8::try_from(nibble.saturating_sub(10)).unwrap_or(0))
            };
            i = i.saturating_add(1);
            value >>= 4;
        } else {
            break;
        }
    }
    let mut o = off;
    while i > 0 {
        i = i.saturating_sub(1);
        if let (Some(slot), Some(&d)) = (buf.get_mut(o), tmp.get(i)) {
            *slot = d;
            o = o.saturating_add(1);
        }
    }
    o
}
