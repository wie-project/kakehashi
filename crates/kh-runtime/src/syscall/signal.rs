//! Soft `sigprocmask` / `sigaction` — track guest state without disturbing host traps.

use std::sync::Mutex;

use crate::mem::registry_check_range;

use super::common::{
    EFAULT, EINVAL, EPERM, SyscallArgs, SyscallResult, guest_ptr, guest_ptr_mut, reg_as_i32,
};

/// Darwin `how` for `sigprocmask`.
const SIG_BLOCK: i32 = 1;
const SIG_UNBLOCK: i32 = 2;
const SIG_SETMASK: i32 = 3;

/// Darwin user-visible signal numbers we care about.
const SIGTRAP: i32 = 5;

/// Darwin `sigset_t` is 4 bytes (`__uint32_t`) in the classic ABI used by
/// `sigprocmask` on arm64 userland.
const SIGSET_SIZE: usize = 4;

/// Minimal Darwin `struct sigaction` we accept:
/// handler(8) + mask(4) + flags(4) = 16 bytes.
const SIGACTION_SIZE: usize = 16;

static GUEST_MASK: Mutex<u32> = Mutex::new(0);
static SIGACTIONS: Mutex<[SigAct; 32]> = Mutex::new([SigAct::zero(); 32]);

#[derive(Clone, Copy)]
struct SigAct {
    handler: u64,
    mask: u32,
    flags: i32,
}

impl SigAct {
    const fn zero() -> Self {
        Self {
            handler: 0,
            mask: 0,
            flags: 0,
        }
    }
}

/// `sigprocmask(how, set, oset)`.
pub(crate) fn handle_sigprocmask(args: SyscallArgs) -> SyscallResult {
    let name = "sigprocmask";
    let how = reg_as_i32(args.x0);
    let set = args.x1;
    let oset = args.x2;

    if set != 0 && !registry_check_range(set, SIGSET_SIZE, false) {
        return SyscallResult::err(name, EFAULT);
    }
    if oset != 0 && !registry_check_range(oset, SIGSET_SIZE, true) {
        return SyscallResult::err(name, EFAULT);
    }

    let Ok(mut guard) = GUEST_MASK.lock() else {
        return SyscallResult::err(name, EPERM);
    };
    let old = *guard;

    if oset != 0 {
        write_u32(oset, old);
    }

    if set != 0 {
        let new_bits = read_u32(set);
        match how {
            SIG_BLOCK => *guard |= new_bits,
            SIG_UNBLOCK => *guard &= !new_bits,
            SIG_SETMASK => *guard = new_bits,
            _ => return SyscallResult::err(name, EINVAL),
        }
        // Never touch host SIGTRAP — translator relies on it.
        let _ = SIGTRAP;
    }

    SyscallResult::ok(name, 0)
}

/// `sigaction(sig, act, oact)`.
pub(crate) fn handle_sigaction(args: SyscallArgs) -> SyscallResult {
    let name = "sigaction";
    let sig = reg_as_i32(args.x0);
    if sig <= 0 || sig >= 32 {
        return SyscallResult::err(name, EINVAL);
    }
    // Protect the translator trap signal: refuse to install a guest handler.
    if sig == SIGTRAP && args.x1 != 0 {
        return SyscallResult::err(name, EPERM);
    }

    let act = args.x1;
    let oact = args.x2;

    if act != 0 && !registry_check_range(act, SIGACTION_SIZE, false) {
        return SyscallResult::err(name, EFAULT);
    }
    if oact != 0 && !registry_check_range(oact, SIGACTION_SIZE, true) {
        return SyscallResult::err(name, EFAULT);
    }

    let Ok(mut table) = SIGACTIONS.lock() else {
        return SyscallResult::err(name, EPERM);
    };
    let idx = usize::try_from(sig).unwrap_or(0);
    let Some(slot) = table.get_mut(idx) else {
        return SyscallResult::err(name, EINVAL);
    };

    if oact != 0 {
        write_sigaction(oact, *slot);
    }
    if act != 0 {
        *slot = read_sigaction(act);
    }
    SyscallResult::ok(name, 0)
}

/// Resets soft signal state for a new guest run.
pub(crate) fn reset_signal_state() {
    if let Ok(mut m) = GUEST_MASK.lock() {
        *m = 0;
    }
    if let Ok(mut t) = SIGACTIONS.lock() {
        *t = [SigAct::zero(); 32];
    }
}

fn read_u32(addr: u64) -> u32 {
    let p = guest_ptr(addr);
    let b = unsafe { std::slice::from_raw_parts(p, 4) };
    le_u32(b)
}

fn write_u32(addr: u64, value: u32) {
    let dst = unsafe { std::slice::from_raw_parts_mut(guest_ptr_mut(addr), 4) };
    dst.copy_from_slice(&value.to_le_bytes());
}

fn read_sigaction(addr: u64) -> SigAct {
    let p = guest_ptr(addr);
    let b = unsafe { std::slice::from_raw_parts(p, SIGACTION_SIZE) };
    SigAct {
        handler: le_u64(b),
        mask: le_u32(b.get(8..12).unwrap_or(&[])),
        flags: le_i32(b.get(12..16).unwrap_or(&[])),
    }
}

fn write_sigaction(addr: u64, act: SigAct) {
    let mut raw = [0_u8; SIGACTION_SIZE];
    if let Some(slot) = raw.get_mut(..8) {
        slot.copy_from_slice(&act.handler.to_le_bytes());
    }
    if let Some(slot) = raw.get_mut(8..12) {
        slot.copy_from_slice(&act.mask.to_le_bytes());
    }
    if let Some(slot) = raw.get_mut(12..16) {
        slot.copy_from_slice(&act.flags.to_le_bytes());
    }
    let dst = unsafe { std::slice::from_raw_parts_mut(guest_ptr_mut(addr), SIGACTION_SIZE) };
    dst.copy_from_slice(&raw);
}

fn le_u32(b: &[u8]) -> u32 {
    let mut a = [0_u8; 4];
    let n = b.len().min(4);
    if let (Some(dst), Some(src)) = (a.get_mut(..n), b.get(..n)) {
        dst.copy_from_slice(src);
    }
    u32::from_le_bytes(a)
}

fn le_i32(b: &[u8]) -> i32 {
    i32::from_le_bytes(le_u32(b).to_le_bytes())
}

fn le_u64(b: &[u8]) -> u64 {
    let mut a = [0_u8; 8];
    let n = b.len().min(8);
    if let (Some(dst), Some(src)) = (a.get_mut(..n), b.get(..n)) {
        dst.copy_from_slice(src);
    }
    u64::from_le_bytes(a)
}
