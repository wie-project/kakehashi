//! Soft `sigprocmask` / `sigaction` — track guest state without disturbing host traps.

use crate::mem::registry_check_range;
use crate::process::{self, SoftSigAct};

use super::common::{
    EFAULT, EINVAL, EPERM, SyscallArgs, SyscallResult, guest_read_i32, guest_read_u32,
    guest_read_u64, guest_write, guest_write_u32, reg_as_i32,
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

    let new_bits = if set != 0 {
        Some(guest_read_u32(set))
    } else {
        None
    };

    let result = process::with_mut(|p| {
        let old = p.sig_mask();
        if let Some(bits) = new_bits {
            let updated = match how {
                SIG_BLOCK => old | bits,
                SIG_UNBLOCK => old & !bits,
                SIG_SETMASK => bits,
                _ => return Err(EINVAL),
            };
            p.set_sig_mask(updated);
            // Never touch host SIGTRAP — translator relies on it.
            let _ = SIGTRAP;
        }
        Ok(old)
    });

    match result {
        Ok(old) => {
            if oset != 0 {
                guest_write_u32(oset, old);
            }
            SyscallResult::ok(name, 0)
        }
        Err(errno) => SyscallResult::err(name, errno),
    }
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

    let idx = usize::try_from(sig).unwrap_or(0);
    let new_act = if act != 0 {
        Some(read_sigaction(act))
    } else {
        None
    };

    let old = process::with_mut(|p| {
        let prev = p.sigaction(idx).unwrap_or_else(SoftSigAct::zero);
        if let Some(a) = new_act {
            let _ = p.set_sigaction(idx, a);
        }
        prev
    });

    if oact != 0 {
        write_sigaction(oact, old);
    }
    SyscallResult::ok(name, 0)
}

fn read_sigaction(addr: u64) -> SoftSigAct {
    SoftSigAct {
        handler: guest_read_u64(addr),
        mask: guest_read_u32(addr.wrapping_add(8)),
        flags: guest_read_i32(addr.wrapping_add(12)),
    }
}

fn write_sigaction(addr: u64, act: SoftSigAct) {
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
    guest_write(addr, &raw);
}
