//! Darwin BSD thread syscalls: `bsdthread_*` / `thread_selfid`.

use crate::process as proc_state;
use crate::process::BsdThreadReg;
use crate::thread::{self, GuestThreadStart};

use super::common::{EINVAL, ENOSYS, SyscallArgs, SyscallResult, reg_as_i32};

/// `bsdthread_register` — store libpthread start trampoline and metadata.
///
/// Prototype (XNU):
/// `int bsdthread_register(threadstart, wqthread, flags, stack_addr_hint,
///                        targetconc_ptr, dispatchqueue_offset, tsd_offset)`
pub(crate) fn handle_bsdthread_register(args: SyscallArgs) -> SyscallResult {
    let name = "bsdthread_register";
    let threadstart = args.x0;
    if threadstart == 0 {
        return SyscallResult::err(name, EINVAL);
    }
    let reg = BsdThreadReg {
        threadstart,
        wqthread: args.x1,
        flags: u32::try_from(args.x2 & 0xFFFF_FFFF).unwrap_or(0),
        stack_addr_hint: args.x3,
        // x4 = targetconc_ptr (ignored in micro)
        dispatchqueue_offset: u32::try_from(args.x5 & 0xFFFF_FFFF).unwrap_or(0),
        tsd_offset: u32::try_from(args.x6 & 0xFFFF_FFFF).unwrap_or(0),
    };
    proc_state::set_bsdthread_reg(reg);
    // Real XNU returns a feature bitmask; 0 is accepted by synthetic fixtures.
    SyscallResult::ok(name, 0)
}

/// `bsdthread_create` — spawn a host thread entering the registered trampoline.
///
/// Prototype:
/// `user_addr_t bsdthread_create(func, func_arg, stack, pthread, flags)`
pub(crate) fn handle_bsdthread_create(args: SyscallArgs) -> SyscallResult {
    let name = "bsdthread_create";
    let func = args.x0;
    let func_arg = args.x1;
    let stack = args.x2;
    let pthread = args.x3;
    let _flags = reg_as_i32(args.x4);

    if func == 0 || stack == 0 || pthread == 0 {
        return SyscallResult::err(name, EINVAL);
    }
    let sp = stack & !0xF;
    if sp == 0 {
        return SyscallResult::err(name, EINVAL);
    }

    let Some(reg) = proc_state::bsdthread_reg() else {
        // Must register before create (libpthread order).
        return SyscallResult::err(name, EINVAL);
    };
    if reg.threadstart == 0 {
        return SyscallResult::err(name, EINVAL);
    }

    let start = GuestThreadStart {
        entry: reg.threadstart,
        sp,
        pthread,
        port: 0,
        func,
        func_arg,
    };

    match thread::spawn_guest_thread(start) {
        Ok(()) => {
            // XNU returns the pthread pointer (user_addr_t) on success.
            SyscallResult::ok(name, pthread)
        }
        Err(errno) => {
            if errno == ENOSYS {
                SyscallResult::err(name, ENOSYS)
            } else {
                SyscallResult::err(name, errno)
            }
        }
    }
}

/// `bsdthread_terminate` — end the current guest/host worker thread.
///
/// Prototype:
/// `int bsdthread_terminate(stackaddr, freesize, port, sema_or_ulock)`
///
/// Micro: ignores stack unmap / semaphore wake; redirects via
/// [`crate::trap::TrapOutcome::ThreadExit`].
pub(crate) fn handle_bsdthread_terminate(_args: SyscallArgs) -> SyscallResult {
    SyscallResult::thread_exit("bsdthread_terminate")
}

/// `thread_selfid` — unique 64-bit id for the calling thread.
pub(crate) fn handle_thread_selfid() -> SyscallResult {
    SyscallResult::ok("thread_selfid", thread::thread_selfid())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::process as proc_state;
    use crate::syscall::{SyscallArgs, reset_syscall_state};

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        proc_state::test_lock()
    }

    #[allow(clippy::too_many_arguments)]
    fn args(
        number: u32,
        x0: u64,
        x1: u64,
        x2: u64,
        x3: u64,
        x4: u64,
        x5: u64,
        x6: u64,
    ) -> SyscallArgs {
        SyscallArgs {
            pc: 0,
            number,
            x0,
            x1,
            x2,
            x3,
            x4,
            x5,
            x6,
        }
    }

    #[test]
    fn register_then_create_zero_stack_einval() {
        let _g = lock();
        reset_syscall_state(256);
        let r = handle_bsdthread_register(args(366, 0x1000, 0, 0, 0, 0, 0, 0));
        assert!(!r.error, "register should succeed");
        assert_eq!(r.name, "bsdthread_register");

        // Invalid stack — must not spawn a host thread.
        let r = handle_bsdthread_create(args(360, 0x2000, 0, 0, 0x2F00, 0, 0, 0));
        assert!(r.error);
        assert_eq!(r.retval, Some(u64::try_from(EINVAL).unwrap()));
    }

    #[test]
    fn create_after_register_enosys_off_linux() {
        #[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
        {
            let _g = lock();
            reset_syscall_state(256);
            assert!(!handle_bsdthread_register(args(366, 0x1000, 0, 0, 0, 0, 0, 0)).error);
            let r = handle_bsdthread_create(args(360, 0x2000, 0, 0x3000, 0x2F00, 0, 0, 0));
            assert!(r.error);
            assert_eq!(r.retval, Some(u64::try_from(ENOSYS).unwrap()));
        }
    }

    #[test]
    fn create_without_register_einval() {
        let _g = lock();
        reset_syscall_state(256);
        let r = handle_bsdthread_create(args(360, 0x2000, 0, 0x3000, 0x2F00, 0, 0, 0));
        assert!(r.error);
        assert_eq!(r.retval, Some(u64::try_from(EINVAL).unwrap()));
    }

    #[test]
    fn terminate_is_thread_exit() {
        let r = handle_bsdthread_terminate(args(361, 0, 0, 0, 0, 0, 0, 0));
        assert_eq!(r.outcome, crate::trap::TrapOutcome::ThreadExit);
    }

    #[test]
    fn selfid_positive() {
        let r = handle_thread_selfid();
        assert!(!r.error);
        assert!(r.retval.unwrap_or(0) > 0);
    }
}
