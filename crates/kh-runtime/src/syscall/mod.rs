//! Table-driven Darwin BSD syscall dispatch (arm64, number in `x16`).
//!
//! Error ABI (Darwin arm64): success clears `PSTATE.C` and places the return
//! value in `x0`; failure sets `PSTATE.C` and places a **positive** errno in
//! `x0`. The trap handler applies the carry bit from [`SyscallResult::error`].
//!
//! Modules:
//! - [`table`] — numbers / names
//! - [`fd`] — FD table, open/close/dup/lseek/fcntl/openat
//! - [`io`] — read/write
//! - [`fs`] — access/stat/fstat
//! - [`mem_sys`] — mmap/mprotect/munmap/msync
//! - [`process`] — exit/getpid/issetugid
//! - [`thread_sys`] — bsdthread_*/thread_selfid
//! - [`time_sys`] — gettimeofday/clock_gettime
//! - [`sysctl`] — sysctl/sysctlbyname
//! - [`signal`] — sigprocmask/sigaction (soft)

mod common;
mod fd;
mod fs;
mod helpers;
mod io;
mod mem_sys;
mod process;
mod signal;
mod sysctl;
mod table;
mod thread_sys;
mod time_sys;

use crate::process as proc_state;
use crate::trap::TrapOutcome;

pub use common::{
    EBADF, EFAULT, EINVAL, ENOENT, ENOMEM, ENOSYS, EPERM, SyscallArgs, SyscallResult,
};
pub use table::{BsdSyscall, known_syscalls, lookup, name_of};

/// Resets FD table, soft signal state, and syscall counter for a new run.
pub fn reset_syscall_state(max_syscalls: usize) {
    proc_state::reset_run(max_syscalls);
}

/// Dispatches a Darwin BSD syscall by number.
pub fn dispatch(args: SyscallArgs) -> SyscallResult {
    if proc_state::with_mut(proc_state::ProcessState::tick_syscall) {
        return SyscallResult {
            name: "max_syscalls",
            outcome: TrapOutcome::Exit { code: 1 },
            retval: Some(1),
            error: false,
        };
    }

    // Synthetic bottle helpers (puts / minimal printf) use high x16 values.
    if helpers::is_helper(args.number) {
        return helpers::dispatch_helper(args);
    }

    match lookup(args.number) {
        Some(BsdSyscall::Exit) => process::handle_exit(args),
        Some(BsdSyscall::Write) => io::handle_write(args),
        Some(BsdSyscall::Read) => io::handle_read(args),
        Some(BsdSyscall::Open) => fd::handle_open(args),
        Some(BsdSyscall::Close) => fd::handle_close(args),
        Some(BsdSyscall::Getpid) => process::handle_getpid(),
        Some(BsdSyscall::Access) => fs::handle_access(args),
        Some(BsdSyscall::Issetugid) => process::handle_issetugid(),
        Some(BsdSyscall::Munmap) => mem_sys::handle_munmap(args),
        Some(BsdSyscall::Mprotect) => mem_sys::handle_mprotect(args),
        Some(BsdSyscall::Mmap) => mem_sys::handle_mmap(args),
        Some(BsdSyscall::Msync) => mem_sys::handle_msync(args),
        Some(BsdSyscall::Dup) => fd::handle_dup(args),
        Some(BsdSyscall::Fcntl) => fd::handle_fcntl(args),
        Some(BsdSyscall::Lseek) => fd::handle_lseek(args),
        Some(BsdSyscall::Stat) => fs::handle_stat(args),
        Some(BsdSyscall::Fstat) => fs::handle_fstat(args),
        Some(BsdSyscall::Openat) => fd::handle_openat(args),
        Some(BsdSyscall::Gettimeofday) => time_sys::handle_gettimeofday(args),
        Some(BsdSyscall::ClockGettime) => time_sys::handle_clock_gettime(args),
        Some(BsdSyscall::Sysctl) => sysctl::handle_sysctl(args),
        Some(BsdSyscall::Sysctlbyname) => sysctl::handle_sysctlbyname(args),
        Some(BsdSyscall::Sigprocmask) => signal::handle_sigprocmask(args),
        Some(BsdSyscall::Sigaction) => signal::handle_sigaction(args),
        Some(BsdSyscall::BsdthreadCreate) => thread_sys::handle_bsdthread_create(args),
        Some(BsdSyscall::BsdthreadTerminate) => thread_sys::handle_bsdthread_terminate(args),
        Some(BsdSyscall::BsdthreadRegister) => thread_sys::handle_bsdthread_register(args),
        Some(BsdSyscall::ThreadSelfid) => thread_sys::handle_thread_selfid(),
        None => SyscallResult::err("unknown", ENOSYS),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::mem::{
        HostPageSize, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE, map_stack, register_borrowed,
        registry_clear,
    };
    use super::common::{guest_read_i32, guest_read_u64, guest_slice, guest_write};
    use super::mem_sys::{
        DARWIN_MAP_ANON, DARWIN_MAP_PRIVATE, DARWIN_MAP_SHARED, host_page_size,
    };
    use std::io::Write;

    fn lock_syscalls() -> std::sync::MutexGuard<'static, ()> {
        proc_state::test_lock()
    }

    fn args(number: u32, x0: u64, x1: u64, x2: u64) -> SyscallArgs {
        SyscallArgs {
            pc: 0,
            number,
            x0,
            x1,
            x2,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
        }
    }

    fn guest_va(base: u64, off: usize) -> u64 {
        base.wrapping_add(u64::try_from(off).unwrap())
    }

    fn write_cstr(base: u64, off: usize, s: &str) -> u64 {
        let va = guest_va(base, off);
        guest_write(va, s.as_bytes());
        guest_write(va.wrapping_add(u64::try_from(s.len()).unwrap()), &[0]);
        va
    }

    #[test]
    fn lookup_common_numbers() {
        assert_eq!(lookup(1), Some(BsdSyscall::Exit));
        assert_eq!(lookup(4), Some(BsdSyscall::Write));
        assert_eq!(lookup(5), Some(BsdSyscall::Open));
        assert_eq!(lookup(20), Some(BsdSyscall::Getpid));
        assert_eq!(lookup(41), Some(BsdSyscall::Dup));
        assert_eq!(lookup(46), Some(BsdSyscall::Sigaction));
        assert_eq!(lookup(48), Some(BsdSyscall::Sigprocmask));
        assert_eq!(lookup(65), Some(BsdSyscall::Msync));
        assert_eq!(lookup(92), Some(BsdSyscall::Fcntl));
        assert_eq!(lookup(116), Some(BsdSyscall::Gettimeofday));
        assert_eq!(lookup(199), Some(BsdSyscall::Lseek));
        assert_eq!(lookup(202), Some(BsdSyscall::Sysctl));
        assert_eq!(lookup(266), Some(BsdSyscall::ClockGettime));
        assert_eq!(lookup(274), Some(BsdSyscall::Sysctlbyname));
        assert_eq!(lookup(360), Some(BsdSyscall::BsdthreadCreate));
        assert_eq!(lookup(361), Some(BsdSyscall::BsdthreadTerminate));
        assert_eq!(lookup(366), Some(BsdSyscall::BsdthreadRegister));
        assert_eq!(lookup(372), Some(BsdSyscall::ThreadSelfid));
        assert_eq!(lookup(463), Some(BsdSyscall::Openat));
        assert_eq!(lookup(9999), None);
    }

    #[test]
    fn name_table_stable() {
        assert_eq!(name_of(1), Some("exit"));
        assert_eq!(name_of(4), Some("write"));
        assert_eq!(name_of(339), Some("fstat"));
        assert_eq!(name_of(42), None);
    }

    #[test]
    fn exit_dispatch() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        let r = dispatch(args(1, 7, 0, 0));
        assert_eq!(r.name, "exit");
        assert_eq!(r.outcome, TrapOutcome::Exit { code: 7 });
        assert!(!r.error);
    }

    #[test]
    fn unknown_returns_enosys_with_error_flag() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        let r = dispatch(args(0xDEAD, 0, 0, 0));
        assert_eq!(r.name, "unknown");
        assert!(r.error);
        assert_eq!(r.retval, Some(u64::try_from(ENOSYS).unwrap_or(0)));
    }

    #[test]
    fn max_syscalls_trips() {
        let _g = lock_syscalls();
        reset_syscall_state(2);
        let a = args(20, 0, 0, 0);
        assert_eq!(dispatch(a).name, "getpid");
        assert_eq!(dispatch(a).name, "getpid");
        let r = dispatch(a);
        assert_eq!(r.name, "max_syscalls");
        assert_eq!(r.outcome, TrapOutcome::Exit { code: 1 });
    }

    #[test]
    fn getpid_positive() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        let r = dispatch(args(20, 0, 0, 0));
        assert_eq!(r.name, "getpid");
        assert!(!r.error);
        assert!(r.retval.unwrap_or(0) > 0);
    }

    #[test]
    fn ok_err_helpers() {
        let ok = SyscallResult::ok("write", 3);
        assert!(!ok.error);
        assert_eq!(ok.retval, Some(3));
        let err = SyscallResult::err("write", EBADF);
        assert!(err.error);
        assert_eq!(err.retval, Some(9));
    }

    #[test]
    fn mmap_anon_private_roundtrip() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        registry_clear();
        let page = host_page_size();
        let page_u = u64::try_from(page).unwrap_or(4096);
        let r = dispatch(SyscallArgs {
            pc: 0,
            number: 197,
            x0: 0,
            x1: page_u,
            x2: u64::from(VM_PROT_READ | VM_PROT_WRITE),
            x3: DARWIN_MAP_ANON | DARWIN_MAP_PRIVATE,
            x4: u64::MAX,
            x5: 0,
            x6: 0,
        });
        assert_eq!(r.name, "mmap");
        assert!(!r.error, "mmap failed: {:?}", r.retval);
        let addr = r.retval.expect("addr");
        assert_ne!(addr, u64::MAX);
        assert_ne!(addr, 0);

        let r2 = dispatch(SyscallArgs {
            pc: 0,
            number: 74,
            x0: addr,
            x1: page_u,
            x2: u64::from(VM_PROT_READ | VM_PROT_EXECUTE),
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
        });
        assert!(!r2.error);

        let r3 = dispatch(SyscallArgs {
            pc: 0,
            number: 73,
            x0: addr,
            x1: page_u,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
        });
        assert!(!r3.error);
        registry_clear();
    }

    #[test]
    fn mmap_file_backed_shared_msync() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        registry_clear();
        let host = HostPageSize::detect().expect("host");
        let stack = map_stack(host, 256 * 1024).expect("stack");
        register_borrowed(&stack);

        let dir = std::env::temp_dir().join(format!("kh-mmap-file-{}", std::process::id()));
        drop(std::fs::create_dir_all(&dir));
        let path = dir.join("payload.bin");
        std::fs::write(&path, b"KAKEMAP01\n").expect("write payload");

        let base = stack.guest_addr;
        let path_str = path.to_str().unwrap();
        let path_va = write_cstr(base, 0x1000, path_str);
        let open = dispatch(args(5, path_va, 2, 0)); // O_RDWR
        assert!(!open.error, "open: {:?}", open.retval);
        let gfd = open.retval.expect("fd");

        let page = host_page_size();
        let page_u = u64::try_from(page).unwrap();
        let map = dispatch(SyscallArgs {
            pc: 0,
            number: 197,
            x0: 0,
            x1: page_u,
            x2: u64::from(VM_PROT_READ | VM_PROT_WRITE),
            x3: DARWIN_MAP_SHARED,
            x4: gfd,
            x5: 0,
            x6: 0,
        });
        assert!(!map.error, "mmap file: {:?}", map.retval);
        let addr = map.retval.expect("map");
        assert_eq!(guest_slice(addr, 9), b"KAKEMAP01");
        guest_write(addr, b"X");

        let sync = dispatch(SyscallArgs {
            pc: 0,
            number: 65,
            x0: addr,
            x1: page_u,
            x2: 0x10, // MS_SYNC
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
        });
        assert!(!sync.error, "msync: {:?}", sync.retval);

        let unmap = dispatch(SyscallArgs {
            pc: 0,
            number: 73,
            x0: addr,
            x1: page_u,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
        });
        assert!(!unmap.error);
        assert!(!dispatch(args(6, gfd, 0, 0)).error);

        let on_disk = std::fs::read(&path).expect("reread");
        assert_eq!(on_disk.first().copied(), Some(b'X'));
        assert_eq!(on_disk.get(1..9), Some(b"AKEMAP01".as_slice()));

        registry_clear();
        drop(stack);
        drop(std::fs::remove_file(&path));
        drop(std::fs::remove_dir(&dir));
    }

    #[test]
    fn gettimeofday_and_clock_gettime() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        registry_clear();
        let host = HostPageSize::detect().expect("host");
        let stack = map_stack(host, 64 * 1024).expect("stack");
        register_borrowed(&stack);
        let base = stack.guest_addr;
        let tv_va = guest_va(base, 0x400);
        let ts_va = guest_va(base, 0x500);

        let r = dispatch(args(116, tv_va, 0, 0));
        assert!(!r.error, "gettimeofday: {:?}", r.retval);
        let sec = guest_read_u64(tv_va);
        let sec = i64::from_ne_bytes(sec.to_ne_bytes());
        assert!(sec > 1_600_000_000, "tv_sec={sec}");

        let r2 = dispatch(args(266, 0, ts_va, 0)); // CLOCK_REALTIME
        assert!(!r2.error, "clock_gettime: {:?}", r2.retval);
        let sec2 = guest_read_u64(ts_va);
        let sec2 = i64::from_ne_bytes(sec2.to_ne_bytes());
        assert!((sec2 - sec).abs() < 5);

        registry_clear();
        drop(stack);
    }

    #[test]
    fn sysctlbyname_hw_ncpu() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        registry_clear();
        let host = HostPageSize::detect().expect("host");
        let stack = map_stack(host, 64 * 1024).expect("stack");
        register_borrowed(&stack);
        let base = stack.guest_addr;
        let key_va = write_cstr(base, 0x200, "hw.ncpu");
        let val_va = guest_va(base, 0x300);
        let len_va = guest_va(base, 0x310);
        guest_write(len_va, &8_u64.to_le_bytes());

        let r = dispatch(SyscallArgs {
            pc: 0,
            number: 274,
            x0: key_va,
            x1: val_va,
            x2: len_va,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
        });
        assert!(!r.error, "sysctlbyname: {:?}", r.retval);
        let ncpu = guest_read_i32(val_va);
        assert!(ncpu >= 1);

        registry_clear();
        drop(stack);
    }

    #[test]
    fn sigprocmask_soft_roundtrip() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        registry_clear();
        let host = HostPageSize::detect().expect("host");
        let stack = map_stack(host, 64 * 1024).expect("stack");
        register_borrowed(&stack);
        let base = stack.guest_addr;
        let set_va = guest_va(base, 0x100);
        let oset_va = guest_va(base, 0x110);
        guest_write(set_va, &0x00FF_u32.to_le_bytes());
        // SIG_SETMASK = 3
        let r = dispatch(SyscallArgs {
            pc: 0,
            number: 48,
            x0: 3,
            x1: set_va,
            x2: oset_va,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
        });
        assert!(!r.error, "sigprocmask: {:?}", r.retval);

        registry_clear();
        drop(stack);
    }

    #[test]
    fn write_efault_when_registry_active_and_bad_ptr() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        registry_clear();
        let host = HostPageSize::detect().expect("host");
        let stack = map_stack(host, 64 * 1024).expect("stack");
        register_borrowed(&stack);

        let r = dispatch(args(4, 1, 0x1, 4));
        assert_eq!(r.name, "write");
        assert!(r.error);
        assert_eq!(r.retval, Some(u64::try_from(EFAULT).unwrap_or(0)));
        registry_clear();
        drop(stack);
    }

    #[test]
    fn open_read_lseek_fstat_dup_roundtrip() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        registry_clear();
        let host = HostPageSize::detect().expect("host");
        let stack = map_stack(host, 256 * 1024).expect("stack");
        register_borrowed(&stack);

        let dir = std::env::temp_dir().join(format!("kh-fd-test-{}", std::process::id()));
        drop(std::fs::create_dir_all(&dir));
        let path = dir.join("data.txt");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(b"hello-DEF").expect("write");
        }

        let base = stack.guest_addr;
        let path_str = path.to_str().expect("utf8 path");
        let path_va = write_cstr(base, 0x1000, path_str);
        let open = dispatch(args(5, path_va, 0, 0)); // O_RDONLY
        assert!(!open.error, "open: {:?}", open.retval);
        let gfd = open.retval.expect("fd");

        let read_va = guest_va(base, 0x2000);
        let rd = dispatch(args(3, gfd, read_va, 5)); // read 5
        assert!(!rd.error, "read: {:?}", rd.retval);
        assert_eq!(rd.retval, Some(5));
        assert_eq!(guest_slice(read_va, 5), b"hello");

        let seek = dispatch(args(199, gfd, 0, 0)); // lseek SET 0
        assert!(!seek.error);
        assert_eq!(seek.retval, Some(0));

        let stat_va = guest_va(base, 0x3000);
        let st = dispatch(args(339, gfd, stat_va, 0));
        assert!(!st.error, "fstat: {:?}", st.retval);
        // Darwin stat64: st_size at offset 96.
        let size = guest_read_u64(stat_va + 96);
        let size = i64::from_ne_bytes(size.to_ne_bytes());
        assert_eq!(size, 9);

        let dup = dispatch(args(41, gfd, 0, 0));
        assert!(!dup.error);
        let gfd2 = dup.retval.expect("dup fd");
        assert_ne!(gfd2, gfd);

        let fl = dispatch(args(92, gfd, 3, 0));
        assert!(!fl.error);

        assert!(!dispatch(args(6, gfd, 0, 0)).error);
        assert!(!dispatch(args(6, gfd2, 0, 0)).error);

        registry_clear();
        drop(stack);
        drop(std::fs::remove_file(&path));
        drop(std::fs::remove_dir(&dir));
    }

    #[test]
    fn openat_at_fdcwd() {
        let _g = lock_syscalls();
        reset_syscall_state(256);
        registry_clear();
        let host = HostPageSize::detect().expect("host");
        let stack = map_stack(host, 64 * 1024).expect("stack");
        register_borrowed(&stack);

        let dir = std::env::temp_dir().join(format!("kh-openat-{}", std::process::id()));
        drop(std::fs::create_dir_all(&dir));
        let path = dir.join("x.txt");
        std::fs::write(&path, b"z").expect("write");

        let base = stack.guest_addr;
        let path_str = path.to_str().unwrap();
        let path_va = write_cstr(base, 0x800, path_str);
        let r = dispatch(SyscallArgs {
            pc: 0,
            number: 463,
            x0: u64::from_ne_bytes(i64::from(fd::AT_FDCWD).to_ne_bytes()),
            x1: path_va,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
        });
        assert!(!r.error, "openat: {:?}", r.retval);
        let gfd = r.retval.unwrap();
        assert!(!dispatch(args(6, gfd, 0, 0)).error);

        registry_clear();
        drop(stack);
        drop(std::fs::remove_file(&path));
        drop(std::fs::remove_dir(&dir));
    }
}
