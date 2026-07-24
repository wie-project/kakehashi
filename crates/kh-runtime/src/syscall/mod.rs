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
//! - [`time_sys`] — gettimeofday/clock_gettime
//! - [`sysctl`] — sysctl/sysctlbyname
//! - [`signal`] — sigprocmask/sigaction (soft)
#![allow(unsafe_code)]

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
mod time_sys;

use std::sync::Mutex;

use crate::trap::TrapOutcome;

pub use common::{
    EBADF, EFAULT, EINVAL, ENOENT, ENOMEM, ENOSYS, EPERM, SyscallArgs, SyscallResult,
};
pub use table::{BsdSyscall, known_syscalls, lookup, name_of};

static SYSCALL_COUNT: Mutex<u64> = Mutex::new(0);
static MAX_SYSCALLS: Mutex<u64> = Mutex::new(256);

/// Resets FD table, soft signal state, and syscall counter for a new run.
pub fn reset_syscall_state(max_syscalls: usize) {
    fd::reset_fd_table();
    signal::reset_signal_state();
    if let Ok(mut c) = SYSCALL_COUNT.lock() {
        *c = 0;
    }
    if let Ok(mut m) = MAX_SYSCALLS.lock() {
        *m = u64::try_from(max_syscalls).unwrap_or(256);
    }
}

/// Dispatches a Darwin BSD syscall by number.
pub fn dispatch(args: SyscallArgs) -> SyscallResult {
    if let Ok(mut c) = SYSCALL_COUNT.lock() {
        *c = c.saturating_add(1);
        let max = MAX_SYSCALLS.lock().map_or(256, |m| *m);
        if *c > max {
            return SyscallResult {
                name: "max_syscalls",
                outcome: TrapOutcome::Exit { code: 1 },
                retval: Some(1),
                error: false,
            };
        }
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
        None => SyscallResult::err("unknown", ENOSYS),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::mem::{
        HostPageSize, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE, map_stack, register_borrowed,
        registry_clear,
    };
    use crate::syscall::mem_sys::{
        DARWIN_MAP_ANON, DARWIN_MAP_PRIVATE, DARWIN_MAP_SHARED, host_page_size,
    };
    use std::io::Write;

    fn lock_syscalls() -> std::sync::MutexGuard<'static, ()> {
        crate::mem::registry_test_lock()
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
        }
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
        let r = dispatch(SyscallArgs {
            pc: 0,
            number: 197,
            x0: 0,
            x1: u64::try_from(page).unwrap_or(4096),
            x2: u64::from(VM_PROT_READ | VM_PROT_WRITE),
            x3: DARWIN_MAP_ANON | DARWIN_MAP_PRIVATE,
            x4: u64::MAX,
            x5: 0,
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
            x1: u64::try_from(page).unwrap_or(4096),
            x2: u64::from(VM_PROT_READ | VM_PROT_EXECUTE),
            x3: 0,
            x4: 0,
            x5: 0,
        });
        assert!(!r2.error);

        let r3 = dispatch(SyscallArgs {
            pc: 0,
            number: 73,
            x0: addr,
            x1: u64::try_from(page).unwrap_or(4096),
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
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
        let path_off = 0x1000_usize;
        let path_ptr = usize::try_from(base).unwrap() + path_off;
        unsafe {
            let dst = std::slice::from_raw_parts_mut(
                std::ptr::with_exposed_provenance_mut::<u8>(path_ptr),
                path_str.len() + 1,
            );
            dst[..path_str.len()].copy_from_slice(path_str.as_bytes());
            dst[path_str.len()] = 0;
        }
        let path_va = base + u64::try_from(path_off).unwrap();
        let open = dispatch(args(5, path_va, 2, 0)); // O_RDWR
        assert!(!open.error, "open: {:?}", open.retval);
        let gfd = open.retval.expect("fd");

        let page = host_page_size();
        let map = dispatch(SyscallArgs {
            pc: 0,
            number: 197,
            x0: 0,
            x1: u64::try_from(page).unwrap(),
            x2: u64::from(VM_PROT_READ | VM_PROT_WRITE),
            x3: DARWIN_MAP_SHARED,
            x4: gfd,
            x5: 0,
        });
        assert!(!map.error, "mmap file: {:?}", map.retval);
        let addr = map.retval.expect("map");
        let host_addr = usize::try_from(addr).unwrap();
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                std::ptr::with_exposed_provenance_mut::<u8>(host_addr),
                10,
            )
        };
        assert_eq!(&bytes[..9], b"KAKEMAP01");
        bytes[0] = b'X';

        let sync = dispatch(SyscallArgs {
            pc: 0,
            number: 65,
            x0: addr,
            x1: u64::try_from(page).unwrap(),
            x2: 0x10, // MS_SYNC
            x3: 0,
            x4: 0,
            x5: 0,
        });
        assert!(!sync.error, "msync: {:?}", sync.retval);

        let unmap = dispatch(SyscallArgs {
            pc: 0,
            number: 73,
            x0: addr,
            x1: u64::try_from(page).unwrap(),
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
        });
        assert!(!unmap.error);
        assert!(!dispatch(args(6, gfd, 0, 0)).error);

        let on_disk = std::fs::read(&path).expect("reread");
        assert_eq!(on_disk[0], b'X');
        assert_eq!(&on_disk[1..9], b"AKEMAP01");

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
        let tv_off = 0x400_usize;
        let ts_off = 0x500_usize;
        let tv_va = base + u64::try_from(tv_off).unwrap();
        let ts_va = base + u64::try_from(ts_off).unwrap();

        let r = dispatch(args(116, tv_va, 0, 0));
        assert!(!r.error, "gettimeofday: {:?}", r.retval);
        let sec = unsafe {
            let p =
                std::ptr::with_exposed_provenance::<u8>(usize::try_from(base).unwrap() + tv_off);
            let b = std::slice::from_raw_parts(p, 8);
            i64::from_le_bytes(b.try_into().unwrap())
        };
        assert!(sec > 1_600_000_000, "tv_sec={sec}");

        let r2 = dispatch(args(266, 0, ts_va, 0)); // CLOCK_REALTIME
        assert!(!r2.error, "clock_gettime: {:?}", r2.retval);
        let sec2 = unsafe {
            let p =
                std::ptr::with_exposed_provenance::<u8>(usize::try_from(base).unwrap() + ts_off);
            let b = std::slice::from_raw_parts(p, 8);
            i64::from_le_bytes(b.try_into().unwrap())
        };
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
        let key = b"hw.ncpu\0";
        let key_off = 0x200_usize;
        let val_off = 0x300_usize;
        let len_off = 0x310_usize;
        let host_base = usize::try_from(base).unwrap();
        unsafe {
            let dst = std::slice::from_raw_parts_mut(
                std::ptr::with_exposed_provenance_mut::<u8>(host_base + key_off),
                key.len(),
            );
            dst.copy_from_slice(key);
            let len_p = std::ptr::with_exposed_provenance_mut::<u8>(host_base + len_off);
            let len_sl = std::slice::from_raw_parts_mut(len_p, 8);
            len_sl.copy_from_slice(&8_u64.to_le_bytes());
        }
        let r = dispatch(SyscallArgs {
            pc: 0,
            number: 274,
            x0: base + u64::try_from(key_off).unwrap(),
            x1: base + u64::try_from(val_off).unwrap(),
            x2: base + u64::try_from(len_off).unwrap(),
            x3: 0,
            x4: 0,
            x5: 0,
        });
        assert!(!r.error, "sysctlbyname: {:?}", r.retval);
        let ncpu = unsafe {
            let p = std::ptr::with_exposed_provenance::<u8>(host_base + val_off);
            let b = std::slice::from_raw_parts(p, 4);
            i32::from_le_bytes(b.try_into().unwrap())
        };
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
        let set_off = 0x100_usize;
        let oset_off = 0x110_usize;
        let host_base = usize::try_from(base).unwrap();
        unsafe {
            let p = std::slice::from_raw_parts_mut(
                std::ptr::with_exposed_provenance_mut::<u8>(host_base + set_off),
                4,
            );
            p.copy_from_slice(&0x00FF_u32.to_le_bytes());
        }
        // SIG_SETMASK = 3
        let r = dispatch(SyscallArgs {
            pc: 0,
            number: 48,
            x0: 3,
            x1: base + u64::try_from(set_off).unwrap(),
            x2: base + u64::try_from(oset_off).unwrap(),
            x3: 0,
            x4: 0,
            x5: 0,
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
        let path_bytes = path_str.as_bytes();
        let path_off = 0x1000_usize;
        let buf_off = 0x2000_usize;
        let stat_off = 0x3000_usize;
        let host_base = usize::try_from(base).expect("base");
        let path_ptr = host_base + path_off;
        let read_ptr = host_base + buf_off;
        let stat_ptr = host_base + stat_off;
        unsafe {
            let dst = std::slice::from_raw_parts_mut(
                std::ptr::with_exposed_provenance_mut::<u8>(path_ptr),
                path_bytes.len() + 1,
            );
            if let Some(slot) = dst.get_mut(..path_bytes.len()) {
                slot.copy_from_slice(path_bytes);
            }
            if let Some(nul) = dst.get_mut(path_bytes.len()) {
                *nul = 0;
            }
        }

        let path_va = base + u64::try_from(path_off).unwrap();
        let open = dispatch(args(5, path_va, 0, 0)); // O_RDONLY
        assert!(!open.error, "open: {:?}", open.retval);
        let gfd = open.retval.expect("fd");

        let read_va = base + u64::try_from(buf_off).unwrap();
        let rd = dispatch(args(3, gfd, read_va, 5)); // read 5
        assert!(!rd.error, "read: {:?}", rd.retval);
        assert_eq!(rd.retval, Some(5));
        let got = unsafe {
            std::slice::from_raw_parts(std::ptr::with_exposed_provenance::<u8>(read_ptr), 5)
        };
        assert_eq!(got, b"hello");

        let seek = dispatch(args(199, gfd, 0, 0)); // lseek SET 0
        assert!(!seek.error);
        assert_eq!(seek.retval, Some(0));

        let stat_va = base + u64::try_from(stat_off).unwrap();
        let st = dispatch(args(339, gfd, stat_va, 0));
        assert!(!st.error, "fstat: {:?}", st.retval);
        let size = unsafe {
            let p = std::ptr::with_exposed_provenance::<u8>(stat_ptr + 96);
            let bytes = std::slice::from_raw_parts(p, 8);
            i64::from_le_bytes(bytes.try_into().unwrap())
        };
        assert_eq!(size, 9);

        let dup = dispatch(args(41, gfd, 0, 0));
        assert!(!dup.error);
        let gfd2 = dup.retval.expect("dup fd");
        assert_ne!(gfd2, gfd);

        let fl = dispatch(args(92, gfd, 3, 0));
        assert!(!fl.error);

        let cl = dispatch(args(6, gfd, 0, 0));
        assert!(!cl.error);
        let cl2 = dispatch(args(6, gfd2, 0, 0));
        assert!(!cl2.error);

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
        let path_off = 0x800_usize;
        let path_ptr = usize::try_from(base).unwrap() + path_off;
        unsafe {
            let dst = std::slice::from_raw_parts_mut(
                std::ptr::with_exposed_provenance_mut::<u8>(path_ptr),
                path_str.len() + 1,
            );
            if let Some(slot) = dst.get_mut(..path_str.len()) {
                slot.copy_from_slice(path_str.as_bytes());
            }
            if let Some(nul) = dst.get_mut(path_str.len()) {
                *nul = 0;
            }
        }
        let path_va = base + u64::try_from(path_off).unwrap();
        let r = dispatch(SyscallArgs {
            pc: 0,
            number: 463,
            x0: u64::from_ne_bytes(i64::from(fd::AT_FDCWD).to_ne_bytes()),
            x1: path_va,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
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
