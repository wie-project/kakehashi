//! BSD `mmap` / `mprotect` / `munmap` / `msync`.

use std::ptr;

use crate::mem::{
    RemoveOutcome, VM_PROT_READ, VM_PROT_WRITE, darwin_to_host_prot, register_owned, registry_find,
    registry_remove, registry_update_prot,
};

use super::common::{
    EBADF, EFAULT, EINVAL, ENOMEM, EPERM, SyscallArgs, SyscallResult, guest_ptr_mut, reg_as_i32,
    reg_as_i64,
};
use super::fd::guest_to_host_fd;

/// Darwin `mmap` flag bits (subset).
pub(crate) const DARWIN_MAP_SHARED: u64 = 0x0001;
pub(crate) const DARWIN_MAP_PRIVATE: u64 = 0x0002;
pub(crate) const DARWIN_MAP_FIXED: u64 = 0x0010;
pub(crate) const DARWIN_MAP_ANON: u64 = 0x1000;

/// Darwin `msync` flag bits (subset).
const DARWIN_MS_ASYNC: i32 = 0x0001;
const DARWIN_MS_INVALIDATE: i32 = 0x0002;
const DARWIN_MS_SYNC: i32 = 0x0010;

/// `mmap` — anonymous (`MAP_ANON` / fd &lt; 0) or file-backed.
pub(crate) fn handle_mmap(args: SyscallArgs) -> SyscallResult {
    let name = "mmap";
    let addr = args.x0;
    let Ok(len) = usize::try_from(args.x1) else {
        return SyscallResult::err(name, EINVAL);
    };
    if len == 0 {
        return SyscallResult::err(name, EINVAL);
    }
    let prot = u32::try_from(args.x2 & 0x7).unwrap_or(0);
    let flags = args.x3;
    let guest_fd = reg_as_i32(args.x4);
    let offset = reg_as_i64(args.x5);

    let is_anon = flags & DARWIN_MAP_ANON != 0 || guest_fd < 0;
    if flags & DARWIN_MAP_SHARED != 0 && flags & DARWIN_MAP_PRIVATE != 0 {
        return SyscallResult::err(name, EINVAL);
    }
    // Default sharing when neither bit is set: private (common for MAP_ANON).
    let shared = flags & DARWIN_MAP_SHARED != 0;
    let fixed = flags & DARWIN_MAP_FIXED != 0;

    if !is_anon && offset < 0 {
        return SyscallResult::err(name, EINVAL);
    }

    let host_fd: libc::c_int = if is_anon {
        -1
    } else {
        let Some(h) = guest_to_host_fd(args.x4) else {
            return SyscallResult::err(name, EBADF);
        };
        h
    };

    let host_page = host_page_size();
    let map_len = align_up(len, host_page);
    if map_len == 0 {
        return SyscallResult::err(name, EINVAL);
    }

    let mut host_flags = if shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    if is_anon {
        host_flags |= libc::MAP_ANONYMOUS;
    }

    let addr_hint = if fixed {
        if addr == 0 {
            return SyscallResult::err(name, EINVAL);
        }
        let page_u64 = u64::try_from(host_page).unwrap_or(1);
        if page_u64 != 0 && !addr.is_multiple_of(page_u64) {
            return SyscallResult::err(name, EINVAL);
        }
        host_flags |= fixed_map_flag();
        guest_ptr_mut(addr).cast()
    } else {
        ptr::null_mut()
    };

    let map_prot = libc::PROT_READ | libc::PROT_WRITE;
    let off = if is_anon { 0 } else { offset };
    // SAFETY: length page-aligned; anon uses -1/fd; file fd from guest table; fixed uses MAP_FIXED*.
    let raw = unsafe { libc::mmap(addr_hint, map_len, map_prot, host_flags, host_fd, off) };
    if raw == libc::MAP_FAILED {
        return SyscallResult::err(name, ENOMEM);
    }
    let base = raw.cast::<u8>();
    let actual = ptr_to_u64(base);
    if fixed && actual != addr {
        unsafe {
            let _ = libc::munmap(raw, map_len);
        }
        return SyscallResult::err(name, ENOMEM);
    }

    let final_prot = if prot == 0 {
        VM_PROT_READ | VM_PROT_WRITE
    } else {
        prot
    };
    let host_prot = darwin_to_host_prot(final_prot);
    let rc = unsafe { libc::mprotect(base.cast(), map_len, host_prot) };
    if rc != 0 {
        unsafe {
            let _ = libc::munmap(raw, map_len);
        }
        return SyscallResult::err(name, EPERM);
    }

    register_owned(actual, base, map_len, final_prot);
    SyscallResult::ok(name, actual)
}

/// `mprotect`.
pub(crate) fn handle_mprotect(args: SyscallArgs) -> SyscallResult {
    let name = "mprotect";
    let addr = args.x0;
    let Ok(len) = usize::try_from(args.x1) else {
        return SyscallResult::err(name, EINVAL);
    };
    if len == 0 {
        return SyscallResult::ok(name, 0);
    }
    let prot = u32::try_from(args.x2 & 0x7).unwrap_or(0);
    let Some(region) = registry_find(addr, len) else {
        return SyscallResult::err(name, EFAULT);
    };
    let offset = usize::try_from(addr.saturating_sub(region.guest_addr)).unwrap_or(0);
    if offset.saturating_add(len) > region.len {
        return SyscallResult::err(name, EFAULT);
    }
    let host_prot = darwin_to_host_prot(prot);
    let rc = unsafe {
        let base = region.ptr.wrapping_add(offset);
        libc::mprotect(base.cast(), len, host_prot)
    };
    if rc != 0 {
        return SyscallResult::err(name, EPERM);
    }
    if addr == region.guest_addr && len == region.len {
        let _ = registry_update_prot(addr, len, prot);
    }
    SyscallResult::ok(name, 0)
}

/// `munmap`.
pub(crate) fn handle_munmap(args: SyscallArgs) -> SyscallResult {
    let name = "munmap";
    let addr = args.x0;
    let Ok(len) = usize::try_from(args.x1) else {
        return SyscallResult::err(name, EINVAL);
    };
    if len == 0 {
        return SyscallResult::ok(name, 0);
    }
    match registry_remove(addr, len) {
        RemoveOutcome::Unmapped | RemoveOutcome::Untracked => SyscallResult::ok(name, 0),
        RemoveOutcome::NotFound => SyscallResult::err(name, EINVAL),
        RemoveOutcome::UnmapFailed => SyscallResult::err(name, EPERM),
    }
}

/// `msync` — flush / invalidate a registered mapping range.
pub(crate) fn handle_msync(args: SyscallArgs) -> SyscallResult {
    let name = "msync";
    let addr = args.x0;
    let Ok(len) = usize::try_from(args.x1) else {
        return SyscallResult::err(name, EINVAL);
    };
    if len == 0 {
        return SyscallResult::ok(name, 0);
    }
    let flags = reg_as_i32(args.x2);
    let Some(region) = registry_find(addr, len) else {
        return SyscallResult::err(name, EFAULT);
    };
    let offset = usize::try_from(addr.saturating_sub(region.guest_addr)).unwrap_or(0);
    if offset.saturating_add(len) > region.len {
        return SyscallResult::err(name, EFAULT);
    }
    let host_flags = darwin_to_host_msync(flags);
    let rc = unsafe {
        let base = region.ptr.wrapping_add(offset);
        libc::msync(base.cast(), len, host_flags)
    };
    if rc != 0 {
        return SyscallResult::err(name, EPERM);
    }
    SyscallResult::ok(name, 0)
}

fn darwin_to_host_msync(flags: i32) -> libc::c_int {
    let mut h = 0;
    if flags & DARWIN_MS_ASYNC != 0 {
        h |= libc::MS_ASYNC;
    }
    if flags & DARWIN_MS_SYNC != 0 {
        h |= libc::MS_SYNC;
    }
    if flags & DARWIN_MS_INVALIDATE != 0 {
        h |= libc::MS_INVALIDATE;
    }
    // Default to sync if neither ASYNC nor SYNC (matches common “flush” intent).
    if h & (libc::MS_ASYNC | libc::MS_SYNC) == 0 {
        h |= libc::MS_SYNC;
    }
    h
}

/// Host page size for tests and mmap alignment.
#[must_use]
pub(crate) fn host_page_size() -> usize {
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n > 0 {
        usize::try_from(n).unwrap_or(4096)
    } else {
        4096
    }
}

fn align_up(len: usize, page: usize) -> usize {
    if page == 0 {
        return len;
    }
    if len.is_multiple_of(page) {
        len
    } else {
        let rem = len.checked_rem(page).unwrap_or(0);
        let pad = page.saturating_sub(rem);
        len.saturating_add(pad)
    }
}

fn fixed_map_flag() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        0x100_000 // MAP_FIXED_NOREPLACE
    }
    #[cfg(not(target_os = "linux"))]
    {
        libc::MAP_FIXED
    }
}

fn ptr_to_u64(p: *mut u8) -> u64 {
    u64::try_from(p.addr()).unwrap_or(0)
}
