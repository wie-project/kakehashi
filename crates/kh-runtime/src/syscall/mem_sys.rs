//! BSD `mmap` / `mprotect` / `munmap` / `msync`.

use crate::host;
use crate::mem::{
    RemoveOutcome, VM_PROT_READ, VM_PROT_WRITE, darwin_to_host_prot, register_owned, registry_find,
    registry_remove, registry_update_prot,
};

use super::common::{
    EBADF, EFAULT, EINVAL, ENOMEM, EPERM, SyscallArgs, SyscallResult, reg_as_i32, reg_as_i64,
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

    let fixed_addr = if fixed {
        if addr == 0 {
            return SyscallResult::err(name, EINVAL);
        }
        let page_u64 = u64::try_from(host_page).unwrap_or(1);
        if page_u64 != 0 && !addr.is_multiple_of(page_u64) {
            return SyscallResult::err(name, EINVAL);
        }
        host_flags |= host::fixed_map_flag();
        Some(addr)
    } else {
        None
    };

    let map_prot = libc::PROT_READ | libc::PROT_WRITE;
    let off = if is_anon { 0 } else { offset };
    let Some(base) = host::mmap(fixed_addr, map_len, map_prot, host_flags, host_fd, off) else {
        return SyscallResult::err(name, ENOMEM);
    };
    let actual = host::ptr_addr_u64(base);
    if fixed && actual != addr {
        let _ = host::munmap(base, map_len);
        return SyscallResult::err(name, ENOMEM);
    }

    let final_prot = if prot == 0 {
        VM_PROT_READ | VM_PROT_WRITE
    } else {
        prot
    };
    let host_prot = darwin_to_host_prot(final_prot);
    // mmap used PROT_READ|PROT_WRITE; skip a no-op mprotect when the guest
    // asked for the same (hot freestanding heap path — roadmap A5).
    if host_prot != map_prot && !host::mprotect(base, map_len, host_prot) {
        let _ = host::munmap(base, map_len);
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
    let base = region.ptr.wrapping_add(offset);
    if !host::mprotect(base, len, host_prot) {
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
    let base = region.ptr.wrapping_add(offset);
    if !host::msync(base, len, host_flags) {
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
    if h & (libc::MS_ASYNC | libc::MS_SYNC) == 0 {
        h |= libc::MS_SYNC;
    }
    h
}

/// Host page size for tests and mmap alignment.
#[must_use]
pub(crate) fn host_page_size() -> usize {
    host::page_size().unwrap_or(4096)
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
