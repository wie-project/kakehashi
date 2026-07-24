//! `sysctl` / `sysctlbyname` stubs that return plausible Darwin-shaped data.

use crate::host;
use crate::mem::registry_check_range;

use super::common::{
    EFAULT, EINVAL, ENOENT, ENOMEM, EPERM, SyscallArgs, SyscallResult, guest_read_u64, guest_slice,
    guest_write, reg_as_i32,
};

/// CTL level-0 names (XNU).
const CTL_KERN: i32 = 1;
const CTL_HW: i32 = 6;

/// `kern.*`
const KERN_OSTYPE: i32 = 1;
const KERN_OSRELEASE: i32 = 2;
const KERN_VERSION: i32 = 4;
const KERN_ARGMAX: i32 = 8;
const KERN_HOSTNAME: i32 = 10;

/// `hw.*`
const HW_MACHINE: i32 = 1;
const HW_MODEL: i32 = 2;
const HW_NCPU: i32 = 3;
const HW_BYTEORDER: i32 = 4;
const HW_PHYSMEM: i32 = 5;
const HW_PAGESIZE: i32 = 7;
const HW_MEMSIZE: i32 = 24;
const HW_AVAILCPU: i32 = 25;

/// Soft hostname (read-only stub; never mutated).
const HOSTNAME: &[u8] = b"kakehashi";

/// `sysctl(name, namelen, oldp, oldlenp, newp, newlen)`.
pub(crate) fn handle_sysctl(args: SyscallArgs) -> SyscallResult {
    let name = "sysctl";
    let namelen = reg_as_i32(args.x1);
    if namelen <= 0 || namelen > 16 {
        return SyscallResult::err(name, EINVAL);
    }
    let Ok(n) = usize::try_from(namelen) else {
        return SyscallResult::err(name, EINVAL);
    };
    let mib_bytes = n.saturating_mul(4);
    if !registry_check_range(args.x0, mib_bytes, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let mut mib = vec![0_i32; n];
    let raw = guest_slice(args.x0, mib_bytes);
    for (i, slot) in mib.iter_mut().enumerate() {
        let off = i.saturating_mul(4);
        if let Some(chunk) = raw.get(off..off.saturating_add(4)) {
            *slot = le_i32(chunk);
        }
    }

    // Writes rejected (read-only translator surface).
    if args.x4 != 0 && args.x5 != 0 {
        return SyscallResult::err(name, EPERM);
    }

    let Some(value) = resolve_mib(&mib) else {
        return SyscallResult::err(name, ENOENT);
    };
    write_sysctl_value(name, args.x2, args.x3, &value)
}

/// `sysctlbyname(name, oldp, oldlenp, newp, newlen)`.
pub(crate) fn handle_sysctlbyname(args: SyscallArgs) -> SyscallResult {
    let name = "sysctlbyname";
    if !registry_check_range(args.x0, 1, false) {
        return SyscallResult::err(name, EFAULT);
    }
    let Some(key) = crate::bottle::read_c_string(args.x0, 256) else {
        return SyscallResult::err(name, EFAULT);
    };
    if args.x3 != 0 && args.x4 != 0 {
        return SyscallResult::err(name, EPERM);
    }
    let Some(value) = resolve_by_name(&key) else {
        return SyscallResult::err(name, ENOENT);
    };
    write_sysctl_value(name, args.x1, args.x2, &value)
}

enum SysctlValue {
    Int32(i32),
    UInt64(u64),
    String(&'static str),
    Bytes(Vec<u8>),
}

fn resolve_mib(mib: &[i32]) -> Option<SysctlValue> {
    match mib {
        [CTL_KERN, KERN_OSTYPE] => Some(SysctlValue::String("Darwin")),
        [CTL_KERN, KERN_OSRELEASE] => Some(SysctlValue::String("24.0.0")),
        [CTL_KERN, KERN_VERSION] => Some(SysctlValue::String(
            "Darwin Kernel Version 24.0.0: kakehashi stub",
        )),
        [CTL_KERN, KERN_ARGMAX] => Some(SysctlValue::Int32(262_144)),
        [CTL_KERN, KERN_HOSTNAME] => Some(SysctlValue::Bytes(HOSTNAME.to_vec())),
        [CTL_HW, HW_MACHINE] => Some(SysctlValue::String("arm64")),
        [CTL_HW, HW_MODEL] => Some(SysctlValue::String("Kakehashi")),
        [CTL_HW, HW_NCPU | HW_AVAILCPU] => Some(SysctlValue::Int32(host_ncpu())),
        [CTL_HW, HW_BYTEORDER] => Some(SysctlValue::Int32(1234)), // little-endian
        [CTL_HW, HW_PAGESIZE] => Some(SysctlValue::Int32(host_pagesize_i32())),
        [CTL_HW, HW_PHYSMEM] => {
            let capped = host_memsize().min(u64::from(i32::MAX.unsigned_abs()));
            Some(SysctlValue::Int32(
                i32::try_from(capped).unwrap_or(i32::MAX),
            ))
        }
        [CTL_HW, HW_MEMSIZE] => Some(SysctlValue::UInt64(host_memsize())),
        _ => None,
    }
}

fn resolve_by_name(key: &str) -> Option<SysctlValue> {
    match key {
        "kern.ostype" => Some(SysctlValue::String("Darwin")),
        "kern.osrelease" => Some(SysctlValue::String("24.0.0")),
        "kern.version" => Some(SysctlValue::String(
            "Darwin Kernel Version 24.0.0: kakehashi stub",
        )),
        "kern.argmax" => Some(SysctlValue::Int32(262_144)),
        "kern.hostname" => resolve_mib(&[CTL_KERN, KERN_HOSTNAME]),
        "hw.machine" => Some(SysctlValue::String("arm64")),
        "hw.model" => Some(SysctlValue::String("Kakehashi")),
        "hw.ncpu" | "hw.availcpu" | "hw.logicalcpu" | "hw.logicalcpu_max" | "hw.physicalcpu"
        | "hw.physicalcpu_max" => Some(SysctlValue::Int32(host_ncpu())),
        "hw.byteorder" => Some(SysctlValue::Int32(1234)),
        "hw.pagesize" => Some(SysctlValue::Int32(host_pagesize_i32())),
        "hw.memsize" => Some(SysctlValue::UInt64(host_memsize())),
        "hw.optional.arm64" | "hw.optional.neon" | "hw.packages" => Some(SysctlValue::Int32(1)),
        "hw.cachelinesize" => Some(SysctlValue::Int32(64)),
        "hw.l1dcachesize" => Some(SysctlValue::Int32(65_536)),
        "hw.l1icachesize" => Some(SysctlValue::Int32(131_072)),
        "hw.l2cachesize" => Some(SysctlValue::Int32(4_194_304)),
        _ => None,
    }
}

fn write_sysctl_value(
    name: &'static str,
    oldp: u64,
    oldlenp: u64,
    value: &SysctlValue,
) -> SyscallResult {
    let bytes = match value {
        SysctlValue::Int32(v) => v.to_le_bytes().to_vec(),
        SysctlValue::UInt64(v) => v.to_le_bytes().to_vec(),
        SysctlValue::String(s) => {
            let mut v = s.as_bytes().to_vec();
            v.push(0);
            v
        }
        SysctlValue::Bytes(b) => {
            let mut v = b.clone();
            if v.last().copied() != Some(0) {
                v.push(0);
            }
            v
        }
    };
    let need = bytes.len();

    // oldlenp required when oldp is set; may be used alone to query size.
    if oldlenp == 0 {
        return if oldp == 0 {
            SyscallResult::ok(name, 0)
        } else {
            SyscallResult::err(name, EFAULT)
        };
    }
    if !registry_check_range(oldlenp, 8, true) {
        return SyscallResult::err(name, EFAULT);
    }
    let old_len = read_usize(oldlenp);

    if oldp == 0 {
        // Size probe only.
        write_usize(oldlenp, need);
        return SyscallResult::ok(name, 0);
    }
    if old_len < need {
        write_usize(oldlenp, need);
        return SyscallResult::err(name, ENOMEM);
    }
    if !registry_check_range(oldp, need, true) {
        return SyscallResult::err(name, EFAULT);
    }
    guest_write(oldp, &bytes);
    write_usize(oldlenp, need);
    SyscallResult::ok(name, 0)
}

fn read_usize(addr: u64) -> usize {
    usize::try_from(guest_read_u64(addr)).unwrap_or(0)
}

fn write_usize(addr: u64, value: usize) {
    let v = u64::try_from(value).unwrap_or(0);
    guest_write(addr, &v.to_le_bytes());
}

fn le_i32(b: &[u8]) -> i32 {
    let mut a = [0_u8; 4];
    let n = b.len().min(4);
    if let (Some(dst), Some(src)) = (a.get_mut(..n), b.get(..n)) {
        dst.copy_from_slice(src);
    }
    i32::from_le_bytes(a)
}

fn host_ncpu() -> i32 {
    let n = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    i32::try_from(n).unwrap_or(1)
}

fn host_pagesize_i32() -> i32 {
    let n = host::page_size().unwrap_or(4096);
    i32::try_from(n).unwrap_or(4096)
}

fn host_memsize() -> u64 {
    host::phys_mem_bytes()
}
