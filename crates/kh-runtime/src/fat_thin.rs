//! Transparent fat (universal) Mach-O → single-arch view for guest `open`.
//!
//! Kakehashi guests are **arm64 only**. Apple CLT ships multi-arch static
//! archives (notably `libclang_rt.osx.a` with five slices). Modern `ld` under
//! freestanding fails LTO materialize when that fat archive is on the link
//! line with the full clang driver flags, while the same content as a thin
//! arm64 archive succeeds.
//!
//! On read-only `open` of a fat file, replace the host FD with a memfd (Linux)
//! or temp file holding only the preferred slice so the guest sees a normal
//! thin Mach-O / `ar` archive. `ld` then never walks foreign-arch slices.
#![allow(
    unsafe_code,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::manual_memcpy
)]

use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};

/// Big-endian `FAT_MAGIC` (`0xcafebabe`).
const FAT_MAGIC: u32 = 0xcafe_babe;
/// Big-endian `FAT_CIGAM` (byte-swapped magic on disk).
const FAT_CIGAM: u32 = 0xbeba_feca;
/// `CPU_TYPE_ARM64` = `CPU_ARCH_ABI64 | CPU_TYPE_ARM`.
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// `CPU_SUBTYPE_ARM64_ALL`.
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
/// `CPU_SUBTYPE_ARM64E` (with ABI64 lib64 bit as stored in fat headers).
const CPU_SUBTYPE_ARM64E: u32 = 0x8000_0002;

/// If `host_fd` is a fat Mach-O, return a new FD on a thin arm64 slice only.
/// On any failure / non-fat file, returns `None` (caller keeps the original FD).
///
/// Caller must close `host_fd` when this returns `Some`.
#[must_use]
pub fn thin_fat_fd(host_fd: RawFd) -> Option<RawFd> {
    if host_fd < 0 {
        return None;
    }
    let slice = read_preferred_slice(host_fd)?;
    if slice.is_empty() {
        return None;
    }
    let thin = create_anon_fd("kh-fat-thin")?;
    // SAFETY: `thin` is a fresh FD we own.
    let mut file = unsafe { std::fs::File::from_raw_fd(thin) };
    if file.write_all(&slice).is_err() {
        // File drop closes thin.
        return None;
    }
    drop(file.flush());
    drop(file.seek(SeekFrom::Start(0)));
    // Keep FD open; `into_raw_fd` transfers ownership without close.
    Some(file.into_raw_fd())
}

fn read_preferred_slice(host_fd: RawFd) -> Option<Vec<u8>> {
    let mut hdr = [0_u8; 8];
    if pread_all(host_fd, &mut hdr, 0)? != 8 {
        return None;
    }
    let magic = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let (swap, nfat) = match magic {
        FAT_MAGIC => (false, u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]])),
        FAT_CIGAM => (true, u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]])),
        _ => return None,
    };
    if nfat == 0 || nfat > 32 {
        return None;
    }
    let table_len = usize::try_from(nfat).ok()?.checked_mul(20)?;
    let mut table = vec![0_u8; table_len];
    if pread_all(host_fd, &mut table, 8)? != table_len {
        return None;
    }

    let mut best: Option<(u32, u32, u32)> = None; // offset, size, rank
    for i in 0..usize::try_from(nfat).ok()? {
        let o = i.checked_mul(20)?;
        let word = |j: usize| -> Option<u32> {
            let b = [
                *table.get(o.checked_add(j)?)?,
                *table.get(o.checked_add(j)?.checked_add(1)?)?,
                *table.get(o.checked_add(j)?.checked_add(2)?)?,
                *table.get(o.checked_add(j)?.checked_add(3)?)?,
            ];
            Some(if swap {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            })
        };
        let cputype = word(0)?;
        let cpusubtype = word(4)?;
        let offset = word(8)?;
        let size = word(12)?;
        if cputype != CPU_TYPE_ARM64 || size == 0 {
            continue;
        }
        let rank = match cpusubtype {
            CPU_SUBTYPE_ARM64_ALL => 2_u32,
            CPU_SUBTYPE_ARM64E => 1_u32,
            _ => 0_u32,
        };
        if rank == 0 {
            continue;
        }
        let replace = match best {
            Some((_, _, br)) => rank > br,
            None => true,
        };
        if replace {
            best = Some((offset, size, rank));
        }
    }
    let (offset, size, _) = best?;
    let size = usize::try_from(size).ok()?;
    if size == 0 || size > 64 * 1024 * 1024 {
        return None;
    }
    let mut body = vec![0_u8; size];
    let off = i64::from(offset);
    if pread_all(host_fd, &mut body, off)? != size {
        return None;
    }
    Some(body)
}

fn pread_all(fd: RawFd, buf: &mut [u8], offset: i64) -> Option<usize> {
    let mut got = 0_usize;
    while got < buf.len() {
        let want = buf.len().checked_sub(got)?;
        let off = offset.checked_add(i64::try_from(got).ok()?)?;
        // SAFETY: `buf[got..]` is valid writable memory; `fd` is open.
        let n = unsafe { libc::pread(fd, buf.get_mut(got..)?.as_mut_ptr().cast(), want, off) };
        if n < 0 {
            return None;
        }
        if n == 0 {
            return if got == 0 { None } else { Some(got) };
        }
        got = got.checked_add(usize::try_from(n).ok()?)?;
    }
    Some(got)
}

fn create_anon_fd(name: &str) -> Option<RawFd> {
    #[cfg(target_os = "linux")]
    {
        let cname = std::ffi::CString::new(name).ok()?;
        // MFD_CLOEXEC = 1
        // SAFETY: name is a valid C string; flags are the memfd CLOEXEC bit.
        let fd = unsafe { libc::syscall(libc::SYS_memfd_create, cname.as_ptr(), 1_i32) };
        if fd < 0 {
            return create_temp_fd();
        }
        return Some(fd as RawFd);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = name;
        create_temp_fd()
    }
}

fn create_temp_fd() -> Option<RawFd> {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "kh-fat-thin-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .ok()?;
    // Unlink so the FD is the only reference (Unix).
    drop(std::fs::remove_file(&path));
    Some(f.into_raw_fd())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn write_fat_arm64_only(body: &[u8]) -> Vec<u8> {
        let body_off: u32 = 0x1000;
        let total = usize::try_from(body_off)
            .unwrap()
            .saturating_add(body.len());
        let mut out = vec![0_u8; total];
        out[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        out[4..8].copy_from_slice(&1_u32.to_be_bytes());
        let words = [
            CPU_TYPE_ARM64.to_be_bytes(),
            CPU_SUBTYPE_ARM64_ALL.to_be_bytes(),
            body_off.to_be_bytes(),
            u32::try_from(body.len()).unwrap_or(0).to_be_bytes(),
            12_u32.to_be_bytes(),
        ];
        let mut p = 8_usize;
        for w in words {
            out[p..p + 4].copy_from_slice(&w);
            p += 4;
        }
        let start = usize::try_from(body_off).unwrap();
        out[start..start + body.len()].copy_from_slice(body);
        out
    }

    #[test]
    fn thin_extracts_arm64_slice() {
        let body = b"!<arch>\nhello-fat-slice\n";
        let fat = write_fat_arm64_only(body);
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kh-fat-test-{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&fat).unwrap();
        }
        let f = std::fs::File::open(&path).unwrap();
        let fd = f.into_raw_fd();
        let thin = thin_fat_fd(fd).expect("thin");
        // SAFETY: close original after thin_fat_fd (it does not close input).
        unsafe {
            libc::close(fd);
        }
        let mut thin_f = unsafe { std::fs::File::from_raw_fd(thin) };
        let mut got = Vec::new();
        thin_f.read_to_end(&mut got).unwrap();
        assert_eq!(got, body);
        drop(std::fs::remove_file(&path));
    }

    #[test]
    fn non_fat_returns_none() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("kh-notfat-{}", std::process::id()));
        std::fs::write(&path, b"!<arch>\nnot-fat\n").unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let fd = f.into_raw_fd();
        assert!(thin_fat_fd(fd).is_none());
        unsafe {
            libc::close(fd);
        }
        drop(std::fs::remove_file(&path));
    }
}
