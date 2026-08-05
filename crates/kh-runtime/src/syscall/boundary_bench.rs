//! Host-side microbench of **dispatch** cost by crossing class (roadmap2 P1).
//!
//! Times `syscall::dispatch` only (after host TLS / outside hypercall prolog).
//! Use this to rank getpid / open+close / readdir / uncontended park relative
//! to each other on a given host build. Full guest wall still needs plate A/B/C
//! + `KAKEHASHI_BOUNDARY_STATS` under `kh run`.
//!
//! Run:
//! ```text
//! cargo test -p kh-runtime --lib boundary_class_microbench -- --nocapture
//! # larger N:
//! KAKEHASHI_BOUNDARY_BENCH_ITERS=200000 cargo test -p kh-runtime --lib \
//!   boundary_class_microbench -- --nocapture --ignored
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fmt::Write as _;
use std::io::Write;
use std::time::Instant;

use crate::mem::{HostPageSize, map_stack, register_borrowed, registry_clear};
use crate::process as proc_state;

use super::common::guest_write;
use super::helpers::{KH_HELPER_PARK, KH_HELPER_READDIR};
use super::{SyscallArgs, dispatch, reset_syscall_state};

/// One timed class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClassTiming {
    /// Stable id for scripts (`getpid`, `open_close`, …).
    id: &'static str,
    /// Human label.
    label: &'static str,
    /// Successful iterations timed.
    iters: u64,
    /// Wall nanoseconds for the loop (host clock).
    total_ns: u64,
}

impl ClassTiming {
    /// Nanoseconds per iteration (0 if no iters).
    #[must_use]
    fn ns_per_iter(&self) -> u64 {
        self.total_ns.checked_div(self.iters.max(1)).unwrap_or(0)
    }
}

/// Full P1 report.
#[derive(Debug, Clone)]
struct BoundaryClassReport {
    /// Requested iterations per class.
    iters: u64,
    /// Per-class timings (unsorted).
    classes: Vec<ClassTiming>,
}

impl BoundaryClassReport {
    /// Classes sorted by descending ns/iter (most expensive first).
    #[must_use]
    fn ranked(&self) -> Vec<ClassTiming> {
        let mut v = self.classes.clone();
        v.sort_by(|a, b| {
            b.ns_per_iter()
                .cmp(&a.ns_per_iter())
                .then_with(|| a.id.cmp(b.id))
        });
        v
    }

    /// Multi-line text report (stderr/stdout friendly).
    #[must_use]
    fn format_report(&self) -> String {
        let mut out = format!(
            "kh boundary class microbench (host dispatch only)\n\
             \titers/class={}\n\
             \tnote: excludes hypercall NEON/TLS/alt-stack; ranks handler cost\n",
            self.iters
        );
        out.push_str("\trank  ns/iter     total_ms  class\n");
        for (i, c) in self.ranked().into_iter().enumerate() {
            let rank = i.saturating_add(1);
            let npi = c.ns_per_iter();
            let ms = c.total_ns.checked_div(1_000_000).unwrap_or(0);
            let _ = writeln!(
                out,
                "\t{rank:>4}  {npi:>8}  {ms:>8}  {} ({})",
                c.label, c.id
            );
        }
        let ranked = self.ranked();
        if let (Some(fast), Some(slow)) = (
            ranked.last().map(ClassTiming::ns_per_iter),
            ranked.first().map(ClassTiming::ns_per_iter),
        ) && fast > 0
        {
            let ratio = slow.checked_div(fast).unwrap_or(0);
            let _ = writeln!(
                out,
                "\tratio slowest/fastest ≈ {ratio}×  (dispatch-path only)"
            );
        }
        out
    }
}

/// Default iteration count for the always-on smoke test.
const DEFAULT_ITERS: u64 = 8_000;

/// Large-N default when running the ignored / script path.
const LARGE_ITERS: u64 = 100_000;

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
    base.wrapping_add(u64::try_from(off).unwrap_or(0))
}

fn write_cstr(base: u64, off: usize, s: &str) -> u64 {
    let va = guest_va(base, off);
    guest_write(va, s.as_bytes());
    guest_write(va.wrapping_add(u64::try_from(s.len()).unwrap_or(0)), &[0]);
    va
}

fn iters_from_env(default: u64) -> u64 {
    std::env::var("KAKEHASHI_BOUNDARY_BENCH_ITERS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

/// Run the four roadmap2 P1 classes under the process test lock.
///
/// Caller must not hold other global guest locks. Uses a private temp dir and
/// an anonymous guest stack mapping for identity-map buffers.
fn run_boundary_class_microbench(iters: u64) -> BoundaryClassReport {
    let _g = proc_state::test_lock();
    // Cap high enough for open+close pairs + readdir rewinds.
    let max =
        usize::try_from(iters.saturating_mul(16).saturating_add(10_000)).unwrap_or(usize::MAX);
    reset_syscall_state(max);
    registry_clear();

    let host = HostPageSize::detect().expect("host page size");
    let stack = map_stack(host, 256 * 1024).expect("map guest stack for bench");
    register_borrowed(&stack);
    let base = stack.guest_addr;

    let dir =
        std::env::temp_dir().join(format!("kh-boundary-bench-{}-{}", std::process::id(), base));
    drop(std::fs::create_dir_all(&dir));
    // A few names so readdir is not a single-shot empty dir.
    for name in ["a", "b", "c", "d", "e"] {
        let p = dir.join(name);
        drop(std::fs::File::create(&p));
    }
    let file_path = dir.join("payload.bin");
    {
        let mut f = std::fs::File::create(&file_path).expect("create payload");
        f.write_all(b"kh-boundary-bench").expect("write payload");
    }

    let file_cstr = file_path.to_str().expect("utf8 temp path");
    let dir_cstr = dir.to_str().expect("utf8 temp dir");
    let file_va = write_cstr(base, 0x1000, file_cstr);
    let dir_va = write_cstr(base, 0x1200, dir_cstr);
    let name_buf = guest_va(base, 0x2000);
    let dtype_va = guest_va(base, 0x2100);
    // Park word: value 0; uncontended path uses expected≠0 → no futex sleep.
    let park_off = 0x3000_usize;
    // Align to 4 within the stack mapping.
    let park_va = guest_va(base, park_off & !3);
    guest_write(park_va, &0_u32.to_ne_bytes());

    let mut classes = Vec::with_capacity(4);

    // ── getpid (BSD #20) ───────────────────────────────────────────────────
    {
        let t0 = Instant::now();
        for _ in 0..iters {
            let r = dispatch(args(20, 0, 0, 0));
            assert!(!r.error, "getpid: {:?}", r.retval);
        }
        let total_ns = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        classes.push(ClassTiming {
            id: "getpid",
            label: "getpid",
            iters,
            total_ns,
        });
    }

    // ── open + close (same file) ───────────────────────────────────────────
    {
        let t0 = Instant::now();
        for _ in 0..iters {
            let open = dispatch(args(5, file_va, 0, 0)); // O_RDONLY
            assert!(!open.error, "open: {:?}", open.retval);
            let gfd = open.retval.expect("fd");
            let close = dispatch(args(6, gfd, 0, 0));
            assert!(!close.error, "close: {:?}", close.retval);
        }
        let total_ns = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        classes.push(ClassTiming {
            id: "open_close",
            label: "open+close",
            iters,
            total_ns,
        });
    }

    // ── readdir helper (rewind at EOF) ─────────────────────────────────────
    {
        let open = dispatch(args(5, dir_va, 0, 0));
        assert!(!open.error, "opendir open: {:?}", open.retval);
        let mut gfd = open.retval.expect("dir fd");
        let t0 = Instant::now();
        let mut n = 0_u64;
        while n < iters {
            let r = dispatch(args(KH_HELPER_READDIR, gfd, name_buf, dtype_va));
            assert!(!r.error, "readdir: {:?}", r.retval);
            match r.retval {
                Some(1) => n = n.saturating_add(1),
                Some(0) => {
                    // EOF: re-open directory stream.
                    assert!(!dispatch(args(6, gfd, 0, 0)).error);
                    let open2 = dispatch(args(5, dir_va, 0, 0));
                    assert!(!open2.error, "readdir reopen: {:?}", open2.retval);
                    gfd = open2.retval.expect("dir fd");
                }
                other => panic!("unexpected readdir retval {other:?}"),
            }
        }
        let total_ns = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let _ = dispatch(args(6, gfd, 0, 0));
        classes.push(ClassTiming {
            id: "readdir",
            label: "kh_readdir",
            iters: n,
            total_ns,
        });
    }

    // ── uncontended park (value mismatch → no sleep) ───────────────────────
    {
        let t0 = Instant::now();
        for _ in 0..iters {
            // *park_va == 0; expected == 1 → mismatch, return without futex wait.
            let r = dispatch(args(KH_HELPER_PARK, park_va, 1, 0));
            assert!(!r.error, "park: {:?}", r.retval);
        }
        let total_ns = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        classes.push(ClassTiming {
            id: "park_uncontended",
            label: "kh_park (mismatch / no wait)",
            iters,
            total_ns,
        });
    }

    registry_clear();
    drop(stack);
    drop(std::fs::remove_dir_all(&dir));

    BoundaryClassReport { iters, classes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_class_microbench_smoke() {
        let iters = iters_from_env(DEFAULT_ITERS);
        let report = run_boundary_class_microbench(iters);
        assert_eq!(report.classes.len(), 4);
        for c in &report.classes {
            assert!(c.iters > 0, "{}", c.id);
            assert!(c.total_ns > 0, "{}", c.id);
        }
        // Always print so `cargo test -- --nocapture` shows the ranking.
        eprint!("{}", report.format_report());
    }

    /// Larger sample; opt-in via `--ignored` or the bench script.
    #[test]
    #[ignore = "set KAKEHASHI_BOUNDARY_BENCH_ITERS; run with --ignored --nocapture"]
    fn boundary_class_microbench_large() {
        let iters = iters_from_env(LARGE_ITERS);
        let report = run_boundary_class_microbench(iters);
        eprint!("{}", report.format_report());
        assert_eq!(report.classes.len(), 4);
    }
}
