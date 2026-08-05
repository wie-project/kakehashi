//! Opt-in hypercall / BSD dispatch counters (`KAKEHASHI_BOUNDARY_STATS`).
//!
//! Roadmap2 M0: prove crossing counts (and optional host-side time in
//! `syscall::dispatch`) without changing guest results when disabled.
//!
//! Hot path when **off**: one `AtomicU8` load + branch. No format, no hash,
//! no `thread_local!`, no work under guest TPIDR (this module only runs on the
//! host path after hypercall TLS enter).

use std::fmt::Write as _;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::Instant;

use super::helpers::{
    KH_HELPER_BASE, KH_HELPER_GETADDRINFO, KH_HELPER_GUEST_HOME, KH_HELPER_HEAP_STATS_ON,
    KH_HELPER_NCPU, KH_HELPER_PARK, KH_HELPER_PRINTF, KH_HELPER_PUTS, KH_HELPER_READDIR,
    KH_HELPER_VERIFY_CERT, KH_HELPER_WAKE, KH_HELPER_YIELD, is_helper,
};
use super::table::name_of;

/// BSD / residual numbers in `0..BSD_SLOTS` get dedicated counters.
const BSD_SLOTS: usize = 512;
/// Helper id = `number & 0xFFFF` when `is_helper`; low ids are dense today.
const HELPER_SLOTS: usize = 64;
/// Max lines in the ranked dump (non-zero buckets).
const DUMP_TOP: usize = 40;

const MODE_UNINIT: u8 = 0;
const MODE_OFF: u8 = 1;
const MODE_COUNT: u8 = 2;
const MODE_COUNT_NS: u8 = 3;

static MODE: AtomicU8 = AtomicU8::new(MODE_UNINIT);

static TOTAL: AtomicU64 = AtomicU64::new(0);
static OTHER: AtomicU64 = AtomicU64::new(0);
static NS_TOTAL: AtomicU64 = AtomicU64::new(0);
static NS_OTHER: AtomicU64 = AtomicU64::new(0);
/// First / last number that landed in the overflow ("other") bucket.
static OTHER_FIRST: AtomicU64 = AtomicU64::new(0);
static OTHER_LAST: AtomicU64 = AtomicU64::new(0);

// Array-of-atomics zero init requires a const AtomicU64 (clippy allows here only).
#[allow(clippy::declare_interior_mutable_const)]
static BSD_COUNT: [AtomicU64; BSD_SLOTS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; BSD_SLOTS]
};
#[allow(clippy::declare_interior_mutable_const)]
static BSD_NS: [AtomicU64; BSD_SLOTS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; BSD_SLOTS]
};
#[allow(clippy::declare_interior_mutable_const)]
static HELPER_COUNT: [AtomicU64; HELPER_SLOTS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; HELPER_SLOTS]
};
#[allow(clippy::declare_interior_mutable_const)]
static HELPER_NS: [AtomicU64; HELPER_SLOTS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; HELPER_SLOTS]
};

/// Token from [`begin`]; holds optional start instant when ns mode is on.
#[derive(Debug, Clone, Copy)]
pub(super) struct BoundaryToken {
    timing: bool,
    start: Option<Instant>,
}

/// Re-read env and clear counters (new guest run / tests).
pub(crate) fn reset() {
    MODE.store(mode_from_env(), Ordering::Relaxed);
    clear_counters();
}

fn clear_counters() {
    TOTAL.store(0, Ordering::Relaxed);
    OTHER.store(0, Ordering::Relaxed);
    NS_TOTAL.store(0, Ordering::Relaxed);
    NS_OTHER.store(0, Ordering::Relaxed);
    OTHER_FIRST.store(0, Ordering::Relaxed);
    OTHER_LAST.store(0, Ordering::Relaxed);
    for a in &BSD_COUNT {
        a.store(0, Ordering::Relaxed);
    }
    for a in &BSD_NS {
        a.store(0, Ordering::Relaxed);
    }
    for a in &HELPER_COUNT {
        a.store(0, Ordering::Relaxed);
    }
    for a in &HELPER_NS {
        a.store(0, Ordering::Relaxed);
    }
}

fn mode_from_env() -> u8 {
    match std::env::var_os("KAKEHASHI_BOUNDARY_STATS") {
        None => MODE_OFF,
        Some(v) => {
            if v == "0"
                || v.eq_ignore_ascii_case("false")
                || v.eq_ignore_ascii_case("no")
                || v.eq_ignore_ascii_case("off")
            {
                MODE_OFF
            } else if v.eq_ignore_ascii_case("ns")
                || v.eq_ignore_ascii_case("time")
                || v.eq_ignore_ascii_case("2")
            {
                MODE_COUNT_NS
            } else if v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
                || v.eq_ignore_ascii_case("count")
            {
                MODE_COUNT
            } else {
                // Unknown non-empty value: treat as count (discoverable).
                MODE_COUNT
            }
        }
    }
}

#[inline]
fn resolved_mode() -> u8 {
    let m = MODE.load(Ordering::Relaxed);
    if m != MODE_UNINIT {
        return m;
    }
    let parsed = mode_from_env();
    // First racer wins; both values equivalent for a process lifetime.
    let _ = MODE.compare_exchange(MODE_UNINIT, parsed, Ordering::Relaxed, Ordering::Relaxed);
    MODE.load(Ordering::Relaxed)
}

/// Start of one `dispatch` entry. When stats are off, only a mode load.
#[inline]
pub(super) fn begin() -> BoundaryToken {
    let mode = resolved_mode();
    if mode == MODE_OFF {
        return BoundaryToken {
            timing: false,
            start: None,
        };
    }
    let timing = mode == MODE_COUNT_NS;
    BoundaryToken {
        timing,
        start: if timing { Some(Instant::now()) } else { None },
    }
}

/// End of one `dispatch` entry: bump count (and optional ns) for `number`.
#[inline]
pub(super) fn end(token: BoundaryToken, number: u32) {
    let mode = resolved_mode();
    if mode == MODE_OFF {
        return;
    }

    TOTAL.fetch_add(1, Ordering::Relaxed);

    let ns = if token.timing {
        token.start.map_or(0, |t| {
            u64::try_from(t.elapsed().as_nanos()).unwrap_or(u64::MAX)
        })
    } else {
        0
    };
    if token.timing {
        NS_TOTAL.fetch_add(ns, Ordering::Relaxed);
    }

    if is_helper(number) {
        let id = usize::try_from(number & 0xFFFF).unwrap_or(usize::MAX);
        if let (Some(c), Some(nslot)) = (HELPER_COUNT.get(id), HELPER_NS.get(id)) {
            c.fetch_add(1, Ordering::Relaxed);
            if token.timing {
                nslot.fetch_add(ns, Ordering::Relaxed);
            }
        } else {
            note_other(number, ns, token.timing);
        }
        return;
    }

    let idx = usize::try_from(number).unwrap_or(usize::MAX);
    if let (Some(c), Some(nslot)) = (BSD_COUNT.get(idx), BSD_NS.get(idx)) {
        c.fetch_add(1, Ordering::Relaxed);
        if token.timing {
            nslot.fetch_add(ns, Ordering::Relaxed);
        }
    } else {
        note_other(number, ns, token.timing);
    }
}

#[inline]
fn note_other(number: u32, ns: u64, timing: bool) {
    OTHER.fetch_add(1, Ordering::Relaxed);
    if timing {
        NS_OTHER.fetch_add(ns, Ordering::Relaxed);
    }
    let n = u64::from(number);
    let _ = OTHER_FIRST.compare_exchange(0, n, Ordering::Relaxed, Ordering::Relaxed);
    OTHER_LAST.store(n, Ordering::Relaxed);
}

/// Dump ranked counters when `KAKEHASHI_BOUNDARY_STATS` enables counting.
///
/// Safe under host TPIDR at process exit (`finish_with_exit_code`).
pub(crate) fn dump_if_enabled() {
    let mode = resolved_mode();
    if mode == MODE_OFF {
        return;
    }
    let with_ns = mode == MODE_COUNT_NS;
    let total = TOTAL.load(Ordering::Relaxed);
    if total == 0 {
        drop(io::stderr().write_all(b"kh boundary stats: total=0 (no dispatches)\n"));
        return;
    }

    let mut rows: Vec<(u64, u64, u32, &'static str)> = Vec::with_capacity(64);

    for (i, c) in BSD_COUNT.iter().enumerate() {
        let count = c.load(Ordering::Relaxed);
        if count == 0 {
            continue;
        }
        let num = u32::try_from(i).unwrap_or(u32::MAX);
        let ns = if with_ns {
            BSD_NS.get(i).map_or(0, |a| a.load(Ordering::Relaxed))
        } else {
            0
        };
        let label = name_of(num).unwrap_or("bsd");
        rows.push((count, ns, num, label));
    }

    for (i, c) in HELPER_COUNT.iter().enumerate() {
        let count = c.load(Ordering::Relaxed);
        if count == 0 {
            continue;
        }
        let num = KH_HELPER_BASE | u32::try_from(i).unwrap_or(0);
        let ns = if with_ns {
            HELPER_NS.get(i).map_or(0, |a| a.load(Ordering::Relaxed))
        } else {
            0
        };
        rows.push((count, ns, num, helper_name(num)));
    }

    let other = OTHER.load(Ordering::Relaxed);
    if other != 0 {
        let ns = if with_ns {
            NS_OTHER.load(Ordering::Relaxed)
        } else {
            0
        };
        // num field unused for label; first/last printed in footer.
        rows.push((other, ns, 0, "other(>=512 or helper id>=64)"));
    }

    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.2.cmp(&b.2)));

    let mode_s = if with_ns { "count+ns" } else { "count" };
    let ns_total = NS_TOTAL.load(Ordering::Relaxed);
    let mut out = format!(
        "kh boundary stats: total={total}  mode={mode_s}  unique_buckets={}\n",
        rows.len()
    );
    if with_ns {
        // Integer ms only (avoid f64 / precision clippy on cold dump path).
        let ms = ns_total.checked_div(1_000_000).unwrap_or(0);
        let _ = writeln!(out, "\thost_dispatch_ns_sum={ns_total}  (~{ms} ms)");
    }
    out.push_str("\trank  count");
    if with_ns {
        out.push_str("         ns  avg_ns");
    }
    out.push_str("  name (#num)\n");

    for (rank, (count, ns, num, label)) in rows.into_iter().take(DUMP_TOP).enumerate() {
        let rank_n = rank.saturating_add(1);
        if with_ns {
            let avg = ns.checked_div(count).unwrap_or(0);
            let _ = writeln!(
                out,
                "\t{rank_n:>4}  {count:>8}  {ns:>10}  {avg:>7}  {label} ({num:#x})"
            );
        } else {
            let _ = writeln!(out, "\t{rank_n:>4}  {count:>8}  {label} ({num:#x})");
        }
    }
    if other != 0 {
        let first = OTHER_FIRST.load(Ordering::Relaxed);
        let last = OTHER_LAST.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "\tother sample: first={first:#x} last={last:#x}  (unknown BSD / out-of-range; often spin ENOSYS)"
        );
    }
    drop(io::stderr().write_all(out.as_bytes()));
}

fn helper_name(number: u32) -> &'static str {
    match number {
        KH_HELPER_PUTS => "kh_puts",
        KH_HELPER_PRINTF => "kh_printf",
        KH_HELPER_READDIR => "kh_readdir",
        KH_HELPER_YIELD => "kh_yield",
        KH_HELPER_NCPU => "kh_ncpu",
        KH_HELPER_PARK => "kh_park",
        KH_HELPER_WAKE => "kh_wake",
        KH_HELPER_GETADDRINFO => "kh_getaddrinfo",
        KH_HELPER_VERIFY_CERT => "kh_verify_cert",
        KH_HELPER_GUEST_HOME => "kh_guest_home",
        KH_HELPER_HEAP_STATS_ON => "kh_heap_stats_on",
        _ => "kh_helper",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process as proc_state;

    fn force_mode(mode: u8) {
        MODE.store(mode, Ordering::Relaxed);
        clear_counters();
    }

    #[test]
    fn off_path_does_not_count() {
        let _g = proc_state::test_lock();
        force_mode(MODE_OFF);
        let t = begin();
        end(t, 20);
        assert_eq!(TOTAL.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn count_path_buckets_bsd_and_helper() {
        let _g = proc_state::test_lock();
        force_mode(MODE_COUNT);
        for _ in 0..3 {
            let t = begin();
            end(t, 20); // getpid
        }
        let t = begin();
        end(t, KH_HELPER_PARK);
        let t = begin();
        end(t, KH_HELPER_PARK);

        assert_eq!(TOTAL.load(Ordering::Relaxed), 5);
        assert_eq!(
            BSD_COUNT
                .get(20)
                .map_or(0, |a| a.load(Ordering::Relaxed)),
            3
        );
        let park_id = usize::try_from(KH_HELPER_PARK & 0xFFFF).unwrap_or(0);
        assert_eq!(
            HELPER_COUNT
                .get(park_id)
                .map_or(0, |a| a.load(Ordering::Relaxed)),
            2
        );
        assert_eq!(helper_name(KH_HELPER_PARK), "kh_park");
        assert_eq!(name_of(20), Some("getpid"));
    }

    #[test]
    fn count_ns_records_nonzero_elapsed() {
        let _g = proc_state::test_lock();
        force_mode(MODE_COUNT_NS);
        let t = begin();
        std::thread::sleep(std::time::Duration::from_micros(50));
        end(t, 4); // write
        assert_eq!(
            BSD_COUNT
                .get(4)
                .map_or(0, |a| a.load(Ordering::Relaxed)),
            1
        );
        assert!(BSD_NS.get(4).map_or(0, |a| a.load(Ordering::Relaxed)) > 0);
        assert!(NS_TOTAL.load(Ordering::Relaxed) > 0);
    }
}
