//! License-clean **libSystem** surface for the Kakehashi bottle (`no_std`).
//!
//! Guest dylib compiled for **aarch64-apple-darwin**, shipped as
//! `/usr/lib/libSystem.B.dylib` inside the bottle. Not Apple code; no
//! proprietary blobs. Build product is `libkh_libsystem.dylib`; stage with
//! `./scripts/stage-libsystem.sh` into
//! `crates/kh-runtime/resources/libSystem.B.dylib` (crates.io embed for
//! `cargo install kakehashi` → `kh bottle ensure`).
//!
//! ## Architecture
//!
//! * All libSystem / libc C ABI lives **here** — not in `kh-runtime` / `kh-loader`.
//! * Bodies use Darwin `svc #0x80` (`x16` = BSD number) or Kakehashi host helpers
//!   (`0x4B48_xxxx`) so `kh-runtime` trap translation can run them on Linux aarch64.
//! * Trace lines go to guest stderr (fd 2) for `kh run` / `kh trace`.
//!
//! ## Build (not part of default Linux workspace build)
//!
//! ```bash
//! rustup target add aarch64-apple-darwin   # when cross-building
//! cargo build -p kh-libsystem --release --target aarch64-apple-darwin
//! # → target/aarch64-apple-darwin/release/libkh_libsystem.dylib
//! ./scripts/stage-libsystem.sh
//! # → crates/kh-runtime/resources/libSystem.B.dylib  (commit for crates.io)
//! kh bottle create               # copies + sets LC_ID_DYLIB to /usr/lib/...
//! ```
//!
//! Default `cargo test` / `cargo clippy` use workspace `default-members` and
//! **exclude** this crate. Explicit Linux builds of this package are unsupported
//! for the product dylib.

#![no_std]
#![allow(unsafe_code)] // guest C ABI + raw Darwin SVC
#![allow(clippy::missing_safety_doc)]

mod apple_stubs;
mod curl;
mod cxxabi;
mod errno;
mod extra_stubs;
mod heap;
mod iconv;
mod locale;
mod net;
mod posix;
mod process;
mod pthread;
mod rtti;
mod stdio;
mod string;
mod sys;
mod trace;
mod zlib;

/// Route Rust `alloc` (miniz_oxide) through freestanding `malloc`/`free`.
struct KhGlobalAlloc;

// SAFETY: forwards to our freestanding heap; layout size is respected.
unsafe impl core::alloc::GlobalAlloc for KhGlobalAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let p = unsafe { heap::malloc(layout.size().max(layout.align()).max(1)) };
        p.cast::<u8>()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        unsafe {
            heap::free(ptr.cast());
        }
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        _layout: core::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        let p = unsafe { heap::realloc(ptr.cast(), new_size.max(1)) };
        p.cast::<u8>()
    }
}

#[global_allocator]
static KH_ALLOC: KhGlobalAlloc = KhGlobalAlloc;

pub use errno::__error;
pub use heap::{calloc, free, kh_heap_stats_dump, kh_heap_stats_enable, malloc, realloc};
pub use process::{exit, exit_now, kh_bottle_mark};
pub use stdio::{bzero, memcpy, memmove, memset, puts, strlen, write};

/// Return value of [`kh_bottle_mark`] (fixture / smoke probe).
pub const KH_BOTTLE_MARK_VALUE: i32 = 77;

/// Host-helper id for `_puts` (must match `kh_runtime` helpers).
pub const KH_HELPER_PUTS: u32 = 0x4B48_0001;
/// Host-helper id for minimal `_printf` (literal format only).
pub const KH_HELPER_PRINTF: u32 = 0x4B48_0002;
/// Host-helper id for `readdir` next entry.
pub const KH_HELPER_READDIR: u32 = 0x4B48_0003;
/// Host-helper id for `sched_yield` / pthread backoff.
pub const KH_HELPER_YIELD: u32 = 0x4B48_0004;
/// Host-helper id for online CPU count (`sysconf(_SC_NPROCESSORS_ONLN)`).
pub const KH_HELPER_NCPU: u32 = 0x4B48_0005;
/// Host-helper id: park while `*u32 == expected` (futex wait).
pub const KH_HELPER_PARK: u32 = 0x4B48_0006;
/// Host-helper id: wake park waiters on a `u32` address.
pub const KH_HELPER_WAKE: u32 = 0x4B48_0007;
/// Host-helper id: `getaddrinfo` → packed sockaddr list in guest buffer.
pub const KH_HELPER_GETADDRINFO: u32 = 0x4B48_0008;
/// Host-helper id: TLS cert chain verify against bottle CA bundle.
pub const KH_HELPER_VERIFY_CERT: u32 = 0x4B48_0009;
/// Host-helper id: guest HOME path (`/Volumes/linux…` or `/var/root`) into buffer.
pub const KH_HELPER_GUEST_HOME: u32 = 0x4B48_000A;
/// Host-helper id: non-zero when host wants freestanding heap stats dump.
pub const KH_HELPER_HEAP_STATS_ON: u32 = 0x4B48_000B;
/// Host-helper id: HTTP(S) perform for freestanding libcurl (`KhHttpReq` in guest).
pub const KH_HELPER_HTTP: u32 = 0x4B48_000C;

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo<'_>) -> ! {
    trace::note(b"panic in kh-libsystem\n");
    // SAFETY: never returns.
    unsafe {
        process::exit_now(127);
    }
}

/// Required when linking freestanding against `libcore`; we never unwind.
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
