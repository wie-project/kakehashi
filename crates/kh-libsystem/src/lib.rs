//! License-clean **libSystem** surface for the Kakehashi bottle (`no_std`).
//!
//! Guest dylib for **aarch64-apple-darwin**, staged as `/usr/lib/libSystem.B.dylib`.
//! Not Apple code. Build product: `libkh_libsystem.dylib` → `./scripts/stage-libsystem.sh`.
//!
//! ## Layout
//!
//! * [`kh_core`] — syscall entry, errno, heap, process, host helpers
//! * [`dylib`] — surfaces mapped to Darwin dylibs (`libsystem_c`, `libcurl`, `libc++`, …)
//! * [`frameworks`] — soft CF / Security / CoreServices
//!
//! ## Build
//!
//! ```bash
//! cargo build -p kh-libsystem --release --target aarch64-apple-darwin
//! ./scripts/stage-libsystem.sh
//! ```

#![no_std]
#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]

#[path = "core/mod.rs"]
mod kh_core;
mod dylib;
mod frameworks;

/// Route Rust `alloc` (miniz_oxide) through freestanding `malloc`/`free`.
struct KhGlobalAlloc;

// SAFETY: forwards to our freestanding heap; layout size is respected.
unsafe impl core::alloc::GlobalAlloc for KhGlobalAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let p = unsafe { crate::kh_core::heap::malloc(layout.size().max(layout.align()).max(1)) };
        p.cast::<u8>()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        unsafe {
            crate::kh_core::heap::free(ptr.cast());
        }
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        _layout: core::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        let p = unsafe { crate::kh_core::heap::realloc(ptr.cast(), new_size.max(1)) };
        p.cast::<u8>()
    }
}

#[global_allocator]
static KH_ALLOC: KhGlobalAlloc = KhGlobalAlloc;

pub use crate::kh_core::errno::__error;
pub use crate::kh_core::heap::{calloc, free, kh_heap_stats_dump, kh_heap_stats_enable, malloc, realloc};
pub use crate::kh_core::helpers::*;
pub use crate::kh_core::process::{exit, exit_now, kh_bottle_mark};
pub use crate::dylib::libsystem_c::stdio::{bzero, memcpy, memmove, memset, puts, strlen, write};

/// Return value of [`kh_bottle_mark`] (fixture / smoke probe).
pub const KH_BOTTLE_MARK_VALUE: i32 = 77;

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo<'_>) -> ! {
    crate::kh_core::trace::note(b"panic in kh-libsystem\n");
    // SAFETY: never returns.
    unsafe {
        crate::kh_core::process::exit_now(127);
    }
}

/// Required when linking freestanding against `libcore`; we never unwind.
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}
