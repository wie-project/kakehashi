//! Late `dlopen` of a guest dylib (installed by `kh-loader` at run start).
//!
//! `kh-runtime` must not depend on the loader. The loader registers a function
//! pointer so `KH_HELPER_DLOPEN` can map a file that was not in the startup
//! image set (otool-classic → `../lib/libLTO.dylib`).

use std::path::Path;
use std::sync::Mutex;

/// `host_path`, `guest_path` → dyld-table handle, or `None`.
pub type DlopenLoadFn = fn(&Path, &str) -> Option<u64>;

static LOADER: Mutex<Option<DlopenLoadFn>> = Mutex::new(None);

/// Install the on-demand dylib mapper. Called once from `run_micro`.
pub fn set_dlopen_loader(f: DlopenLoadFn) {
    if let Ok(mut g) = LOADER.lock() {
        *g = Some(f);
    }
}

/// Map `host` into the live guest and return a `dlopen` handle.
#[must_use]
pub fn try_dlopen_load(host: &Path, guest: &str) -> Option<u64> {
    let f = LOADER.lock().ok().and_then(|g| *g)?;
    f(host, guest)
}
