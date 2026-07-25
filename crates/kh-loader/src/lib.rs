//! Mach-O loading, image planning, and process session orchestration.
//!
//! Depends on `kh-runtime` for page geometry and register types.
//! Must not depend on `kh-cli`.

pub mod bind;
pub mod chained;
pub mod deps;
pub mod error;
pub mod execute;
pub mod fixture;
pub mod image;
pub mod init;
pub mod link;
pub mod parse;
pub mod rebase;
pub mod resolve;
pub mod session;

pub use bind::{BindSite, bind_process, collect_bind_sites, encode_pointer_bind};
pub use chained::{
    ChainDecode, ChainedImport, DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET,
    apply_chained_fixups, bytes_have_chained_fixups, decode_ptr_64, encode_chained_fixups_blob,
    encode_ptr_64_bind, encode_ptr_64_rebase, image_has_chained_fixups,
};
pub use deps::{DepEdge, MAX_DYLIBS, is_followable};
pub use error::LoadError;
pub use execute::{RunOptions, RunResult, run_micro};
pub use image::{
    DylibDep, DylibKind, ImagePlan, LoadCommandInfo, MachOImage, MachOSummary, PlannedMapping,
    SectionInfo, SegmentInfo,
};
pub use init::{
    InitFunc, S_MOD_INIT_FUNC_POINTERS, collect_mod_init, plan_initializers, run_initializers,
};
pub use link::{DefinedSymbol, UndefinedSymbol, defined_exports, undefined_imports};
pub use parse::{
    Arm64Slice, locate_arm64_slice, parse_bytes, parse_path, read_thin_arm64, thin_arm64_bytes,
};
pub use rebase::{
    S_INTERPOSING, S_LITERAL_POINTERS, S_MOD_TERM_FUNC_POINTERS, is_rebasable_section_type,
    rebase_image, rebase_memory, rebase_process,
};
// Note: `S_MOD_INIT_FUNC_POINTERS` is exported from `init` (same numeric value).
pub use resolve::{ResolveContext, ResolveError, resolve_install_name};
pub use session::{
    DryLoadImageInfo, DryLoadReport, ImageLoadStatus, ImageRole, LoadSession, MappedRegionInfo,
    ProcessImage, SkipReason, map_requests_from_plan,
};

#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod test_util {
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

    /// Serialize identity-map unit tests so preferred-VA races under
    /// `MAP_FIXED_NOREPLACE` (Linux) do not flake as `PlacementFailed`.
    pub(crate) fn map_test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Unique path under the system temp directory.
    pub(crate) fn temp_path(prefix: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("kh-{prefix}-{}-{n}", std::process::id()))
    }

    /// Write `bytes` to a new unique temp file; returns the path.
    pub(crate) fn write_temp_bytes(prefix: &str, bytes: &[u8]) -> PathBuf {
        let path = temp_path(prefix);
        let mut f = File::create(&path).expect("create temp");
        f.write_all(bytes).expect("write temp");
        path
    }

    /// Create a unique temp directory.
    pub(crate) fn temp_dir(prefix: &str) -> PathBuf {
        let dir = temp_path(prefix);
        std::fs::create_dir_all(&dir).expect("mkdir temp");
        dir
    }

    /// Write a file under `dir` (creating parents as needed).
    pub(crate) fn write_under(dir: &Path, rel: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir parent");
        }
        let mut f = File::create(&path).expect("create under");
        f.write_all(bytes).expect("write under");
        path
    }
}
