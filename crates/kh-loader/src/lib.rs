//! Mach-O loading, image planning, and process session orchestration.
//!
//! Depends on `kh-runtime` for page geometry and register types.
//! Must not depend on `kh-cli`.

pub mod bind;
pub mod chained;
pub mod deps;
pub mod error;
pub mod execute;
pub mod file_image;
pub mod image;
pub mod init;
pub mod link;
pub mod load_timing;
pub mod missing_stub;
pub mod parse;
pub mod rebase;
pub mod resolve;
pub mod session;

pub use bind::{
    BindResolveCache, BindSite, bind_process, bind_process_with_flat, collect_bind_sites,
    encode_pointer_bind,
};
pub use chained::{
    ChainDecode, ChainedImport, DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET,
    DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND, DYLD_CHAINED_PTR_ARM64E_USERLAND24,
    apply_chained_fixups,
    bytes_have_chained_fixups, decode_ptr, decode_ptr_64, encode_chained_fixups_blob,
    encode_ptr_64_bind, encode_ptr_64_rebase, image_has_chained_fixups,
};
pub use deps::{DepEdge, MAX_DYLIBS, is_followable};
pub use error::LoadError;
pub use execute::{RunOptions, RunResult, run_micro};
pub use file_image::FileImage;
pub use image::{
    DylibDep, DylibKind, ImagePlan, LoadCommandInfo, MachOImage, MachOSummary, PlannedMapping,
    SectionInfo, SegmentInfo,
};
pub use init::{
    InitFunc, S_INIT_FUNC_OFFSETS, S_MOD_INIT_FUNC_POINTERS, collect_mod_init, plan_initializers,
    run_initializers,
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
