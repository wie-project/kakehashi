//! Dependency walk helpers for multi-image load (Phase 6 dyld-lite).
//!
//! Main is mapped outside the BFS; this module only enqueues and classifies
//! followable load edges (`LC_LOAD_DYLIB` / weak / reexport).

use std::path::{Path, PathBuf};

use crate::image::{DylibDep, DylibKind, MachOImage};

/// Maximum number of **dylib** images (not counting main).
pub const MAX_DYLIBS: usize = 64;

/// One pending dependency edge in the BFS queue.
#[derive(Debug, Clone)]
pub struct DepEdge {
    /// Install name from the load command.
    pub install_name: String,
    /// Load command kind (Load / Weak / Reexport).
    pub kind: DylibKind,
    /// Host directory of the image that issued this load command.
    pub loader_dir: PathBuf,
    /// Rpath list for resolve: loader rpaths then main rpaths.
    pub rpaths: Vec<String>,
}

/// Returns true when Phase 6 follows this dependency kind as a map edge.
#[must_use]
pub const fn is_followable(kind: DylibKind) -> bool {
    matches!(
        kind,
        DylibKind::Load | DylibKind::Weak | DylibKind::Reexport
    )
}

/// Collects followable deps from an image into BFS edges.
#[must_use]
pub fn edges_from_image(image: &MachOImage, loader_dir: &Path, rpaths: &[String]) -> Vec<DepEdge> {
    image
        .dylibs
        .iter()
        .filter(|dep| is_followable(dep.kind))
        .map(|dep| DepEdge {
            install_name: dep.name.clone(),
            kind: dep.kind,
            loader_dir: loader_dir.to_path_buf(),
            rpaths: rpaths.to_vec(),
        })
        .collect()
}

/// Concatenates loader then main rpath lists (loader first).
#[must_use]
pub fn concat_rpaths(loader_rpaths: &[String], main_rpaths: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(loader_rpaths.len().saturating_add(main_rpaths.len()));
    out.extend(loader_rpaths.iter().cloned());
    out.extend(main_rpaths.iter().cloned());
    out
}

/// Install name for a mapped image: `LC_ID_DYLIB` if present, else fallback.
#[must_use]
pub fn image_install_name(image: &MachOImage, fallback: &str) -> String {
    image
        .dylibs
        .iter()
        .find(|d| d.kind == DylibKind::Id)
        .map_or_else(|| fallback.to_owned(), |d| d.name.clone())
}

/// Filters dylib deps by followable kinds (for tests / inspect helpers).
#[must_use]
pub fn followable_deps(image: &MachOImage) -> Vec<&DylibDep> {
    image
        .dylibs
        .iter()
        .filter(|d| is_followable(d.kind))
        .collect()
}
