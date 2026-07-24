//! Load session: ties a bottle root, page layout, planned images, and maps.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::path::{Path, PathBuf};

use goblin::mach::header::MH_DYLIB;
use kh_runtime::{GuestMemory, GuestPageSize, HostPageSize, MapRequest, PageLayout};

use crate::bind;
use crate::deps::{DepEdge, MAX_DYLIBS, concat_rpaths, edges_from_image, image_install_name};
use crate::error::LoadError;
use crate::image::{DylibKind, ImagePlan, MachOImage, PlannedMapping};
use crate::link::DefinedSymbol;
use crate::parse;
use crate::rebase;
use crate::resolve::{ResolveContext, ResolveError, resolve_install_name};

/// Role of an image in the process set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageRole {
    /// Main `MH_EXECUTE` (always `images[0]` when mapped).
    Main,
    /// Mapped or skipped dylib dependency.
    Dylib,
}

/// Why a dependency was not mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// Resolved host path does not exist (or soft-failed open).
    MissingPath,
    /// Absolute install name with no bottle root — never probe host FS.
    NoBottle,
    /// Weak load and missing / not allowlisted.
    WeakMissing,
    /// Already loaded under another install name / real path.
    Duplicate,
    /// Lazy/Upward not followed in Phase 6.
    KindNotFollowed,
    /// Resolved path is outside bottle ∪ executable_dir allowlist.
    OutsideAllowlist,
}

impl SkipReason {
    /// Stable dry-load / JSON status suffix (`skipped:<label>`).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MissingPath => "missing_path",
            Self::NoBottle => "no_bottle",
            Self::WeakMissing => "weak_missing",
            Self::Duplicate => "duplicate",
            Self::KindNotFollowed => "kind_not_followed",
            Self::OutsideAllowlist => "outside_allowlist",
        }
    }
}

/// Mapped vs skipped status for one process image entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageLoadStatus {
    /// Image was planned and `mmap`'d.
    Mapped,
    /// Dependency walk soft-skipped this edge.
    Skipped(SkipReason),
}

impl ImageLoadStatus {
    /// Stable status string for dry-load text/JSON.
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Mapped => "mapped".to_owned(),
            Self::Skipped(reason) => format!("skipped:{}", reason.as_str()),
        }
    }
}

/// One image in the process set (mapped or skipped).
#[derive(Debug)]
pub struct ProcessImage {
    /// Main vs dylib.
    pub role: ImageRole,
    /// Host path attempted / opened.
    pub path: PathBuf,
    /// Install name from the load command (or `LC_ID_DYLIB` when mapped).
    pub install_name: String,
    /// Map outcome.
    pub status: ImageLoadStatus,
    /// Present when status is [`ImageLoadStatus::Mapped`].
    pub image: Option<MachOImage>,
    /// Full plan when mapped; [`ImagePlan::empty`] when skipped.
    pub plan: ImagePlan,
    /// Guest mapping when mapped.
    pub memory: Option<GuestMemory>,
    /// How this edge was requested. Main uses [`DylibKind::Load`] as sentinel.
    pub requested_kind: DylibKind,
    /// Defined external nlist symbols (PR2; empty in PR1).
    pub exports: Vec<DefinedSymbol>,
}

impl ProcessImage {
    /// Slide applied to this image (0 if unmapped).
    #[must_use]
    pub fn slide(&self) -> u64 {
        self.memory.as_ref().map_or(0, GuestMemory::slide)
    }

    /// Preferred base from the plan (0 if empty).
    #[must_use]
    pub fn preferred_base(&self) -> u64 {
        self.plan.preferred_base
    }

    /// Region infos for dry-load (empty when skipped).
    #[must_use]
    pub fn region_infos(&self) -> Vec<MappedRegionInfo> {
        let Some(memory) = self.memory.as_ref() else {
            return Vec::new();
        };
        memory
            .regions()
            .iter()
            .map(|r| MappedRegionInfo {
                name: r.name.clone(),
                guest_addr: r.guest_addr,
                host_addr: r.host_addr(),
                host_len: u64::try_from(r.host_len()).unwrap_or(u64::MAX),
                vmsize: r.vmsize,
                file_bytes: r.file_bytes,
                prot: r.prot,
            })
            .collect()
    }
}

/// Configuration and state for loading one guest process image set.
#[derive(Debug)]
pub struct LoadSession {
    /// Path to the main executable.
    pub executable: PathBuf,
    /// Optional bottle root (`KAKEHASHI_ROOT` / `--root`).
    pub root: Option<PathBuf>,
    /// Host/guest page geometry.
    pub pages: PageLayout,
    /// Process image set (main at index 0 when mapped). Source of truth after map.
    pub images: Vec<ProcessImage>,
    /// Legacy mirror of main parse (`images[0].image` after map).
    pub image: Option<MachOImage>,
    /// Legacy mirror of main plan (`images[0].plan` after map).
    pub plan: ImagePlan,
    /// Legacy main memory slot. After map, ownership lives in `images[0].memory`
    /// (GuestMemory is not `Clone`); use [`Self::memory_mut`] / [`Self::images`].
    pub memory: Option<GuestMemory>,
}

/// Result of a successful map-only (`--dry-load`) session.
#[derive(Debug)]
pub struct DryLoadReport {
    /// Path that was mapped (main executable).
    pub path: PathBuf,
    /// Main image slide (0 if preferred base worked).
    pub slide: u64,
    /// Preferred base of the main image.
    pub preferred_base: u64,
    /// Guest page size used for planning.
    pub guest_page_size: u32,
    /// Host page size used for mapping.
    pub host_page_size: u32,
    /// Entry VA after main slide (if known).
    pub entry: Option<u64>,
    /// Concatenated mapped regions (all images) for simple consumers.
    pub regions: Vec<MappedRegionInfo>,
    /// Whether every planned segment on the main image was guest-page aligned.
    pub fully_guest_aligned: bool,
    /// Per-image status (mapped + skipped).
    pub images: Vec<DryLoadImageInfo>,
}

/// One image entry in a dry-load report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryLoadImageInfo {
    /// `"main"` or `"dylib"`.
    pub role: &'static str,
    /// Host path.
    pub path: PathBuf,
    /// Install name.
    pub install_name: String,
    /// `"mapped"` or `"skipped:<reason>"`.
    pub status: String,
    /// Slide (0 if skipped).
    pub slide: u64,
    /// Preferred base (0 if skipped / empty plan).
    pub preferred_base: u64,
    /// Mapped regions for this image.
    pub regions: Vec<MappedRegionInfo>,
}

/// One mapped region for CLI / JSON output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedRegionInfo {
    /// Segment name.
    pub name: String,
    /// Guest VA after slide.
    pub guest_addr: u64,
    /// Host VA (identity model: equals guest when placement succeeds).
    pub host_addr: u64,
    /// Host mapping length.
    pub host_len: u64,
    /// Declared virtual size.
    pub vmsize: u64,
    /// File bytes copied in.
    pub file_bytes: u64,
    /// Darwin `initprot` bits applied.
    pub prot: u32,
}

impl LoadSession {
    /// Starts a session for `executable` with detected host pages and default guest size.
    pub fn open(executable: impl Into<PathBuf>, root: Option<PathBuf>) -> Result<Self, LoadError> {
        Self::open_with_guest(executable, root, GuestPageSize::default())
    }

    /// Starts a session with an explicit guest page policy.
    pub fn open_with_guest(
        executable: impl Into<PathBuf>,
        root: Option<PathBuf>,
        guest: GuestPageSize,
    ) -> Result<Self, LoadError> {
        let host = HostPageSize::detect().map_err(|err| LoadError::PageLayout(err.to_string()))?;
        Ok(Self {
            executable: executable.into(),
            root,
            pages: PageLayout::new(host, guest),
            images: Vec::new(),
            image: None,
            plan: ImagePlan::empty(),
            memory: None,
        })
    }

    /// Executable path.
    #[inline]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// All process images (mapped + skipped), main at index 0 when mapped.
    #[must_use]
    pub fn images(&self) -> &[ProcessImage] {
        &self.images
    }

    /// Mutable view of images (bind / patch prep).
    pub fn images_mut(&mut self) -> &mut [ProcessImage] {
        &mut self.images
    }

    /// Iterator of mapped `GuestMemory` mut refs (main then dylibs, map order).
    pub fn mapped_memories_mut(&mut self) -> impl Iterator<Item = &mut GuestMemory> {
        self.images.iter_mut().filter_map(|img| img.memory.as_mut())
    }

    /// Parses the main executable into an owned image.
    pub fn load_main_image(&mut self) -> Result<&MachOImage, LoadError> {
        if self.image.is_none() {
            let image = parse::parse_path(&self.executable)?;
            self.image = Some(image);
        }
        self.image
            .as_ref()
            .ok_or(LoadError::NotImplemented("image missing after load"))
    }

    /// Parses (if needed) and builds an image plan for the main executable.
    pub fn plan_main_image(&mut self) -> Result<&ImagePlan, LoadError> {
        let _ = self.load_main_image()?;
        let guest = self.pages.guest;
        let Some(image) = self.image.as_ref() else {
            return Err(LoadError::NotImplemented("image missing after load"));
        };
        self.plan = image.plan(guest);
        Ok(&self.plan)
    }

    /// Maps main only into `images = [main]` (no dependency walk).
    ///
    /// Unit tests / simple tooling. Production `dry_load` and `run_micro` use
    /// [`Self::map_process`].
    pub fn map_main_image(&mut self) -> Result<&GuestMemory, LoadError> {
        self.map_main_only()?;
        self.main_memory()
            .ok_or(LoadError::NotImplemented("memory missing after map"))
    }

    /// Map main once, BFS-load allowed dylibs, rebase pointer arrays, bind.
    ///
    /// Order matches a minimal dyld load sequence: map → rebase → bind.
    ///
    /// Bind prefers chained fixups, then classic opcodes, else nlist → `__got`.
    /// Section rebase is skipped for images that use chained fixups.
    pub fn map_process(&mut self) -> Result<&[ProcessImage], LoadError> {
        self.map_main_only()?;
        self.walk_dependencies()?;
        let _ = rebase::rebase_process(self)?;
        bind::bind_process(self)?;
        Ok(self.images())
    }

    /// Maps the process image set and builds a dry-load report for the CLI.
    pub fn dry_load(&mut self) -> Result<DryLoadReport, LoadError> {
        let _ = self.map_process()?;

        let main = self
            .images
            .first()
            .ok_or(LoadError::NotImplemented("main image missing after map"))?;
        let slide = main.slide();
        let preferred_base = main.preferred_base();
        let fully_guest_aligned = main.plan.fully_guest_aligned;
        let entry = main.plan.entry.map(|e| e.wrapping_add(slide));
        let guest_page_size = self.pages.guest_bytes();
        let host_page_size = self.pages.host_bytes();
        let path = self.executable.clone();

        let mut regions = Vec::new();
        let mut image_infos = Vec::with_capacity(self.images.len());
        for img in &self.images {
            let info_regions = img.region_infos();
            if matches!(img.status, ImageLoadStatus::Mapped) {
                regions.extend(info_regions.iter().cloned());
            }
            image_infos.push(DryLoadImageInfo {
                role: match img.role {
                    ImageRole::Main => "main",
                    ImageRole::Dylib => "dylib",
                },
                path: img.path.clone(),
                install_name: img.install_name.clone(),
                status: img.status.as_str(),
                slide: img.slide(),
                preferred_base: img.preferred_base(),
                regions: info_regions,
            });
        }

        Ok(DryLoadReport {
            path,
            slide,
            preferred_base,
            guest_page_size,
            host_page_size,
            entry,
            regions,
            fully_guest_aligned,
            images: image_infos,
        })
    }

    /// Mutable access to main mapped memory (after map).
    pub fn memory_mut(&mut self) -> Option<&mut GuestMemory> {
        if let Some(main) = self.images.first_mut()
            && main.memory.is_some()
        {
            return main.memory.as_mut();
        }
        self.memory.as_mut()
    }

    /// Guest entry VA after main slide, if known.
    #[must_use]
    pub fn entry_va(&self) -> Option<u64> {
        if let Some(main) = self.images.first() {
            let slide = main.slide();
            return main.plan.entry.map(|e| e.wrapping_add(slide));
        }
        let slide = self.memory.as_ref().map_or(0, GuestMemory::slide);
        self.plan.entry.map(|e| e.wrapping_add(slide))
    }

    fn main_memory(&self) -> Option<&GuestMemory> {
        self.images
            .first()
            .and_then(|i| i.memory.as_ref())
            .or(self.memory.as_ref())
    }

    /// Parse + plan + map main into `images[0]`; does not walk deps.
    fn map_main_only(&mut self) -> Result<(), LoadError> {
        // Drop previous process set (unmaps dylibs + main).
        self.images.clear();
        self.memory = None;

        let _ = self.plan_main_image()?;
        let image = self
            .image
            .clone()
            .ok_or(LoadError::NotImplemented("image missing after load"))?;
        let plan = self.plan.clone();
        let requests = map_requests_from_plan(&plan);
        let preferred = plan.preferred_base;
        let mut file = File::open(&self.executable)?;
        let memory = GuestMemory::map_image(self.pages.host, preferred, &requests, &mut file)?;

        let main = ProcessImage {
            role: ImageRole::Main,
            path: self.executable.clone(),
            install_name: self.executable.display().to_string(),
            status: ImageLoadStatus::Mapped,
            image: Some(image),
            plan,
            memory: Some(memory),
            requested_kind: DylibKind::Load,
            exports: Vec::new(),
        };
        self.images.push(main);
        self.mirror_main_legacy();
        Ok(())
    }

    /// BFS dependency walk (main already in `images[0]`).
    fn walk_dependencies(&mut self) -> Result<(), LoadError> {
        let main = self
            .images
            .first()
            .ok_or(LoadError::NotImplemented("main missing before dep walk"))?;
        let main_image = main
            .image
            .as_ref()
            .ok_or(LoadError::NotImplemented("main image missing"))?
            .clone();
        let main_rpaths = main_image.rpaths.clone();
        let exe_dir = self
            .executable
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

        let mut seen_real_paths: HashSet<PathBuf> = HashSet::new();
        if let Some(key) = real_path_key(&self.executable) {
            seen_real_paths.insert(key);
        }

        let mut queue: VecDeque<DepEdge> =
            edges_from_image(&main_image, &exe_dir, &main_rpaths).into();

        while let Some(edge) = queue.pop_front() {
            let dylib_count = self
                .images
                .iter()
                .filter(|i| {
                    i.role == ImageRole::Dylib && matches!(i.status, ImageLoadStatus::Mapped)
                })
                .count();
            if dylib_count >= MAX_DYLIBS {
                return Err(LoadError::TooManyDylibs(MAX_DYLIBS));
            }

            let ctx = ResolveContext {
                bottle_root: self.root.as_deref(),
                executable_dir: &exe_dir,
                loader_dir: &edge.loader_dir,
                rpaths: &edge.rpaths,
            };

            let host_path = match resolve_install_name(&edge.install_name, &ctx) {
                Ok(p) => p,
                Err(ResolveError::InvalidEncoding) => {
                    return Err(LoadError::Resolve(
                        ResolveError::InvalidEncoding.to_string(),
                    ));
                }
                Err(err) => {
                    let reason = skip_reason_from_resolve(&err, edge.kind);
                    self.push_skipped(
                        edge.install_name.clone(),
                        edge.install_name.clone(),
                        edge.kind,
                        reason,
                        &err,
                    );
                    continue;
                }
            };

            if !host_path.exists() {
                let reason = if edge.kind == DylibKind::Weak {
                    SkipReason::WeakMissing
                } else {
                    SkipReason::MissingPath
                };
                log_skip(&edge.install_name, &reason);
                self.push_skipped_path(host_path, edge.install_name.clone(), edge.kind, reason);
                continue;
            }

            if let Some(key) = real_path_key(&host_path)
                && !seen_real_paths.insert(key)
            {
                self.push_skipped_path(
                    host_path,
                    edge.install_name.clone(),
                    edge.kind,
                    SkipReason::Duplicate,
                );
                continue;
            }

            let parsed = parse::parse_path(&host_path)?;
            if parsed.summary.file_type_raw != MH_DYLIB {
                return Err(LoadError::NotDylib(host_path.display().to_string()));
            }

            let plan = parsed.plan(self.pages.guest);
            let requests = map_requests_from_plan(&plan);
            let preferred = plan.preferred_base;
            let mut file = File::open(&host_path)?;
            let memory = GuestMemory::map_image(self.pages.host, preferred, &requests, &mut file)?;

            let install = image_install_name(&parsed, &edge.install_name);
            let loader_dir = host_path
                .parent()
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
            let dylib_rpaths = parsed.rpaths.clone();
            let child_rpaths = concat_rpaths(&dylib_rpaths, &main_rpaths);

            tracing::info!(
                path = %host_path.display(),
                install_name = %install,
                slide = memory.slide(),
                base = preferred,
                "mapped dylib"
            );

            let child_edges = edges_from_image(&parsed, &loader_dir, &child_rpaths);

            self.images.push(ProcessImage {
                role: ImageRole::Dylib,
                path: host_path,
                install_name: install,
                status: ImageLoadStatus::Mapped,
                image: Some(parsed),
                plan,
                memory: Some(memory),
                requested_kind: edge.kind,
                exports: Vec::new(),
            });

            for child in child_edges {
                queue.push_back(child);
            }
        }

        // Main legacy mirrors unchanged by dylibs; re-assert after walk.
        self.mirror_main_legacy();
        Ok(())
    }

    fn push_skipped(
        &mut self,
        path_display: String,
        install_name: String,
        kind: DylibKind,
        reason: SkipReason,
        err: &ResolveError,
    ) {
        log_skip(&install_name, &reason);
        tracing::debug!(
            install_name = %install_name,
            reason = reason.as_str(),
            resolve = %err,
            "skipped dylib"
        );
        self.images.push(ProcessImage {
            role: ImageRole::Dylib,
            path: PathBuf::from(path_display),
            install_name,
            status: ImageLoadStatus::Skipped(reason),
            image: None,
            plan: ImagePlan::empty(),
            memory: None,
            requested_kind: kind,
            exports: Vec::new(),
        });
    }

    fn push_skipped_path(
        &mut self,
        path: PathBuf,
        install_name: String,
        kind: DylibKind,
        reason: SkipReason,
    ) {
        self.images.push(ProcessImage {
            role: ImageRole::Dylib,
            path,
            install_name,
            status: ImageLoadStatus::Skipped(reason),
            image: None,
            plan: ImagePlan::empty(),
            memory: None,
            requested_kind: kind,
            exports: Vec::new(),
        });
    }

    /// Mirrors main parse/plan into legacy fields. Memory stays in `images[0]`.
    fn mirror_main_legacy(&mut self) {
        if let Some(main) = self.images.first() {
            self.image = main.image.clone();
            self.plan = main.plan.clone();
        }
        // GuestMemory is not Clone — ownership remains in images[0].memory.
        self.memory = None;
    }
}

fn skip_reason_from_resolve(err: &ResolveError, kind: DylibKind) -> SkipReason {
    match err {
        ResolveError::NoBottle => SkipReason::NoBottle,
        ResolveError::OutsideAllowlist(_)
        | ResolveError::Escape(_)
        | ResolveError::NestedRpath
        | ResolveError::Empty => {
            if kind == DylibKind::Weak {
                SkipReason::WeakMissing
            } else {
                SkipReason::OutsideAllowlist
            }
        }
        ResolveError::InvalidEncoding => SkipReason::OutsideAllowlist,
    }
}

fn log_skip(install_name: &str, reason: &SkipReason) {
    let is_libsystem = install_name.contains("/usr/lib/libSystem");
    match reason {
        SkipReason::NoBottle | SkipReason::MissingPath if is_libsystem => {
            tracing::debug!(install_name, reason = reason.as_str(), "skip dylib");
        }
        SkipReason::NoBottle
        | SkipReason::MissingPath
        | SkipReason::OutsideAllowlist
        | SkipReason::WeakMissing => {
            tracing::warn!(install_name, reason = reason.as_str(), "skip dylib");
        }
        SkipReason::Duplicate | SkipReason::KindNotFollowed => {
            tracing::debug!(install_name, reason = reason.as_str(), "skip dylib");
        }
    }
}

fn real_path_key(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok().or_else(|| {
        if path.as_os_str().is_empty() {
            None
        } else {
            Some(path.to_path_buf())
        }
    })
}

/// Builds runtime map requests from a planned image.
#[must_use]
pub fn map_requests_from_plan(plan: &ImagePlan) -> Vec<MapRequest> {
    plan.mappings.iter().map(mapping_to_request).collect()
}

fn mapping_to_request(m: &PlannedMapping) -> MapRequest {
    MapRequest {
        name: m.name.clone(),
        preferred_va: m.vmaddr,
        vmsize: m.vmsize,
        fileoff: m.fileoff,
        filesize: m.filesize,
        initprot: m.initprot,
        maxprot: m.maxprot,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::fixture::minimal_arm64_execute;
    use crate::test_util::map_test_lock;
    use std::io::Write;

    fn write_temp_fixture() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kh-session-fixture-{}-{n}.macho",
            std::process::id()
        ));
        let mut f = File::create(&path).expect("create");
        f.write_all(&minimal_arm64_execute()).expect("write");
        path
    }

    #[test]
    fn dry_load_maps_text_skips_pagezero() {
        let _guard = map_test_lock();
        let path = write_temp_fixture();
        let mut session = LoadSession::open(&path, None).expect("open");
        let report = session.dry_load().expect("dry_load");
        assert!(
            report.regions.iter().all(|r| r.name != "__PAGEZERO"),
            "PAGEZERO must not be materialized"
        );
        assert!(
            report.regions.iter().any(|r| r.name == "__TEXT"),
            "expected __TEXT mapping"
        );
        let text = report.regions.iter().find(|r| r.name == "__TEXT").unwrap();
        assert!(text.vmsize >= 0x1000);
        assert!(text.file_bytes > 0);
        assert_eq!(text.guest_addr, text.host_addr);
        drop(session);
        drop(std::fs::remove_file(path));
    }

    #[test]
    fn minimal_fixture_skips_libsystem_no_bottle() {
        let _guard = map_test_lock();
        let path = write_temp_fixture();
        let mut session = LoadSession::open(&path, None).expect("open");
        let images = session.map_process().expect("map_process");
        let main = images.first().expect("main image");
        assert_eq!(main.role, ImageRole::Main);
        assert!(matches!(main.status, ImageLoadStatus::Mapped));
        let skipped: Vec<_> = images
            .iter()
            .filter(|i| matches!(i.status, ImageLoadStatus::Skipped(_)))
            .collect();
        assert!(
            !skipped.is_empty(),
            "expected at least one skipped dylib (libSystem)"
        );
        assert!(
            skipped.iter().any(|i| {
                matches!(i.status, ImageLoadStatus::Skipped(SkipReason::NoBottle))
                    && i.install_name.contains("libSystem")
            }),
            "libSystem must be Skipped(NoBottle), got: {:?}",
            skipped
                .iter()
                .map(|i| (&i.install_name, i.status.as_str()))
                .collect::<Vec<_>>()
        );
        assert!(
            images
                .iter()
                .filter(|i| matches!(i.status, ImageLoadStatus::Mapped))
                .count()
                == 1,
            "only main should be mapped without bottle"
        );
        drop(session);
        drop(std::fs::remove_file(path));
    }

    #[test]
    fn map_main_image_does_not_walk_deps() {
        let _guard = map_test_lock();
        let path = write_temp_fixture();
        let mut session = LoadSession::open(&path, None).expect("open");
        let _ = session.map_main_image().expect("map_main");
        assert_eq!(session.images().len(), 1);
        assert_eq!(
            session.images().first().expect("main").role,
            ImageRole::Main
        );
        drop(session);
        drop(std::fs::remove_file(path));
    }

    #[test]
    fn dry_load_report_lists_skipped_libsystem() {
        let _guard = map_test_lock();
        let path = write_temp_fixture();
        let mut session = LoadSession::open(&path, None).expect("open");
        let report = session.dry_load().expect("dry_load");
        assert!(
            report.images.iter().any(|i| {
                i.role == "dylib"
                    && i.status == "skipped:no_bottle"
                    && i.install_name.contains("libSystem")
            }),
            "dry-load images must include skipped libSystem: {:?}",
            report.images
        );
        drop(session);
        drop(std::fs::remove_file(path));
    }

    #[test]
    fn bottle_libsystem_maps_and_binds() {
        use crate::fixture::{
            CALL_LIBSYSTEM_GOT_VA, KH_BOTTLE_MARK_SYMBOL, LIBSYSTEM_INSTALL_NAME,
            arm64_libsystem_stub, call_libsystem_exit,
        };
        use std::sync::atomic::{AtomicU64, Ordering};

        static N: AtomicU64 = AtomicU64::new(0);
        let _guard = map_test_lock();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("kh-bottle-session-{}-{n}", std::process::id()));
        let bottle = dir.join("bottle");
        let lib_dir = bottle.join("usr/lib");
        std::fs::create_dir_all(&lib_dir).expect("mkdir bottle");
        let main_path = dir.join("call_libsystem.macho");
        let sys_path = lib_dir.join("libSystem.B.dylib");
        {
            let mut f = File::create(&main_path).expect("create main");
            f.write_all(&call_libsystem_exit()).expect("write main");
        }
        {
            let mut f = File::create(&sys_path).expect("create libSystem");
            f.write_all(&arm64_libsystem_stub()).expect("write stub");
        }

        let mut session = LoadSession::open(&main_path, Some(bottle.clone())).expect("open");
        let report = session.dry_load().expect("dry_load with bottle");
        assert!(
            report.images.iter().any(|i| {
                i.role == "dylib"
                    && i.status == "mapped"
                    && i.install_name == LIBSYSTEM_INSTALL_NAME
            }),
            "libSystem must map under bottle: {:?}",
            report.images
        );
        assert!(
            !report
                .images
                .iter()
                .any(|i| i.status.starts_with("skipped:")),
            "no skips expected when bottle has libSystem: {:?}",
            report.images
        );

        // Re-open to re-map (dry_load already bound).
        drop(session);
        let mut session = LoadSession::open(&main_path, Some(bottle)).expect("reopen");
        let _ = session.map_process().expect("map_process");
        let main = session.images().first().expect("main");
        let main_slide = main.slide();
        let export_va = session
            .images()
            .iter()
            .find(|i| {
                i.role == ImageRole::Dylib
                    && matches!(i.status, ImageLoadStatus::Mapped)
                    && i.install_name == LIBSYSTEM_INSTALL_NAME
            })
            .and_then(|dylib| {
                dylib
                    .exports
                    .iter()
                    .find(|e| e.name == KH_BOTTLE_MARK_SYMBOL)
                    .map(|e| e.value.wrapping_add(dylib.slide()))
            })
            .expect("libSystem export");

        let got_va = CALL_LIBSYSTEM_GOT_VA.wrapping_add(main_slide);
        let main_mem = session
            .images()
            .first()
            .and_then(|i| i.memory.as_ref())
            .expect("main mem");
        let region = main_mem
            .regions()
            .iter()
            .find(|r| got_va >= r.guest_addr && got_va < r.guest_addr.saturating_add(r.vmsize))
            .expect("DATA region");
        let off = usize::try_from(got_va.saturating_sub(region.guest_addr)).unwrap();
        let end = off.saturating_add(8);
        let bytes = region.host_bytes().get(off..end).expect("got bytes");
        let mut le = [0_u8; 8];
        le.copy_from_slice(bytes);
        assert_eq!(u64::from_le_bytes(le), export_va);

        drop(session);
        drop(std::fs::remove_dir_all(dir));
    }

    #[test]
    fn call_libsystem_without_bottle_fails_bind() {
        use crate::error::LoadError;
        use crate::fixture::call_libsystem_exit;
        use std::sync::atomic::{AtomicU64, Ordering};

        static N: AtomicU64 = AtomicU64::new(0);
        let _guard = map_test_lock();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kh-call-libsys-nobottle-{}-{n}.macho",
            std::process::id()
        ));
        {
            let mut f = File::create(&path).expect("create");
            f.write_all(&call_libsystem_exit()).expect("write");
        }
        let mut session = LoadSession::open(&path, None).expect("open");
        let err = session.map_process().expect_err("bind must fail");
        assert!(
            matches!(err, LoadError::UnresolvedSymbol { .. }),
            "expected UnresolvedSymbol, got {err:?}"
        );
        // Soft-skip still recorded before bind fails.
        assert!(
            session.images().iter().any(|i| {
                matches!(i.status, ImageLoadStatus::Skipped(SkipReason::NoBottle))
                    && i.install_name.contains("libSystem")
            }),
            "libSystem should be skipped:no_bottle before bind fail: {:?}",
            session
                .images()
                .iter()
                .map(|i| (i.install_name.as_str(), i.status.as_str()))
                .collect::<Vec<_>>()
        );
        drop(session);
        drop(std::fs::remove_file(path));
    }
}
