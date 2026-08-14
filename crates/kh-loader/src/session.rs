//! Load session: ties a bottle root, page layout, planned images, and maps.

use std::collections::{HashMap, HashSet, VecDeque};
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
    /// Canonical (or best-effort absolute) path, computed **once** at insert.
    ///
    /// Used for duplicate detection and bottle alias matching (`libc++` →
    /// `libSystem`) without re-running `canonicalize` / `readlinkat` on every
    /// bind site (roadmap A4).
    pub real_path: PathBuf,
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
    /// Preferred-VA index of [`Self::exports`] for O(1) bind / chained resolve.
    ///
    /// Built in `fill_exports` (same pass as the nlist scan). Includes the
    /// `dyld_stub_binder` → `_dyld_stub_binder` alias when present.
    pub export_by_name: HashMap<String, u64>,
    /// Full on-disk container from the first parse (`mmap` preferred).
    ///
    /// Reused for (1) segment fill without a second disk pass and (2) bind /
    /// chained fixups (arm64 thin view). Any guest benefits — not tool-specific.
    /// Taken/dropped during bind after use.
    pub file_bytes: Option<crate::FileImage>,
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

/// Parsed + planned main image held only until [`LoadSession::map_main_only`]
/// moves ownership into `images[0]`.
#[derive(Debug)]
struct StagedMain {
    image: MachOImage,
    plan: ImagePlan,
    /// Full container (fat or thin) from `parse_path_with_bytes`.
    file_bytes: crate::FileImage,
}

/// Configuration and state for loading one guest process image set.
///
/// **Ownership model:** after map, `images` is the single source of truth for
/// parse / plan / `GuestMemory`. Before map, the main executable may live in
/// private staging only (no duplicated top-level fields).
#[derive(Debug)]
pub struct LoadSession {
    /// Path to the main executable.
    pub executable: PathBuf,
    /// Optional bottle root (`KAKEHASHI_ROOT` / `--root`).
    pub root: Option<PathBuf>,
    /// Host/guest page geometry.
    pub pages: PageLayout,
    /// Process image set (main at index 0 when mapped). Sole owner after map.
    pub images: Vec<ProcessImage>,
    /// Pre-map main parse/plan; cleared when main is pushed into `images`.
    staged_main: Option<StagedMain>,
    /// Extra install names mapped as if the main image had `LC_LOAD_DYLIB`
    /// for them (`otool-classic -t -v` → sibling `libLTO.dylib`).
    extra_seed_dylibs: Vec<String>,
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
            staged_main: None,
            extra_seed_dylibs: Vec::new(),
        })
    }

    /// Map `install_name` during the dependency walk (in addition to `LC_LOAD_*`).
    pub fn seed_dylib(&mut self, install_name: impl Into<String>) {
        let name = install_name.into();
        if name.is_empty() {
            return;
        }
        if !self.extra_seed_dylibs.iter().any(|s| s == &name) {
            self.extra_seed_dylibs.push(name);
        }
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

    /// Parses the main executable into staged (or already mapped) state.
    pub fn load_main_image(&mut self) -> Result<&MachOImage, LoadError> {
        self.main_image_ref()
    }

    /// Parses (if needed) and builds an image plan for the main executable.
    pub fn plan_main_image(&mut self) -> Result<&ImagePlan, LoadError> {
        self.main_plan_ref()
    }

    /// Parse + plan + map the session executable only (no dependency walk).
    ///
    /// Used for late `dlopen` of a single dylib already resolved on the host.
    pub fn map_standalone(&mut self) -> Result<(), LoadError> {
        self.map_main_only()
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

    /// Main image: mapped `images[0]` or staged pre-map parse.
    fn main_image_ref(&mut self) -> Result<&MachOImage, LoadError> {
        if self
            .images
            .first()
            .and_then(|img| img.image.as_ref())
            .is_some()
        {
            return self
                .images
                .first()
                .and_then(|img| img.image.as_ref())
                .ok_or(LoadError::NotImplemented("image missing after load"));
        }
        self.ensure_staged_main()?;
        self.staged_main
            .as_ref()
            .map(|s| &s.image)
            .ok_or(LoadError::NotImplemented("image missing after load"))
    }

    /// Main plan: mapped `images[0]` or staged pre-map plan.
    fn main_plan_ref(&mut self) -> Result<&ImagePlan, LoadError> {
        if self
            .images
            .first()
            .is_some_and(|img| matches!(img.status, ImageLoadStatus::Mapped) && img.image.is_some())
        {
            return self
                .images
                .first()
                .map(|img| &img.plan)
                .ok_or(LoadError::NotImplemented("plan missing after map"));
        }
        self.ensure_staged_main()?;
        self.staged_main
            .as_ref()
            .map(|s| &s.plan)
            .ok_or(LoadError::NotImplemented("plan missing after load"))
    }

    /// Ensures `staged_main` holds a parse + plan for the executable.
    fn ensure_staged_main(&mut self) -> Result<(), LoadError> {
        if self.staged_main.is_some() {
            return Ok(());
        }
        let (image, file_bytes) = parse::parse_path_with_bytes(&self.executable)?;
        let plan = image.plan(self.pages.guest);
        self.staged_main = Some(StagedMain {
            image,
            plan,
            file_bytes,
        });
        Ok(())
    }

    /// Map main once, BFS-load allowed dylibs, rebase pointer arrays, bind.
    ///
    /// Order matches a minimal dyld load sequence: map → rebase → bind.
    ///
    /// Bind prefers chained fixups, then classic opcodes, else nlist → `__got`.
    /// Section rebase is skipped for images that use chained fixups.
    pub fn map_process(&mut self) -> Result<&[ProcessImage], LoadError> {
        // parse_main + mmap_main recorded inside map_main_only when timing is on.
        self.map_main_only()?;
        crate::load_timing::time_result("walk_deps", || self.walk_dependencies())?;
        let _ = crate::load_timing::time_result("rebase", || rebase::rebase_process(self))?;
        // bind records sub-phases (fill_exports / chained|sites / apply).
        bind::bind_process(self)?;
        if crate::load_timing::enabled() {
            let mapped = self
                .images
                .iter()
                .filter(|i| matches!(i.status, ImageLoadStatus::Mapped))
                .count();
            let skipped = self.images.len().saturating_sub(mapped);
            let mut file_bytes: u64 = 0;
            for img in &self.images {
                if !matches!(img.status, ImageLoadStatus::Mapped) {
                    continue;
                }
                if let Ok(meta) = std::fs::metadata(&img.path) {
                    file_bytes = file_bytes.saturating_add(meta.len());
                }
            }
            crate::load_timing::note(format!(
                "images mapped={mapped} skipped={skipped} file_bytes={file_bytes}"
            ));
            for img in &self.images {
                if matches!(img.status, ImageLoadStatus::Mapped) {
                    let sz = std::fs::metadata(&img.path).map_or(0, |m| m.len());
                    crate::load_timing::note(format!(
                        "  {}  bytes={sz}  {}",
                        match img.role {
                            ImageRole::Main => "main ",
                            ImageRole::Dylib => "dylib",
                        },
                        img.path.display()
                    ));
                }
            }
        }
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
        self.images
            .first_mut()
            .and_then(|main| main.memory.as_mut())
    }

    /// Guest entry VA after main slide, if known.
    #[must_use]
    pub fn entry_va(&self) -> Option<u64> {
        if let Some(main) = self.images.first() {
            let slide = main.slide();
            return main.plan.entry.map(|e| e.wrapping_add(slide));
        }
        // Pre-map: preferred entry without slide (placement not yet known).
        self.staged_main.as_ref().and_then(|s| s.plan.entry)
    }

    fn main_memory(&self) -> Option<&GuestMemory> {
        self.images.first().and_then(|i| i.memory.as_ref())
    }

    /// Parse + plan + map main into `images[0]`; does not walk deps.
    fn map_main_only(&mut self) -> Result<(), LoadError> {
        // Drop previous process set (unmaps dylibs + main via GuestMemory Drop).
        self.images.clear();

        crate::load_timing::time_result("parse_main", || self.ensure_staged_main())?;
        let StagedMain {
            image,
            plan,
            file_bytes,
        } = self
            .staged_main
            .take()
            .ok_or(LoadError::NotImplemented("image missing after load"))?;
        let requests = map_requests_from_plan(&plan);
        let preferred = plan.preferred_base;
        // Prefer path/`File` map so host-page-aligned interiors use file-backed
        // `MAP_PRIVATE` (no full-TEXT memcpy). `file_bytes` stays for bind.
        let memory = crate::load_timing::time_result("mmap_main", || {
            let mut file = std::fs::File::open(&self.executable)?;
            GuestMemory::map_image(self.pages.host, preferred, &requests, &mut file)
                .map_err(LoadError::from)
        })?;

        let main = ProcessImage {
            role: ImageRole::Main,
            path: self.executable.clone(),
            real_path: real_path_key(&self.executable).unwrap_or_else(|| self.executable.clone()),
            install_name: self.executable.display().to_string(),
            status: ImageLoadStatus::Mapped,
            image: Some(image),
            plan,
            memory: Some(memory),
            requested_kind: DylibKind::Load,
            exports: Vec::new(),
            export_by_name: HashMap::new(),
            file_bytes: Some(file_bytes),
        };
        self.images.push(main);
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
        for name in &self.extra_seed_dylibs {
            queue.push_back(DepEdge {
                install_name: name.clone(),
                kind: DylibKind::Load,
                loader_dir: exe_dir.clone(),
                rpaths: main_rpaths.clone(),
            });
        }

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

            let key = real_path_key(&host_path).unwrap_or_else(|| host_path.clone());
            if !seen_real_paths.insert(key.clone()) {
                self.push_skipped_path(
                    host_path,
                    edge.install_name.clone(),
                    edge.kind,
                    SkipReason::Duplicate,
                );
                continue;
            }

            let (parsed, file_bytes) = parse::parse_path_with_bytes(&host_path)?;
            if parsed.summary.file_type_raw != MH_DYLIB {
                return Err(LoadError::NotDylib(host_path.display().to_string()));
            }

            let plan = parsed.plan(self.pages.guest);
            let requests = map_requests_from_plan(&plan);
            let preferred = plan.preferred_base;
            let memory = {
                let mut file = std::fs::File::open(&host_path)?;
                GuestMemory::map_image(self.pages.host, preferred, &requests, &mut file)?
            };

            // Prefer the **LC_LOAD** install name (`edge.install_name`) over the
            // dylib's LC_ID. Bottle aliases (`libc++.1.dylib` / `libcurl.4.dylib`
            // → freestanding `libSystem.B.dylib`) share one real file whose LC_ID
            // is always `/usr/lib/libSystem.B.dylib`. Two-level binds use the
            // consumer's LC_LOAD string as the ordinal target, so the mapped
            // image must be findable under that name (see `find_mapped_by_install_name`
            // + duplicate real_path alias for the true libSystem edge).
            let lc_id = image_install_name(&parsed, &edge.install_name);
            let install = if edge.install_name.is_empty() {
                lc_id.clone()
            } else {
                edge.install_name.clone()
            };
            let loader_dir = host_path
                .parent()
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
            let dylib_rpaths = parsed.rpaths.clone();
            let child_rpaths = concat_rpaths(&dylib_rpaths, &main_rpaths);

            tracing::info!(
                path = %host_path.display(),
                install_name = %install,
                lc_id = %lc_id,
                slide = memory.slide(),
                base = preferred,
                "mapped dylib"
            );

            let child_edges = edges_from_image(&parsed, &loader_dir, &child_rpaths);

            self.images.push(ProcessImage {
                role: ImageRole::Dylib,
                path: host_path,
                real_path: key,
                install_name: install,
                status: ImageLoadStatus::Mapped,
                image: Some(parsed),
                plan,
                memory: Some(memory),
                requested_kind: edge.kind,
                exports: Vec::new(),
                export_by_name: HashMap::new(),
                file_bytes: Some(file_bytes),
            });

            for child in child_edges {
                queue.push_back(child);
            }
        }

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
        let path = PathBuf::from(path_display);
        let real_path = real_path_key(&path).unwrap_or_else(|| path.clone());
        self.images.push(ProcessImage {
            role: ImageRole::Dylib,
            path,
            real_path,
            install_name,
            status: ImageLoadStatus::Skipped(reason),
            image: None,
            plan: ImagePlan::empty(),
            memory: None,
            requested_kind: kind,
            exports: Vec::new(),
            export_by_name: HashMap::new(),
            file_bytes: None,
        });
    }

    fn push_skipped_path(
        &mut self,
        path: PathBuf,
        install_name: String,
        kind: DylibKind,
        reason: SkipReason,
    ) {
        let real_path = real_path_key(&path).unwrap_or_else(|| path.clone());
        self.images.push(ProcessImage {
            role: ImageRole::Dylib,
            path,
            real_path,
            install_name,
            status: ImageLoadStatus::Skipped(reason),
            image: None,
            plan: ImagePlan::empty(),
            memory: None,
            requested_kind: kind,
            exports: Vec::new(),
            export_by_name: HashMap::new(),
            file_bytes: None,
        });
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
    // Expected soft skips (CF/libz/libiconv/…) are debug; only odd failures stay warn.
    match reason {
        SkipReason::NoBottle
        | SkipReason::MissingPath
        | SkipReason::WeakMissing
        | SkipReason::Duplicate
        | SkipReason::KindNotFollowed => {
            tracing::debug!(install_name, reason = reason.as_str(), "skip dylib");
        }
        SkipReason::OutsideAllowlist => {
            tracing::warn!(install_name, reason = reason.as_str(), "skip dylib");
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
        svc_scan_ranges: m.svc_scan_ranges.clone(),
    }
}
