//! Classic dyld bind opcodes (`LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`).
//!
//! Interprets the non-lazy and lazy bind streams and writes resolved absolute
//! pointers into guest memory (eager bind for Micro — no lazy stub helper).
//! When an image has no bind opcodes, falls back to nlist → `__got` for the
//! main executable (Phase 6 fixtures / tools without dyld info).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use goblin::mach::Mach;
use goblin::mach::bind_opcodes::{
    BIND_IMMEDIATE_MASK, BIND_OPCODE_ADD_ADDR_ULEB, BIND_OPCODE_DO_BIND,
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED, BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, BIND_OPCODE_DONE, BIND_OPCODE_MASK,
    BIND_OPCODE_SET_ADDEND_SLEB, BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB, BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM,
    BIND_OPCODE_SET_TYPE_IMM, BIND_SPECIAL_DYLIB_FLAT_LOOKUP, BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE,
    BIND_SPECIAL_DYLIB_SELF, BIND_SYMBOL_FLAGS_WEAK_IMPORT, BIND_TYPE_POINTER,
};
use goblin::mach::load_command::{CommandVariant, DyldInfoCommand};
use kh_runtime::{GuestMemory, VM_PROT_WRITE, mprotect_darwin, mprotect_rw};
use scroll::{Sleb128, Uleb128};

use crate::error::LoadError;
use crate::image::{DylibKind, MachOImage};
use crate::link::{self, fill_exports};
use crate::parse::thin_arm64_bytes;
use crate::session::{ImageLoadStatus, LoadSession, ProcessImage, SkipReason};

/// One pointer write derived from a bind opcode stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindSite {
    /// Symbol name (nlist / bind spelling, e.g. `_kh_add`).
    pub name: String,
    /// Preferred (slide-0) virtual address of the slot.
    pub preferred_va: u64,
    /// Addend applied after symbol resolution.
    pub addend: i64,
    /// `BIND_SYMBOL_FLAGS_WEAK_IMPORT`.
    pub weak: bool,
    /// Bind type (`BIND_TYPE_POINTER`, …).
    pub bind_type: u8,
    /// Library ordinal (1-based dylib index, or special ≤ 0).
    pub lib_ordinal: i16,
    /// From the lazy bind stream.
    pub is_lazy: bool,
}

/// Process-wide bind/chained resolve tables (built once per `bind_process`).
///
/// Avoids rebuilding a flat export `HashMap` (and re-walking install names /
/// dep ordinals) on every site — critical for large guests with thousands of
/// chained/classic binds.
#[derive(Debug)]
pub struct BindResolveCache {
    /// Slid absolute VA; first definition in load order wins.
    flat: HashMap<String, u64>,
    /// Mapped image index by `install_name`.
    install_to_idx: HashMap<String, usize>,
    /// Mapped image index by path basename (`libSystem.B.dylib`).
    basename_to_idx: HashMap<String, usize>,
    /// Skipped-duplicate install_name → `real_path` (bottle alias).
    alias_real: HashMap<String, PathBuf>,
    /// Mapped `real_path` → image index.
    real_to_idx: HashMap<PathBuf, usize>,
    /// Per-image dependent dylib install names (non-`LC_ID_DYLIB`), load order.
    deps: Vec<Vec<String>>,
    missing_named: Option<u64>,
    missing_anon: Option<u64>,
}

impl BindResolveCache {
    /// Build export / install-name indexes for the current process set.
    #[must_use]
    pub fn build(images: &[ProcessImage]) -> Self {
        let mut flat = HashMap::new();
        let mut install_to_idx = HashMap::new();
        let mut basename_to_idx = HashMap::new();
        let mut alias_real = HashMap::new();
        let mut real_to_idx = HashMap::new();
        let mut deps = Vec::with_capacity(images.len());

        for (idx, img) in images.iter().enumerate() {
            let dep_list = img
                .image
                .as_ref()
                .map(dependent_dylib_names)
                .unwrap_or_default();
            deps.push(dep_list);

            match &img.status {
                ImageLoadStatus::Mapped => {
                    let slide = img.slide();
                    if img.export_by_name.is_empty() {
                        for exp in &img.exports {
                            flat.entry(exp.name.clone())
                                .or_insert_with(|| exp.value.wrapping_add(slide));
                        }
                    } else {
                        for (name, &pref) in &img.export_by_name {
                            flat.entry(name.clone())
                                .or_insert_with(|| pref.wrapping_add(slide));
                        }
                    }
                    install_to_idx
                        .entry(img.install_name.clone())
                        .or_insert(idx);
                    if let Some(base) = img.path.file_name().and_then(|n| n.to_str()) {
                        basename_to_idx.entry(base.to_owned()).or_insert(idx);
                    }
                    if !img.real_path.as_os_str().is_empty() {
                        real_to_idx.entry(img.real_path.clone()).or_insert(idx);
                    }
                }
                ImageLoadStatus::Skipped(SkipReason::Duplicate) => {
                    alias_real
                        .entry(img.install_name.clone())
                        .or_insert_with(|| img.real_path.clone());
                }
                ImageLoadStatus::Skipped(_) => {}
            }
        }

        let missing_named = flat.get("_kh_missing_symbol_named").copied();
        let missing_anon = flat.get("_kh_missing_symbol").copied();

        Self {
            flat,
            install_to_idx,
            basename_to_idx,
            alias_real,
            real_to_idx,
            deps,
            missing_named,
            missing_anon,
        }
    }

    fn find_mapped_idx(&self, install_name: &str) -> Option<usize> {
        if let Some(&idx) = self.install_to_idx.get(install_name) {
            return Some(idx);
        }
        // Original path also matched `install_name.ends_with(path_basename)`.
        if let Some(base) = Path::new(install_name).file_name().and_then(|n| n.to_str())
            && let Some(&idx) = self.basename_to_idx.get(base)
        {
            return Some(idx);
        }
        let alias_key = self.alias_real.get(install_name)?;
        if alias_key.as_os_str().is_empty() {
            return None;
        }
        self.real_to_idx.get(alias_key).copied()
    }

    fn dep_name(&self, binder_idx: usize, ordinal: u32) -> Result<&str, LoadError> {
        let deps = self.deps.get(binder_idx).ok_or(LoadError::NotImplemented(
            "binder image missing for bind resolve",
        ))?;
        let idx = ordinal
            .checked_sub(1)
            .and_then(|i| usize::try_from(i).ok())
            .ok_or_else(|| LoadError::Resolve(format!("invalid dylib ordinal {ordinal}")))?;
        deps.get(idx).map(String::as_str).ok_or_else(|| {
            LoadError::Resolve(format!(
                "dylib ordinal {ordinal} out of range ({} deps)",
                deps.len()
            ))
        })
    }
}

/// Fill exports, then bind each mapped image.
///
/// Preference per image:
/// 1. [`crate::chained`] fixups (`LC_DYLD_CHAINED_FIXUPS`) — rebase + bind
/// 2. classic dyld bind opcodes (`LC_DYLD_INFO`)
/// 3. if nothing applied for any image → nlist → `__got` on main
///
/// Call **after** map and (non-chained) section rebase.
pub fn bind_process(session: &mut LoadSession) -> Result<(), LoadError> {
    bind_process_with_flat(session, &[])
}

/// Bind with extra slid exports (already-mapped process images).
///
/// Late `dlopen` maps only the new dylib; two-level ordinals to libc++ /
/// libSystem miss the session set and fall back to this flat table.
pub fn bind_process_with_flat(
    session: &mut LoadSession,
    extra_flat: &[(String, u64)],
) -> Result<(), LoadError> {
    crate::load_timing::time_result("bind_fill_exports", || fill_exports(session))?;
    let mut cache = crate::load_timing::time("bind_resolve_cache", || {
        BindResolveCache::build(session.images())
    });
    for (name, va) in extra_flat {
        cache.flat.entry(name.clone()).or_insert(*va);
    }
    if cache.missing_named.is_none() {
        cache.missing_named = cache.flat.get("_kh_missing_symbol_named").copied();
    }
    if cache.missing_anon.is_none() {
        cache.missing_anon = cache.flat.get("_kh_missing_symbol").copied();
    }

    let n = session.images.len();
    let mut used_any = false;
    for idx in 0..n {
        let mapped = session
            .images
            .get(idx)
            .is_some_and(|i| matches!(i.status, ImageLoadStatus::Mapped));
        if !mapped {
            continue;
        }
        // Prefer container from parse (mmap or heap; no second disk pass).
        let container = if let Some(b) = session
            .images
            .get_mut(idx)
            .and_then(|i| i.file_bytes.take())
        {
            b
        } else {
            let path = session
                .images
                .get(idx)
                .map(|i| i.path.clone())
                .unwrap_or_default();
            if path.as_os_str().is_empty() {
                continue;
            }
            crate::load_timing::time_result("bind_reread_file", || crate::FileImage::open(&path))?
        };
        // Bind/chained operate on the arm64 thin view (identity for thin files).
        // Keep `container` alive for the duration — no full-file copy.
        if crate::chained::bytes_have_chained_fixups(container.as_slice())? {
            crate::load_timing::time_result("bind_chained", || {
                crate::chained::apply_chained_fixups(session, idx, container.as_slice(), &cache)
            })?;
            used_any = true;
            continue;
        }
        let sites = crate::load_timing::time_result("bind_collect_sites", || {
            collect_bind_sites(container.as_slice())
        })?;
        if sites.is_empty() {
            continue;
        }
        used_any = true;
        crate::load_timing::time_result("bind_apply_sites", || {
            apply_bind_sites(session, idx, &sites, &cache)
        })?;
        drop(container);
    }

    if !used_any {
        link::bind_main_got_nlist(session)?;
    }
    crate::missing_stub::seal_pool();
    Ok(())
}

/// Bind an unresolved strong import to a named missing trampoline (or anonymous
/// `_kh_missing_symbol` if the named handler is absent).
fn resolve_missing_stub(cache: &BindResolveCache, name: &str) -> Result<u64, LoadError> {
    if let Some(handler) = cache.missing_named {
        match crate::missing_stub::trampoline_for(name, handler) {
            Ok(va) => {
                // Expected for incomplete libSystem; list at debug, not every run.
                tracing::debug!(
                    name = %name,
                    stub = format_args!("{va:#x}"),
                    "unresolved strong symbol; bound to named missing trampoline"
                );
                return Ok(va);
            }
            Err(err) => {
                tracing::warn!(
                    name = %name,
                    error = %err,
                    "missing trampoline emit failed; falling back"
                );
            }
        }
    }
    if let Some(stub) = cache.missing_anon {
        tracing::debug!(
            name = %name,
            "unresolved strong symbol; bound to _kh_missing_symbol"
        );
        return Ok(stub);
    }
    if let Some(handler) = cache.missing_named {
        // No trampoline path; still better than hard fail for load.
        tracing::debug!(
            name = %name,
            "unresolved strong symbol; bound to _kh_missing_symbol_named (no trampoline)"
        );
        return Ok(handler);
    }
    Err(LoadError::UnresolvedSymbol {
        name: name.to_owned(),
    })
}

/// Collect POINTER bind sites from `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`.
///
/// Empty when the image has no dyld info or zero-sized bind streams.
/// Weak-bind is not interpreted yet (Phase 10).
pub fn collect_bind_sites(bytes: &[u8]) -> Result<Vec<BindSite>, LoadError> {
    let thin = thin_arm64_bytes(bytes)?;
    let macho = match Mach::parse(thin) {
        Ok(Mach::Binary(m)) => m,
        Ok(Mach::Fat(_)) => {
            return Err(LoadError::NotMachO(
                "nested fat image inside arm64 slice".into(),
            ));
        }
        Err(err) => return Err(LoadError::NotMachO(err.to_string())),
    };

    let Some(cmd) = dyld_info_command(&macho) else {
        return Ok(Vec::new());
    };

    let seg_vmaddrs: Vec<u64> = macho.segments.iter().map(|s| s.vmaddr).collect();
    let mut sites = Vec::new();

    if cmd.bind_size > 0 {
        let range = file_range(cmd.bind_off, cmd.bind_size, thin.len())?;
        interpret_stream(thin, range, false, &seg_vmaddrs, &mut sites)?;
    }
    if cmd.lazy_bind_size > 0 {
        let range = file_range(cmd.lazy_bind_off, cmd.lazy_bind_size, thin.len())?;
        interpret_stream(thin, range, true, &seg_vmaddrs, &mut sites)?;
    }

    Ok(sites)
}

fn dyld_info_command<'a>(macho: &'a goblin::mach::MachO<'a>) -> Option<&'a DyldInfoCommand> {
    for lc in &macho.load_commands {
        match &lc.command {
            CommandVariant::DyldInfo(c) | CommandVariant::DyldInfoOnly(c) => return Some(c),
            _ => {}
        }
    }
    None
}

fn file_range(off: u32, size: u32, len: usize) -> Result<std::ops::Range<usize>, LoadError> {
    let start = usize::try_from(off).map_err(|_| LoadError::Resolve("bind off overflow".into()))?;
    let size =
        usize::try_from(size).map_err(|_| LoadError::Resolve("bind size overflow".into()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| LoadError::Resolve("bind range overflow".into()))?;
    if end > len {
        return Err(LoadError::Resolve(format!(
            "bind stream {start:#x}..{end:#x} past file end {len:#x}"
        )));
    }
    Ok(start..end)
}

#[derive(Clone)]
struct BindState {
    seg_index: u8,
    seg_offset: u64,
    bind_type: u8,
    lib_ordinal: i16,
    symbol_name: String,
    symbol_flags: u8,
    addend: i64,
}

impl BindState {
    fn new(is_lazy: bool) -> Self {
        Self {
            seg_index: 0,
            seg_offset: 0,
            bind_type: if is_lazy { BIND_TYPE_POINTER } else { 0 },
            lib_ordinal: 0,
            symbol_name: String::new(),
            symbol_flags: 0,
            addend: 0,
        }
    }

    fn is_weak(&self) -> bool {
        self.symbol_flags & BIND_SYMBOL_FLAGS_WEAK_IMPORT != 0
    }
}

fn interpret_stream(
    data: &[u8],
    range: std::ops::Range<usize>,
    is_lazy: bool,
    seg_vmaddrs: &[u64],
    out: &mut Vec<BindSite>,
) -> Result<(), LoadError> {
    const PTR_SIZE: u64 = 8;
    let mut state = BindState::new(is_lazy);
    let mut offset = range.start;

    while offset < range.end {
        let opcode_byte = *data
            .get(offset)
            .ok_or_else(|| LoadError::Resolve("bind stream truncated".into()))?;
        offset = offset.saturating_add(1);
        let opcode = opcode_byte & BIND_OPCODE_MASK;
        let imm = opcode_byte & BIND_IMMEDIATE_MASK;

        match opcode {
            BIND_OPCODE_DONE => {
                state = BindState::new(is_lazy);
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                state.lib_ordinal = i16::from(imm);
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                let v = read_uleb(data, &mut offset)?;
                state.lib_ordinal = i16::try_from(v).map_err(|_| {
                    LoadError::Resolve(format!("bind dylib ordinal too large: {v}"))
                })?;
            }
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                // dyld: imm==0 → SELF; else sign-extend nibble with high nibble 0xF.
                if imm == 0 {
                    state.lib_ordinal = i16::from(BIND_SPECIAL_DYLIB_SELF);
                } else {
                    let raw = BIND_OPCODE_MASK | imm;
                    let sign_ext = raw.cast_signed();
                    state.lib_ordinal = i16::from(sign_ext);
                }
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                state.symbol_flags = imm;
                let name = read_cstring(data, &mut offset, range.end)?;
                state.symbol_name = name;
            }
            BIND_OPCODE_SET_TYPE_IMM => {
                state.bind_type = imm;
            }
            BIND_OPCODE_SET_ADDEND_SLEB => {
                state.addend = read_sleb(data, &mut offset)?;
            }
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                state.seg_index = imm;
                state.seg_offset = read_uleb(data, &mut offset)?;
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                let addr = read_uleb(data, &mut offset)?;
                state.seg_offset = state.seg_offset.wrapping_add(addr);
            }
            BIND_OPCODE_DO_BIND => {
                push_site(&state, is_lazy, seg_vmaddrs, out)?;
                state.seg_offset = state.seg_offset.wrapping_add(PTR_SIZE);
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                push_site(&state, is_lazy, seg_vmaddrs, out)?;
                let addr = read_uleb(data, &mut offset)?;
                state.seg_offset = state.seg_offset.wrapping_add(addr).wrapping_add(PTR_SIZE);
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                push_site(&state, is_lazy, seg_vmaddrs, out)?;
                let scale = u64::from(imm);
                state.seg_offset = state
                    .seg_offset
                    .wrapping_add(scale.wrapping_mul(PTR_SIZE))
                    .wrapping_add(PTR_SIZE);
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let count = read_uleb(data, &mut offset)?;
                let skip = read_uleb(data, &mut offset)?;
                let step = skip.wrapping_add(PTR_SIZE);
                for _ in 0..count {
                    push_site(&state, is_lazy, seg_vmaddrs, out)?;
                    state.seg_offset = state.seg_offset.wrapping_add(step);
                }
            }
            _ => {
                return Err(LoadError::Resolve(format!(
                    "unknown bind opcode {opcode_byte:#x}"
                )));
            }
        }
    }
    Ok(())
}

fn push_site(
    state: &BindState,
    is_lazy: bool,
    seg_vmaddrs: &[u64],
    out: &mut Vec<BindSite>,
) -> Result<(), LoadError> {
    if state.symbol_name.is_empty() {
        return Err(LoadError::Resolve(
            "bind DO_BIND without symbol name".into(),
        ));
    }
    let seg_i = usize::from(state.seg_index);
    let seg_base = *seg_vmaddrs.get(seg_i).ok_or_else(|| {
        LoadError::Resolve(format!(
            "bind segment index {} out of range ({})",
            state.seg_index,
            seg_vmaddrs.len()
        ))
    })?;
    let preferred_va = seg_base.wrapping_add(state.seg_offset);
    out.push(BindSite {
        name: state.symbol_name.clone(),
        preferred_va,
        addend: state.addend,
        weak: state.is_weak(),
        bind_type: state.bind_type,
        lib_ordinal: state.lib_ordinal,
        is_lazy,
    });
    Ok(())
}

fn read_uleb(data: &[u8], offset: &mut usize) -> Result<u64, LoadError> {
    Uleb128::read(data, offset).map_err(|err| LoadError::Resolve(format!("bind uleb: {err}")))
}

fn read_sleb(data: &[u8], offset: &mut usize) -> Result<i64, LoadError> {
    Sleb128::read(data, offset).map_err(|err| LoadError::Resolve(format!("bind sleb: {err}")))
}

fn read_cstring(data: &[u8], offset: &mut usize, end: usize) -> Result<String, LoadError> {
    let start = *offset;
    if start >= end {
        return Err(LoadError::Resolve(
            "bind symbol name past stream end".into(),
        ));
    }
    let slice = data
        .get(start..end)
        .ok_or_else(|| LoadError::Resolve("bind symbol name OOB".into()))?;
    let nul = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| LoadError::Resolve("bind symbol name not NUL-terminated".into()))?;
    let name_bytes = slice
        .get(..nul)
        .ok_or_else(|| LoadError::Resolve("bind symbol name slice OOB".into()))?;
    let name = std::str::from_utf8(name_bytes)
        .map_err(|err| LoadError::Resolve(format!("bind symbol utf8: {err}")))?
        .to_owned();
    *offset = start.saturating_add(nul).saturating_add(1);
    Ok(name)
}

fn apply_bind_sites(
    session: &mut LoadSession,
    image_idx: usize,
    sites: &[BindSite],
    cache: &BindResolveCache,
) -> Result<(), LoadError> {
    let slide = session.images.get(image_idx).map_or(0, ProcessImage::slide);

    let mut updates: Vec<(u64, u64)> = Vec::with_capacity(sites.len());
    for site in sites {
        // Type 0: stream omitted SET_TYPE (unusual); treat as POINTER.
        if site.bind_type != BIND_TYPE_POINTER && site.bind_type != 0 {
            return Err(LoadError::NotImplemented(
                "non-POINTER classic bind type (TEXT absolute/pcrel)",
            ));
        }
        let resolved = resolve_bind_symbol(cache, session.images(), image_idx, site)?;
        let value = if site.addend == 0 {
            resolved
        } else {
            resolved.wrapping_add(site.addend.cast_unsigned())
        };
        let slot = site.preferred_va.wrapping_add(slide);
        tracing::debug!(
            name = %site.name,
            slot,
            value,
            ordinal = site.lib_ordinal,
            lazy = site.is_lazy,
            "bind opcode POINTER"
        );
        updates.push((slot, value));
    }

    write_pointer_slots(session, image_idx, &updates)
}

/// Resolve a two-level (or special/flat) import for bind / chained fixups.
pub(crate) fn resolve_bind_symbol(
    cache: &BindResolveCache,
    images: &[ProcessImage],
    binder_idx: usize,
    site: &BindSite,
) -> Result<u64, LoadError> {
    match resolve_bind_symbol_inner(cache, images, binder_idx, site) {
        Ok(va) => Ok(va),
        Err(LoadError::UnresolvedSymbol { name }) if !site.weak => {
            // Large guests (curl) import more libc surface than freestanding
            // libSystem implements. Point each strong miss at a per-name
            // trampoline → `_kh_missing_symbol_named` so the first *call*
            // prints which import we still need (G1).
            resolve_missing_stub(cache, &name)
        }
        Err(err) => Err(err),
    }
}

fn resolve_bind_symbol_inner(
    cache: &BindResolveCache,
    images: &[ProcessImage],
    binder_idx: usize,
    site: &BindSite,
) -> Result<u64, LoadError> {
    // Specials from SET_DYLIB_SPECIAL_IMM / chained import ordinals are
    // sign-extended to negative i16 (SELF=0, MAIN=-1, FLAT=-2, WEAK=-3).
    // Positive ordinals are 1-based LC_LOAD_* order.
    match site.lib_ordinal {
        o if o == i16::from(BIND_SPECIAL_DYLIB_SELF) => {
            lookup_in_image(images.get(binder_idx), &site.name, site.weak)
        }
        -1 => {
            // BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE
            debug_assert_eq!(BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE, 0xf);
            lookup_in_image(images.first(), &site.name, site.weak)
        }
        -2 => {
            // BIND_SPECIAL_DYLIB_FLAT_LOOKUP
            debug_assert_eq!(BIND_SPECIAL_DYLIB_FLAT_LOOKUP, 0xe);
            lookup_flat(cache, &site.name, site.weak)
        }
        -3 => {
            // BIND_SPECIAL_DYLIB_WEAK_LOOKUP (object/macho: -3; not in goblin yet).
            // Search all loaded images for a definition (weak coalescing). Same
            // map walk as flat lookup for our micro loader.
            lookup_flat(cache, &site.name, site.weak)
        }
        n if n > 0 => {
            let ordinal_u32 = u32::try_from(n)
                .map_err(|_| LoadError::Resolve(format!("bind ordinal out of u32 range: {n}")))?;
            let dep_name = cache.dep_name(binder_idx, ordinal_u32)?;
            if let Some(idx) = cache.find_mapped_idx(dep_name) {
                lookup_in_image(images.get(idx), &site.name, site.weak)
            } else if site.weak {
                Ok(0)
            } else if let Ok(va) = lookup_flat(cache, &site.name, false) {
                // Framework skipped (e.g. CoreFoundation) but freestanding
                // libSystem may still export a stub for G1 probes (curl).
                tracing::debug!(
                    name = %site.name,
                    missing = %dep_name,
                    "two-level target missing; flat stub resolve"
                );
                Ok(va)
            } else {
                // Two-level target not mapped and no flat definition.
                Err(LoadError::UnresolvedSymbol {
                    name: site.name.clone(),
                })
            }
        }
        other => Err(LoadError::Resolve(format!(
            "unsupported bind library ordinal {other}"
        ))),
    }
}

fn dependent_dylib_names(image: &MachOImage) -> Vec<String> {
    image
        .dylibs
        .iter()
        .filter(|d| d.kind != DylibKind::Id)
        .map(|d| d.name.clone())
        .collect()
}

fn lookup_in_image(img: Option<&ProcessImage>, name: &str, weak: bool) -> Result<u64, LoadError> {
    let Some(img) = img else {
        return if weak {
            Ok(0)
        } else {
            Err(LoadError::UnresolvedSymbol {
                name: name.to_owned(),
            })
        };
    };
    if !matches!(img.status, ImageLoadStatus::Mapped) {
        return if weak {
            Ok(0)
        } else {
            Err(LoadError::UnresolvedSymbol {
                name: name.to_owned(),
            })
        };
    }
    let slide = img.slide();
    if let Some(&pref) = img.export_by_name.get(name) {
        return Ok(pref.wrapping_add(slide));
    }
    // Fallback when index not built (tests / nlist-only path).
    if img.export_by_name.is_empty()
        && let Some(exp) = img.exports.iter().find(|e| e.name == name)
    {
        return Ok(exp.value.wrapping_add(slide));
    }
    if weak {
        Ok(0)
    } else {
        Err(LoadError::UnresolvedSymbol {
            name: name.to_owned(),
        })
    }
}

fn lookup_flat(cache: &BindResolveCache, name: &str, weak: bool) -> Result<u64, LoadError> {
    match cache.flat.get(name) {
        Some(&va) => Ok(va),
        None if weak => Ok(0),
        None => Err(LoadError::UnresolvedSymbol {
            name: name.to_owned(),
        }),
    }
}

/// Write absolute pointers into a mapped image.
///
/// Batches by region and skips host `mprotect` when the region is already
/// Darwin-writable (typical `__DATA` binds). Per-slot RW↔restore used to cost
/// ~2×N `mprotect` syscalls on large guests (roadmap A5).
pub(crate) fn write_pointer_slots(
    session: &mut LoadSession,
    image_idx: usize,
    updates: &[(u64, u64)],
) -> Result<(), LoadError> {
    if updates.is_empty() {
        return Ok(());
    }
    let img = session
        .images
        .get_mut(image_idx)
        .ok_or(LoadError::NotImplemented("image missing for bind write"))?;
    let memory = img
        .memory
        .as_mut()
        .ok_or(LoadError::NotImplemented("memory missing for bind write"))?;
    write_slots_batched(memory, updates)
}

/// Apply `(slot_va, value)` writes with at most one mprotect pair per region.
pub(crate) fn write_slots_batched(
    memory: &mut GuestMemory,
    updates: &[(u64, u64)],
) -> Result<(), LoadError> {
    if updates.is_empty() {
        return Ok(());
    }

    // Group slot → value by region index (stable order for deterministic errors).
    let mut by_region: BTreeMap<usize, Vec<(u64, u64)>> = BTreeMap::new();
    for &(slot, value) in updates {
        let region_idx = memory
            .regions()
            .iter()
            .position(|r| {
                let start = r.guest_addr;
                let end = start.saturating_add(r.vmsize);
                slot >= start && slot < end
            })
            .ok_or_else(|| {
                LoadError::Resolve(format!("bind slot {slot:#x} outside mapped regions"))
            })?;
        by_region.entry(region_idx).or_default().push((slot, value));
    }

    for (region_idx, slots) in by_region {
        let restore = memory
            .regions()
            .get(region_idx)
            .ok_or_else(|| LoadError::Resolve(format!("bind region missing idx {region_idx}")))?
            .prot;
        // DATA/BSS already RW after map: do not thrash mprotect (A5).
        let need_flip = restore & VM_PROT_WRITE == 0;
        if need_flip {
            let region = memory.regions_mut().get_mut(region_idx).ok_or_else(|| {
                LoadError::Resolve(format!("bind region missing idx {region_idx}"))
            })?;
            mprotect_rw(region).map_err(LoadError::Map)?;
        }

        for (slot, value) in slots {
            if memory.write_u64_le(slot, value).is_none() {
                return Err(LoadError::Resolve(format!(
                    "bind write failed at {slot:#x}"
                )));
            }
        }

        if need_flip {
            let region = memory
                .regions()
                .get(region_idx)
                .ok_or_else(|| LoadError::Resolve(format!("bind region lost idx {region_idx}")))?;
            mprotect_darwin(region, restore).map_err(LoadError::Map)?;
        }
    }
    Ok(())
}

/// Encode a minimal non-lazy POINTER bind sequence (unit tests / opcode smoke).
#[must_use]
pub fn encode_pointer_bind(
    dylib_ordinal: u8,
    symbol: &str,
    seg_index: u8,
    seg_offset: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.push(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | (dylib_ordinal & BIND_IMMEDIATE_MASK));
    out.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
    out.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
    out.extend_from_slice(symbol.as_bytes());
    out.push(0);
    out.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | (seg_index & BIND_IMMEDIATE_MASK));
    push_uleb(&mut out, seg_offset);
    out.push(BIND_OPCODE_DO_BIND);
    out.push(BIND_OPCODE_DONE);
    out
}

fn push_uleb(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_collect_one_site() {
        const GOT_VA: u64 = 0x1_0000_4000;
        let stream = encode_pointer_bind(1, "_kh_add", 2, 0);
        let seg = [0_u64, 0x1_0000_0000, GOT_VA];
        let mut sites = Vec::new();
        interpret_stream(&stream, 0..stream.len(), false, &seg, &mut sites).expect("interp");
        assert_eq!(sites.len(), 1);
        let s = sites.first().expect("one");
        assert_eq!(s.name, "_kh_add");
        assert_eq!(s.preferred_va, GOT_VA);
        assert_eq!(s.lib_ordinal, 1);
        assert_eq!(s.bind_type, BIND_TYPE_POINTER);
        assert!(!s.weak);
        assert!(!s.is_lazy);
    }

    #[test]
    fn do_bind_times_skipping() {
        // SET_ORD 1, SET_TYPE PTR, SET_SYM "x", SET_SEG 0 off 0,
        // DO_BIND_ULEB_TIMES_SKIPPING count=2 skip=8 → slots 0 and 16
        let mut stream = Vec::new();
        stream.push(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | 1);
        stream.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
        stream.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
        stream.extend_from_slice(b"x\0");
        stream.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB);
        push_uleb(&mut stream, 0);
        stream.push(BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB);
        push_uleb(&mut stream, 2);
        push_uleb(&mut stream, 8);
        stream.push(BIND_OPCODE_DONE);

        let seg = [0x1000_u64];
        let mut sites = Vec::new();
        interpret_stream(&stream, 0..stream.len(), false, &seg, &mut sites).expect("interp");
        assert_eq!(sites.len(), 2);
        assert_eq!(sites.first().expect("0").preferred_va, 0x1000);
        assert_eq!(sites.get(1).expect("1").preferred_va, 0x1000 + 16);
    }
}
