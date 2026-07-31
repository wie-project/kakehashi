//! Classic dyld bind opcodes (`LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`).
//!
//! Interprets the non-lazy and lazy bind streams and writes resolved absolute
//! pointers into guest memory (eager bind for Micro — no lazy stub helper).
//! When an image has no bind opcodes, falls back to nlist → `__got` for the
//! main executable (Phase 6 fixtures / tools without dyld info).

use std::collections::BTreeMap;

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
use crate::link::{self, build_export_map, fill_exports};
use crate::parse::{read_thin_arm64, thin_arm64_bytes};
use crate::session::{ImageLoadStatus, LoadSession, ProcessImage};

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

/// Fill exports, then bind each mapped image.
///
/// Preference per image:
/// 1. [`crate::chained`] fixups (`LC_DYLD_CHAINED_FIXUPS`) — rebase + bind
/// 2. classic dyld bind opcodes (`LC_DYLD_INFO`)
/// 3. if nothing applied for any image → nlist → `__got` on main
///
/// Call **after** map and (non-chained) section rebase.
pub fn bind_process(session: &mut LoadSession) -> Result<(), LoadError> {
    fill_exports(session)?;

    let paths: Vec<_> = session
        .images
        .iter()
        .map(|img| {
            (
                img.path.clone(),
                matches!(img.status, ImageLoadStatus::Mapped),
            )
        })
        .collect();

    let mut used_any = false;
    for (idx, (path, mapped)) in paths.into_iter().enumerate() {
        if !mapped || path.as_os_str().is_empty() {
            continue;
        }
        let bytes = read_thin_arm64(&path)?;
        if crate::chained::bytes_have_chained_fixups(&bytes)? {
            crate::chained::apply_chained_fixups(session, idx, &bytes)?;
            used_any = true;
            continue;
        }
        let sites = collect_bind_sites(&bytes)?;
        if sites.is_empty() {
            continue;
        }
        used_any = true;
        apply_bind_sites(session, idx, &sites)?;
    }

    if !used_any {
        link::bind_main_got_nlist(session)?;
    }
    Ok(())
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
        let resolved = resolve_bind_symbol(session.images(), image_idx, site)?;
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
    images: &[ProcessImage],
    binder_idx: usize,
    site: &BindSite,
) -> Result<u64, LoadError> {
    match resolve_bind_symbol_inner(images, binder_idx, site) {
        Ok(va) => Ok(va),
        Err(LoadError::UnresolvedSymbol { name }) if !site.weak => {
            // Large guests (curl) import more libc surface than freestanding
            // libSystem implements. Point strong misses at `_kh_missing_symbol`
            // so load completes; first call aborts with a guest-visible note.
            if let Ok(stub) = lookup_flat(images, "_kh_missing_symbol", false) {
                tracing::warn!(
                    name = %name,
                    "unresolved strong symbol; bound to _kh_missing_symbol"
                );
                Ok(stub)
            } else {
                Err(LoadError::UnresolvedSymbol { name })
            }
        }
        Err(err) => Err(err),
    }
}

fn resolve_bind_symbol_inner(
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
            lookup_flat(images, &site.name, site.weak)
        }
        -3 => {
            // BIND_SPECIAL_DYLIB_WEAK_LOOKUP (object/macho: -3; not in goblin yet).
            // Search all loaded images for a definition (weak coalescing). Same
            // map walk as flat lookup for our micro loader.
            lookup_flat(images, &site.name, site.weak)
        }
        n if n > 0 => {
            let binder = images.get(binder_idx).ok_or(LoadError::NotImplemented(
                "binder image missing for bind resolve",
            ))?;
            let ordinal_u32 = u32::try_from(n)
                .map_err(|_| LoadError::Resolve(format!("bind ordinal out of u32 range: {n}")))?;
            let dep_name = nth_dependent_dylib(binder, ordinal_u32)?;
            if let Some(img) = find_mapped_by_install_name(images, &dep_name) {
                lookup_in_image(Some(img), &site.name, site.weak)
            } else if site.weak {
                Ok(0)
            } else if let Ok(va) = lookup_flat(images, &site.name, false) {
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

fn nth_dependent_dylib(binder: &ProcessImage, ordinal: u32) -> Result<String, LoadError> {
    let image = binder
        .image
        .as_ref()
        .ok_or(LoadError::NotImplemented("binder has no Mach-O image"))?;
    let deps = dependent_dylib_names(image);
    let idx = ordinal
        .checked_sub(1)
        .and_then(|i| usize::try_from(i).ok())
        .ok_or_else(|| LoadError::Resolve(format!("invalid dylib ordinal {ordinal}")))?;
    deps.get(idx).cloned().ok_or_else(|| {
        LoadError::Resolve(format!(
            "dylib ordinal {ordinal} out of range ({} deps)",
            deps.len()
        ))
    })
}

fn dependent_dylib_names(image: &MachOImage) -> Vec<String> {
    image
        .dylibs
        .iter()
        .filter(|d| d.kind != DylibKind::Id)
        .map(|d| d.name.clone())
        .collect()
}

fn find_mapped_by_install_name<'a>(
    images: &'a [ProcessImage],
    install_name: &str,
) -> Option<&'a ProcessImage> {
    if let Some(img) = images.iter().find(|img| {
        matches!(img.status, ImageLoadStatus::Mapped)
            && (img.install_name == install_name
                || img
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| install_name.ends_with(n)))
    }) {
        return Some(img);
    }

    // Bottle alias: `libc++.1.dylib` → same real path as already-mapped
    // `libSystem.B.dylib` is recorded as `skipped:duplicate`. Reuse the mapped
    // image so two-level binds against the alias ordinal still resolve.
    //
    // Use the load-time cached `real_path` (no per-bind `canonicalize` /
    // readlinkat storm — roadmap A4).
    let alias = images.iter().find(|img| {
        matches!(
            img.status,
            ImageLoadStatus::Skipped(crate::session::SkipReason::Duplicate)
        ) && img.install_name == install_name
    })?;
    let alias_key = &alias.real_path;
    if alias_key.as_os_str().is_empty() {
        return None;
    }
    images
        .iter()
        .find(|img| matches!(img.status, ImageLoadStatus::Mapped) && img.real_path == *alias_key)
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
    if let Some(exp) = img.exports.iter().find(|e| e.name == name) {
        return Ok(exp.value.wrapping_add(slide));
    }
    // curl imports unadorned `dyld_stub_binder`; freestanding libSystem exports
    // the C nlist `_dyld_stub_binder` (see `build_export_map` alias).
    if name == "dyld_stub_binder"
        && let Some(exp) = img.exports.iter().find(|e| e.name == "_dyld_stub_binder")
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

fn lookup_flat(images: &[ProcessImage], name: &str, weak: bool) -> Result<u64, LoadError> {
    let map = build_export_map(images);
    match map.get(name) {
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

/// Encode a minimal non-lazy POINTER bind sequence for fixtures / tests.
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
    use crate::fixture::{CALL_DYLIB_GOT_VA, KH_ADD_SYMBOL, arm64_dylib_add, call_dylib_exit};
    use crate::session::{ImageRole, LoadSession};
    use crate::test_util::map_test_lock;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn encode_and_collect_one_site() {
        let stream = encode_pointer_bind(1, KH_ADD_SYMBOL, 2, 0);
        // Minimal fake: only stream interpretation via a tiny Mach-O is heavy;
        // unit-test the encoder shape and DO_BIND fields via interpret_stream.
        let seg = [0_u64, 0x1_0000_0000, CALL_DYLIB_GOT_VA];
        let mut sites = Vec::new();
        interpret_stream(&stream, 0..stream.len(), false, &seg, &mut sites).expect("interp");
        assert_eq!(sites.len(), 1);
        let s = sites.first().expect("one");
        assert_eq!(s.name, KH_ADD_SYMBOL);
        assert_eq!(s.preferred_va, CALL_DYLIB_GOT_VA);
        assert_eq!(s.lib_ordinal, 1);
        assert_eq!(s.bind_type, BIND_TYPE_POINTER);
        assert!(!s.weak);
        assert!(!s.is_lazy);
    }

    #[test]
    fn call_dylib_fixture_has_bind_opcodes() {
        let bytes = call_dylib_exit();
        let sites = collect_bind_sites(&bytes).expect("sites");
        assert_eq!(sites.len(), 1, "{sites:?}");
        let s = sites.first().expect("one");
        assert_eq!(s.name, KH_ADD_SYMBOL);
        assert_eq!(s.preferred_va, CALL_DYLIB_GOT_VA);
        assert_eq!(s.lib_ordinal, 1);
    }

    #[test]
    fn opcode_bind_writes_got() {
        static N: AtomicU64 = AtomicU64::new(0);
        let _guard = map_test_lock();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kh-bind-op-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let main_path = dir.join("call_dylib.macho");
        let dylib_path = dir.join("libkh_add.dylib");
        {
            let mut f = std::fs::File::create(&main_path).expect("create main");
            f.write_all(&call_dylib_exit()).expect("write main");
        }
        {
            let mut f = std::fs::File::create(&dylib_path).expect("create dylib");
            f.write_all(&arm64_dylib_add()).expect("write dylib");
        }

        let mut session = LoadSession::open(&main_path, None).expect("open");
        let _ = session.map_process().expect("map_process");
        let main = session.images().first().expect("main");
        assert_eq!(main.role, ImageRole::Main);
        let main_slide = main.slide();

        let export_va = session
            .images()
            .iter()
            .find(|i| i.role == ImageRole::Dylib && matches!(i.status, ImageLoadStatus::Mapped))
            .and_then(|dylib| {
                dylib
                    .exports
                    .iter()
                    .find(|e| e.name == KH_ADD_SYMBOL)
                    .map(|e| e.value.wrapping_add(dylib.slide()))
            })
            .expect("dylib export");

        let got_va = CALL_DYLIB_GOT_VA.wrapping_add(main_slide);
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
