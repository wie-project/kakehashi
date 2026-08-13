//! Anonymous Apple **Software Update** catalog → Command Line Tools packages.
//!
//! Primary install path for `kh install xcode-tools` (no Apple ID / cookies):
//!
//! 1. Fetch a public `*.sucatalog` from `swscan.apple.com`
//! 2. Find products that ship `CLTools_Executables*.pkg`
//! 3. Read the English `.dist` for a human title (`suDisabledGroupID`)
//! 4. Download from `swcdn.apple.com` into the cache:
//!    - `CLTools_Executables*.pkg` (toolchain)
//!    - `CLTools_macOSNMOS_SDK.pkg` (current MacOSX.sdk headers)
//!
//! Not downloaded: empty `CLTools_macOS_SDK.pkg` marker, previous-major
//! `CLTools_macOSLMOS_SDK.pkg`, `*_DevSDK_Remove_*`, Swift back-deploy.
//!
//! This is the same CDN path macOS `softwareupdate` / `xcode-select --install`
//! use for CLT — not the authenticated developer.apple.com portal.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use plist::{Date, Value};

use super::download_cache::{self, CacheError};

/// Optional pin: substring match against the CLT title, e.g. `26.6` or
/// `Command Line Tools for Xcode 26.6`. Empty → latest stable.
pub const ENV_XCODE_TOOLS_VERSION: &str = "KAKEHASHI_XCODE_TOOLS_VERSION";

/// Cache filename for the raw sucatalog blob.
const CATALOG_CACHE_NAME: &str = "software-update.sucatalog";

/// Cache filename alias for the selected CLT executables package.
const CLT_EXEC_ALIAS: &str = "CLTools_Executables.pkg";

/// Meta written next to the cached package.
const CLT_META_NAME: &str = "command-line-tools.meta.json";

/// Candidate Software Update catalog URLs (newest-first). Apple rolls a new
/// `index-<maj>-…merged-1.sucatalog` when a major ships; try until one returns
/// a body with Products.
const CATALOG_URLS: &[&str] = &[
    // macOS 26 seed / seed+history chain (2026).
    "https://swscan.apple.com/content/catalogs/others/index-26-15-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
    // Sequoia (15) chain — fallback if 26 catalog is temporarily empty/404.
    "https://swscan.apple.com/content/catalogs/others/index-15-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
    "https://swscan.apple.com/content/catalogs/others/index-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
    "https://swscan.apple.com/content/catalogs/others/index-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog",
];

/// One CLT product discovered in the Software Update catalog.
#[derive(Debug, Clone)]
pub(crate) struct CltPackage {
    /// Catalog product key, e.g. `140-17812`.
    pub product_id: String,
    /// Display title from the English dist, e.g. `Command Line Tools for Xcode 26.6`.
    pub name: String,
    /// Direct `swcdn` URL of `CLTools_Executables*.pkg`.
    pub executables_url: String,
    /// Package file basename for the cache.
    pub executables_name: String,
    /// Current-major SDK package (`CLTools_macOSNMOS_SDK.pkg`), if listed.
    pub nmos_sdk: Option<CltSdkPackage>,
    /// Catalog `PostDate` as Unix seconds (0 if missing).
    pub post_date: i64,
}

/// One SDK `.pkg` shipped next to CLT executables on `swcdn.apple.com`.
#[derive(Debug, Clone)]
pub(crate) struct CltSdkPackage {
    /// Basename, e.g. `CLTools_macOSNMOS_SDK.pkg`.
    pub name: String,
    /// Direct CDN URL.
    pub url: String,
}

/// Full path: catalog → select → download executables pkg. Returns (meta, path).
pub(crate) fn download_selected_clt() -> Result<(CltPackage, PathBuf), SwscanError> {
    let list = list_clt_packages()?;
    let pkg = select_clt_package(&list)?;
    let path = ensure_clt_archive(&pkg)?;
    Ok((pkg, path))
}

/// Download (or reuse) the current-major MacOSX SDK for a selected CLT product.
///
/// Always installs NMOS only (not LMOS / previous major). Returns empty when
/// the catalog product has no NMOS package.
pub(crate) fn ensure_clt_sdk_archives(pkg: &CltPackage) -> Result<Vec<PathBuf>, SwscanError> {
    let Some(sdk) = pkg.nmos_sdk.as_ref() else {
        return Ok(Vec::new());
    };
    Ok(vec![ensure_named_archive(&sdk.name, &sdk.url)?])
}

/// List CLT products from a cached/fetched Software Update catalog.
pub(crate) fn list_clt_packages() -> Result<Vec<CltPackage>, SwscanError> {
    let catalog_path = ensure_catalog()?;
    let products = parse_clt_products(&catalog_path)?;
    if products.is_empty() {
        return Err(SwscanError::Command(
            "Software Update catalog has no CLTools_Executables packages \
             (Apple may have renamed the product — try KAKEHASHI_FORCE_DOWNLOAD=1)"
                .into(),
        ));
    }
    Ok(products)
}

/// Select one package: optional pin via [`ENV_XCODE_TOOLS_VERSION`], else latest
/// stable (title without beta/seed/rc preferred).
pub(crate) fn select_clt_package(packages: &[CltPackage]) -> Result<CltPackage, SwscanError> {
    if packages.is_empty() {
        return Err(SwscanError::Command(
            "no Command Line Tools products in catalog".into(),
        ));
    }

    if let Ok(pin) = env::var(ENV_XCODE_TOOLS_VERSION) {
        let pin = pin.trim();
        if !pin.is_empty() {
            let pin_l = pin.to_ascii_lowercase();
            if let Some(p) = packages.iter().find(|p| {
                p.name.to_ascii_lowercase().contains(&pin_l)
                    || p.product_id.to_ascii_lowercase().contains(&pin_l)
                    || p.executables_name.to_ascii_lowercase().contains(&pin_l)
            }) {
                return Ok(p.clone());
            }
            return Err(SwscanError::Command(format!(
                "no CLT matching {ENV_XCODE_TOOLS_VERSION}={pin:?}; available: {}",
                packages
                    .iter()
                    .take(8)
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }

    if let Some(p) = packages.iter().find(|p| !is_prerelease_name(&p.name)) {
        return Ok(p.clone());
    }
    packages
        .first()
        .cloned()
        .ok_or_else(|| SwscanError::Command("empty CLT list".into()))
}

/// Download (or reuse) the executables package for `pkg`.
pub(crate) fn ensure_clt_archive(pkg: &CltPackage) -> Result<PathBuf, SwscanError> {
    let dest = ensure_named_archive(&pkg.executables_name, &pkg.executables_url)?;
    let alias = download_cache::download_path(CLT_EXEC_ALIAS).map_err(SwscanError::Io)?;
    write_meta(&dest, pkg)?;
    mirror_alias(&dest, &alias)?;
    Ok(dest)
}

/// Download (or reuse) any CLT-related flat package by basename + URL.
fn ensure_named_archive(name: &str, url: &str) -> Result<PathBuf, SwscanError> {
    let dest = download_cache::download_path(name).map_err(SwscanError::Io)?;

    if !download_cache::force_download() && download_cache::is_nonempty_file(&dest) {
        return Ok(dest);
    }

    download_cache::ensure_url(url, &dest).map_err(cache_to_swscan)?;
    // Reject tiny non-xar responses (HTML error pages, empty stubs).
    let meta = fs::metadata(&dest).map_err(SwscanError::Io)?;
    if meta.len() < 1024 {
        drop(fs::remove_file(&dest));
        return Err(SwscanError::Command(format!(
            "CLT download too small ({} bytes); url={url}",
            meta.len()
        )));
    }
    let head = fs::read(&dest).unwrap_or_default();
    if !head.starts_with(b"xar!") {
        drop(fs::remove_file(&dest));
        return Err(SwscanError::Command(format!(
            "CLT download is not a xar package ({} bytes); url={url}",
            meta.len()
        )));
    }
    Ok(dest)
}

fn ensure_catalog() -> Result<PathBuf, SwscanError> {
    let dest = download_cache::download_path(CATALOG_CACHE_NAME).map_err(SwscanError::Io)?;
    if !download_cache::force_download()
        && download_cache::is_nonempty_file(&dest)
        && catalog_is_fresh(&dest)
        && catalog_looks_valid(&dest)
    {
        // Reuse catalog for a day unless forced — keeps Docker re-runs quiet.
        return Ok(dest);
    }

    // Stale or missing: drop so ensure_url re-fetches (cache hit would skip).
    if dest.exists() {
        drop(fs::remove_file(&dest));
    }

    let mut last_err = None;
    for url in CATALOG_URLS {
        match download_cache::ensure_url(url, &dest) {
            Ok(()) => {
                if catalog_looks_valid(&dest) {
                    return Ok(dest);
                }
                drop(fs::remove_file(&dest));
                last_err = Some(format!("catalog from {url} is not a valid sucatalog"));
            }
            Err(e) => {
                last_err = Some(e.to_string());
            }
        }
    }
    Err(SwscanError::Command(format!(
        "failed to fetch Software Update catalog: {}",
        last_err.unwrap_or_else(|| "no URLs tried".into())
    )))
}

fn catalog_is_fresh(path: &Path) -> bool {
    let Ok(meta) = path.metadata() else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        return false;
    };
    // 24h TTL — CLT releases are infrequent; force-download bypasses.
    age.as_secs() < 24 * 60 * 60
}

fn catalog_looks_valid(path: &Path) -> bool {
    let Ok(head) = fs::read(path) else {
        return false;
    };
    if head.len() < 64 {
        return false;
    }
    let n = head.len().min(512);
    let Some(slice) = head.get(..n) else {
        return false;
    };
    let text = String::from_utf8_lossy(slice);
    text.contains("plist") || text.contains("Products")
}

fn parse_clt_products(catalog_path: &Path) -> Result<Vec<CltPackage>, SwscanError> {
    let root = Value::from_file(catalog_path).map_err(|e| {
        SwscanError::Parse(format!("sucatalog parse {}: {e}", catalog_path.display()))
    })?;
    let dict = root
        .as_dictionary()
        .ok_or_else(|| SwscanError::Parse("sucatalog root is not a dictionary".into()))?;
    let products = dict
        .get("Products")
        .and_then(Value::as_dictionary)
        .ok_or_else(|| SwscanError::Parse("sucatalog missing Products".into()))?;

    // Collect candidates that ship executables; resolve titles lazily (newest first).
    let mut raw: Vec<RawClt> = Vec::new();
    for (product_id, prod) in products {
        let Some(prod_dict) = prod.as_dictionary() else {
            continue;
        };
        let post_date = prod_dict
            .get("PostDate")
            .and_then(plist_date_secs)
            .unwrap_or(0);
        let Some(packages) = prod_dict.get("Packages").and_then(Value::as_array) else {
            continue;
        };
        let mut exec_url = None;
        let mut exec_name = None;
        let mut nmos_sdk = None;
        for pkg in packages {
            let Some(pkg_dict) = pkg.as_dictionary() else {
                continue;
            };
            let Some(url) = pkg_dict.get("URL").and_then(Value::as_string) else {
                continue;
            };
            let base = url.rsplit('/').next().unwrap_or(url);
            if is_executables_pkg_name(base) {
                exec_url = Some(url.to_owned());
                exec_name = Some(base.to_owned());
                continue;
            }
            if is_nmos_sdk_pkg_name(base) {
                nmos_sdk = Some(CltSdkPackage {
                    name: base.to_owned(),
                    url: url.to_owned(),
                });
            }
        }
        let (Some(executables_url), Some(executables_name)) = (exec_url, exec_name) else {
            continue;
        };
        let dist_url = prod_dict
            .get("Distributions")
            .and_then(Value::as_dictionary)
            .and_then(|d| {
                d.get("English")
                    .or_else(|| d.get("en"))
                    .and_then(Value::as_string)
                    .map(str::to_owned)
            });
        raw.push(RawClt {
            product_id: product_id.clone(),
            executables_url,
            executables_name,
            nmos_sdk,
            post_date,
            dist_url,
        });
    }

    raw.sort_by(|a, b| {
        b.post_date
            .cmp(&a.post_date)
            .then_with(|| b.product_id.cmp(&a.product_id))
    });

    // Resolve titles for the newest products only (dist is a small HTTP GET each).
    let pin = env::var(ENV_XCODE_TOOLS_VERSION).unwrap_or_default();
    let pin = pin.trim().to_ascii_lowercase();
    let limit = if pin.is_empty() { 12 } else { raw.len() };

    let mut out = Vec::new();
    for r in raw.into_iter().take(limit) {
        let name = match r.dist_url.as_deref() {
            Some(url) => fetch_clt_title(url)
                .unwrap_or_else(|| format!("Command Line Tools ({})", r.product_id)),
            None => format!("Command Line Tools ({})", r.product_id),
        };
        // Prefer titles that look like CLT; drop false-positive products.
        if !is_clt_name(&name) && !r.executables_name.contains("CLTools") {
            continue;
        }
        out.push(CltPackage {
            product_id: r.product_id,
            name,
            executables_url: r.executables_url,
            executables_name: r.executables_name,
            nmos_sdk: r.nmos_sdk,
            post_date: r.post_date,
        });
    }

    // Newest first (already sorted raw; keep stable order).
    out.sort_by(|a, b| {
        b.post_date
            .cmp(&a.post_date)
            .then_with(|| b.name.cmp(&a.name))
    });
    Ok(out)
}

struct RawClt {
    product_id: String,
    executables_url: String,
    executables_name: String,
    nmos_sdk: Option<CltSdkPackage>,
    post_date: i64,
    dist_url: Option<String>,
}

fn is_executables_pkg_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("cltools_executables")
        && Path::new(&n)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pkg"))
}

/// Current-major SDK only (`CLTools_macOSNMOS_SDK.pkg`).
///
/// LMOS (previous major), empty `CLTools_macOS_SDK.pkg`, and Remove/Swift
/// packages are intentionally ignored.
fn is_nmos_sdk_pkg_name(name: &str) -> bool {
    if !Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pkg"))
    {
        return false;
    }
    name.to_ascii_lowercase()
        .starts_with("cltools_macosnmos_sdk")
}

fn is_clt_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("command line tools") && n.contains("xcode")
}

fn is_prerelease_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("beta")
        || n.contains("seed")
        || n.contains(" release candidate")
        || n.contains(" rc")
        || n.ends_with(" rc")
}

fn plist_date_secs(v: &Value) -> Option<i64> {
    match v {
        Value::Date(d) => {
            let st = SystemTime::from(*d);
            st.duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_secs()).ok())
        }
        // XML catalogs almost always emit real Date values; string form is rare.
        Value::String(s) => Date::from_xml_format(s.trim()).ok().and_then(|d| {
            SystemTime::from(d)
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_secs()).ok())
        }),
        _ => None,
    }
}

fn fetch_clt_title(dist_url: &str) -> Option<String> {
    // Small file; don't persist every dist — fetch into a temp under cache.
    let name = format!(
        "dist-{}.tmp",
        dist_url
            .rsplit('/')
            .next()
            .unwrap_or("english.dist")
            .replace(['/', ' '], "_")
    );
    let dest = download_cache::download_path(&name).ok()?;
    if download_cache::ensure_url(dist_url, &dest).is_err() {
        return None;
    }
    let text = fs::read_to_string(&dest).ok()?;
    // Prefer Software Update group id (human title used by softwareupdate).
    if let Some(id) = extract_xml_attr(&text, "suDisabledGroupID") {
        return Some(id);
    }
    if let Some(id) = extract_assignment(&text, "suDisabledGroupID") {
        return Some(id);
    }
    // Fallback: <title>…</title> (often a localization key).
    if let Some(t) = extract_xml_tag(&text, "title")
        && t != "SU_TITLE"
        && !t.is_empty()
    {
        return Some(t);
    }
    None
}

fn extract_xml_attr(text: &str, attr: &str) -> Option<String> {
    // suDisabledGroupID="Command Line Tools for Xcode 26.6"
    let key = format!("{attr}=\"");
    let idx = text.find(&key)?;
    let rest = text.get(idx.saturating_add(key.len())..)?;
    let end = rest.find('"')?;
    let val = rest.get(..end)?.trim();
    if val.is_empty() {
        return None;
    }
    Some(val.to_owned())
}

fn extract_assignment(text: &str, key: &str) -> Option<String> {
    // suDisabledGroupID = "…";
    for line in text.lines() {
        let t = line.trim();
        if !t.contains(key) {
            continue;
        }
        if let Some(q0) = t.find('"') {
            let rest = t.get(q0.saturating_add(1)..)?;
            if let Some(q1) = rest.find('"') {
                let val = rest.get(..q1)?.trim();
                if !val.is_empty() {
                    return Some(val.to_owned());
                }
            }
        }
    }
    None
}

fn extract_xml_tag(text: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)?.saturating_add(open.len());
    let rel = text.get(start..)?.find(&close)?;
    let end = start.saturating_add(rel);
    let val = text.get(start..end)?.trim();
    if val.is_empty() {
        return None;
    }
    Some(val.to_owned())
}

fn write_meta(archive: &Path, pkg: &CltPackage) -> Result<(), SwscanError> {
    let meta_path = archive
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(CLT_META_NAME);
    let nmos = pkg.nmos_sdk.as_ref().map(|s| s.name.as_str());
    let body = serde_json::json!({
        "source": "swscan",
        "name": pkg.name,
        "product_id": pkg.product_id,
        "url": pkg.executables_url,
        "nmos_sdk": nmos,
        "post_date": pkg.post_date,
        "archive": archive.display().to_string(),
        "fetched_unix": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    });
    if let Some(parent) = meta_path.parent() {
        fs::create_dir_all(parent).map_err(SwscanError::Io)?;
    }
    fs::write(&meta_path, body.to_string()).map_err(SwscanError::Io)?;
    Ok(())
}

fn mirror_alias(src: &Path, alias: &Path) -> Result<(), SwscanError> {
    if src == alias {
        return Ok(());
    }
    if alias.exists() || alias.symlink_metadata().is_ok() {
        drop(fs::remove_file(alias));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        if src.parent() == alias.parent()
            && let Some(name) = src.file_name()
        {
            symlink(name, alias).map_err(SwscanError::Io)?;
            return Ok(());
        }
        symlink(src, alias).map_err(SwscanError::Io)?;
    }
    #[cfg(not(unix))]
    {
        fs::copy(src, alias).map_err(SwscanError::Io)?;
    }
    Ok(())
}

fn cache_to_swscan(e: CacheError) -> SwscanError {
    match e {
        CacheError::Io(io) => SwscanError::Io(io),
        CacheError::Command(s) => SwscanError::Command(s),
    }
}

/// Errors talking to the Software Update catalog / CDN.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SwscanError {
    /// Filesystem I/O.
    #[error("swscan I/O: {0}")]
    Io(#[from] io::Error),
    /// curl / HTTP / catalog business error.
    #[error("{0}")]
    Command(String),
    /// plist / dist parse failure.
    #[error("catalog parse: {0}")]
    Parse(String),
}

/// Human-readable help when swscan path fails.
pub(crate) fn fallback_help(writer: &mut dyn Write) -> io::Result<()> {
    writeln!(
        writer,
        "Software Update (swscan) CLT download failed.\n  \
         Check network access to swscan.apple.com / swcdn.apple.com.\n  \
         Retry with KAKEHASHI_FORCE_DOWNLOAD=1 to refresh the catalog.\n  \
         Optional pin: {ENV_XCODE_TOOLS_VERSION}=26.6"
    )
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    unsafe_code
)]
mod tests {
    use super::*;

    #[test]
    fn detects_executables_pkg_names() {
        assert!(is_executables_pkg_name("CLTools_Executables_Universal.pkg"));
        assert!(is_executables_pkg_name("CLTools_Executables.pkg"));
        assert!(!is_executables_pkg_name("CLTools_macOS_SDK.pkg"));
        assert!(!is_executables_pkg_name("Command_Line_Tools.dmg"));
    }

    #[test]
    fn detects_nmos_sdk_only() {
        assert!(is_nmos_sdk_pkg_name("CLTools_macOSNMOS_SDK.pkg"));
        // Previous major / empty marker / remove / swift — not installed.
        assert!(!is_nmos_sdk_pkg_name("CLTools_macOSLMOS_SDK.pkg"));
        assert!(!is_nmos_sdk_pkg_name("CLTools_macOS_SDK.pkg"));
        assert!(!is_nmos_sdk_pkg_name(
            "CLTools_macOS_DevSDK_Remove_macOS14.pkg"
        ));
        assert!(!is_nmos_sdk_pkg_name("CLTools_SwiftBackDeploy.pkg"));
        assert!(!is_nmos_sdk_pkg_name("CLTools_Executables.pkg"));
    }

    #[test]
    fn detects_clt_names() {
        assert!(is_clt_name("Command Line Tools for Xcode 16.4"));
        assert!(is_clt_name("Command Line Tools for Xcode 26.6"));
        assert!(!is_clt_name("Xcode 16.4"));
    }

    #[test]
    fn prefers_stable_over_beta() {
        let pkgs = vec![
            CltPackage {
                product_id: "a".into(),
                name: "Command Line Tools for Xcode 26.0 beta".into(),
                executables_url: "https://example/a.pkg".into(),
                executables_name: "a.pkg".into(),
                nmos_sdk: None,
                post_date: 200,
            },
            CltPackage {
                product_id: "b".into(),
                name: "Command Line Tools for Xcode 16.4".into(),
                executables_url: "https://example/b.pkg".into(),
                executables_name: "b.pkg".into(),
                nmos_sdk: None,
                post_date: 100,
            },
        ];
        let mut sorted = pkgs;
        sorted.sort_by_key(|b| std::cmp::Reverse(b.post_date));
        let chosen = select_clt_package(&sorted).expect("select");
        assert!(chosen.name.contains("16.4"), "got {}", chosen.name);
    }

    #[test]
    fn extract_title_from_dist_snippet() {
        let snip = r#"
            <installer-gui-script>
            <title>SU_TITLE</title>
            <options suDisabledGroupID="Command Line Tools for Xcode 26.6"/>
            </installer-gui-script>
        "#;
        assert_eq!(
            extract_xml_attr(snip, "suDisabledGroupID").as_deref(),
            Some("Command Line Tools for Xcode 26.6")
        );
    }

    #[test]
    fn plist_date_from_xml_sort_key() {
        let a = plist_date_secs(&Value::Date(
            Date::from_xml_format("2026-06-26T16:11:21Z").expect("a"),
        ))
        .expect("a secs");
        let b = plist_date_secs(&Value::Date(
            Date::from_xml_format("2025-05-28T17:21:50Z").expect("b"),
        ))
        .expect("b secs");
        assert!(a > b);
    }

    /// Network smoke: public sucatalog lists at least one CLT product.
    #[test]
    #[ignore = "network: swscan.apple.com"]
    fn live_catalog_lists_clt() {
        // Isolate cache so we always hit the network for this smoke.
        let root = std::env::temp_dir().join(format!(
            "kh-swscan-live-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        ));
        fs::create_dir_all(&root).expect("tmpdir");
        // SAFETY: test-only env for isolated cache.
        unsafe {
            std::env::set_var("KAKEHASHI_CACHE_DIR", &root);
            std::env::set_var("KAKEHASHI_FORCE_DOWNLOAD", "1");
        }
        let list = list_clt_packages().expect("list CLT from swscan");
        assert!(!list.is_empty(), "expected CLT products");
        let chosen = select_clt_package(&list).expect("select");
        assert!(
            chosen.executables_url.contains("swcdn.apple.com"),
            "url={}",
            chosen.executables_url
        );
        assert!(
            is_executables_pkg_name(&chosen.executables_name),
            "name={}",
            chosen.executables_name
        );
        eprintln!(
            "selected: {} ({}) → {}",
            chosen.name, chosen.product_id, chosen.executables_name
        );
        unsafe {
            std::env::remove_var("KAKEHASHI_CACHE_DIR");
            std::env::remove_var("KAKEHASHI_FORCE_DOWNLOAD");
        }
        drop(fs::remove_dir_all(&root));
    }
}
