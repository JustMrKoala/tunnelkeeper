//! Finding, checking and downloading cloudflared.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cloudflare::agent;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::util::hex;

pub const RELEASE_BASE: &str = "https://api.github.com";

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct CloudflaredStatus {
    pub found: bool,
    /// The file that would be copied to the managed folder.
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    /// Found through a launcher such as a Scoop shim.
    pub via_shim: bool,
    pub meets_minimum: bool,
    pub minimum: String,
}

impl CloudflaredStatus {
    pub fn missing(minimum: &str) -> Self {
        CloudflaredStatus { found: false, path: None, version: None, via_shim: false, meets_minimum: false, minimum: minimum.to_string() }
    }
}

/// `cloudflared version 2026.3.0 (built ...)` gives `2026.3.0`.
pub fn parse_version(output: &str) -> Option<String> {
    let mut words = output.split_whitespace();
    while let Some(w) = words.next() {
        if w == "version" {
            return words.next().map(str::to_string);
        }
    }
    None
}

pub fn version_at_least(version: &str, minimum: &str) -> bool {
    let parts = |v: &str| v.split('.').map(|p| p.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    parts(version) >= parts(minimum)
}

/// Scoop puts a launcher in its shims folder with a `.shim` file beside it.
/// A launcher breaks the service handshake, so we need the real file.
pub fn resolve_shim(path: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(path.with_extension("shim")).ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "path").then(|| PathBuf::from(value.trim().trim_matches('"')))
    })
}

fn exe_name() -> &'static str {
    if cfg!(windows) { "cloudflared.exe" } else { "cloudflared" }
}

fn from_path_env() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(exe_name())).find(|p| p.is_file())
}

fn read_version(path: &Path) -> Option<String> {
    let out = Command::new(path).arg("--version").output().ok()?;
    parse_version(&String::from_utf8_lossy(&out.stdout))
}

/// Looks in every known place and picks the newest binary.
pub fn locate(config: &Config, paths: &Paths) -> CloudflaredStatus {
    let minimum = config.cloudflared.min_version.clone();
    let mut candidates: Vec<(PathBuf, bool)> = Vec::new();
    if config.cloudflared.path != "managed" {
        candidates.push((PathBuf::from(&config.cloudflared.path), false));
    } else {
        candidates.push((paths.managed_cloudflared(), false));
        candidates.push((paths.download_dir().join(exe_name()), false));
        if let Some(p) = from_path_env() {
            match resolve_shim(&p) {
                Some(real) => candidates.push((real, true)),
                None => candidates.push((p, false)),
            }
        }
    }
    let mut best: Option<(PathBuf, bool, String)> = None;
    for (path, via_shim) in candidates {
        if !path.is_file() {
            continue;
        }
        if let Some(v) = read_version(&path) {
            let newer = best.as_ref().is_none_or(|(_, _, b)| !version_at_least(b, &v));
            if newer {
                best = Some((path, via_shim, v));
            }
        }
    }
    match best {
        Some((path, via_shim, version)) => CloudflaredStatus {
            found: true,
            meets_minimum: version_at_least(&version, &minimum),
            path: Some(path),
            version: Some(version),
            via_shim,
            minimum,
        },
        None => CloudflaredStatus::missing(&minimum),
    }
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ReleaseInfo {
    pub version: String,
    pub asset: String,
    pub url: String,
    pub sha256: String,
}

pub fn asset_name() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Ok("cloudflared-windows-amd64.exe"),
        ("windows", "x86") => Ok("cloudflared-windows-386.exe"),
        ("linux", "x86_64") => Ok("cloudflared-linux-amd64"),
        ("linux", "aarch64") => Ok("cloudflared-linux-arm64"),
        (os, arch) => Err(Error::CloudflaredMissing(format!("no official download known for {os} {arch}"))),
    }
}

/// Finds `name: hash` in the release notes, the only place checksums are published.
pub fn checksum_from_notes(notes: &str, asset: &str) -> Option<String> {
    notes.lines().find_map(|line| {
        let (name, hash) = line.split_once(':')?;
        let hash = hash.trim();
        (name.trim() == asset && hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

pub fn fetch_release(base: &str, version: Option<&str>, asset: &str) -> Result<ReleaseInfo> {
    let url = match version {
        Some(v) => format!("{base}/repos/cloudflare/cloudflared/releases/tags/{v}"),
        None => format!("{base}/repos/cloudflare/cloudflared/releases/latest"),
    };
    let mut resp = agent(Duration::from_secs(30))
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| Error::Network(format!("GET {url}: {e}")))?;
    if resp.status().as_u16() != 200 {
        return Err(Error::Network(format!("GET {url}: HTTP {}", resp.status().as_u16())));
    }
    let text = resp.body_mut().read_to_string().map_err(|e| Error::Network(e.to_string()))?;
    let release: GithubRelease = serde_json::from_str(&text).map_err(|e| Error::Network(format!("unexpected release data: {e}")))?;
    let found = release
        .assets
        .iter()
        .find(|a| a.name == asset)
        .ok_or_else(|| Error::CloudflaredMissing(format!("release {} has no asset {asset}", release.tag_name)))?;
    let sha256 = checksum_from_notes(&release.body, asset)
        .ok_or_else(|| Error::CloudflaredMissing(format!("release {} publishes no checksum for {asset}, refusing to download", release.tag_name)))?;
    Ok(ReleaseInfo { version: release.tag_name, asset: asset.to_string(), url: found.browser_download_url.clone(), sha256 })
}

/// Downloads into the user cache. The file only gets its final name after
/// the checksum matches.
pub fn download_verified(release: &ReleaseInfo, paths: &Paths) -> Result<PathBuf> {
    let dir = paths.download_dir();
    std::fs::create_dir_all(&dir).map_err(|e| Error::io("create download folder", e))?;
    let partial = dir.join(format!("{}.partial", release.asset));
    let resp = agent(Duration::from_secs(600))
        .get(&release.url)
        .call()
        .map_err(|e| Error::Network(format!("download {}: {e}", release.asset)))?;
    if resp.status().as_u16() != 200 {
        return Err(Error::Network(format!("download {}: HTTP {}", release.asset, resp.status().as_u16())));
    }
    let mut reader = resp.into_body().into_reader();
    let mut file = std::fs::File::create(&partial).map_err(|e| Error::io("create download file", e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(|e| Error::io("read download", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).map_err(|e| Error::io("write download", e))?;
    }
    drop(file);
    let actual = hex(&hasher.finalize());
    if actual != release.sha256 {
        let _ = std::fs::remove_file(&partial);
        return Err(Error::CloudflaredMissing(format!(
            "checksum mismatch for {}: expected {}, got {actual}. The download was deleted",
            release.asset, release.sha256
        )));
    }
    let target = dir.join(exe_name());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o755)).map_err(|e| Error::io("mark executable", e))?;
    }
    std::fs::rename(&partial, &target).map_err(|e| Error::io("move download into place", e))?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_version_output() {
        assert_eq!(parse_version("cloudflared version 2026.3.0 (built 2026-03-05T16:47 UTC)").as_deref(), Some("2026.3.0"));
        assert_eq!(parse_version("nonsense"), None);
    }

    #[test]
    fn compares_versions_numerically() {
        assert!(version_at_least("2026.3.0", "2025.4.0"));
        assert!(version_at_least("2025.4.0", "2025.4.0"));
        assert!(version_at_least("2025.10.0", "2025.4.0"));
        assert!(!version_at_least("2025.3.9", "2025.4.0"));
    }

    #[test]
    fn reads_scoop_shim() {
        let dir = std::env::temp_dir().join(format!("tk-shim-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cloudflared.shim"), "path = \"C:\\apps\\cloudflared.exe\"\n").unwrap();
        assert_eq!(resolve_shim(&dir.join("cloudflared.exe")), Some(PathBuf::from("C:\\apps\\cloudflared.exe")));
        assert_eq!(resolve_shim(&dir.join("other.exe")), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn finds_checksum_in_real_format() {
        let notes = "### SHA256 Checksums:\n```\ncloudflared-windows-amd64.exe: 2493dbc168923bb3e59e5e7716f71deced92992eea9acd6e9d74f84ac7751343\ncloudflared-windows-amd64.msi: 057a1370fe26b1a4d45d8673c219fa3ddb3c3b4bcbf0cde25ee938c932645387\n```";
        assert_eq!(
            checksum_from_notes(notes, "cloudflared-windows-amd64.exe").as_deref(),
            Some("2493dbc168923bb3e59e5e7716f71deced92992eea9acd6e9d74f84ac7751343")
        );
        assert_eq!(checksum_from_notes(notes, "cloudflared-linux-amd64"), None);
    }
}
