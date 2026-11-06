//! Where things live. User level and machine level paths are kept apart
//! because machine paths are protected and need elevation to change.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct Paths {
    /// config.toml and the journal. User level.
    pub config_dir: PathBuf,
    /// Downloads and privileged handoff files. User level.
    pub cache_dir: PathBuf,
    /// Root of the machine level folders.
    pub machine_dir: PathBuf,
    /// Machine level folder for the managed cloudflared binary.
    pub bin_dir: PathBuf,
    /// Machine level folder for tunnel tokens.
    pub token_dir: PathBuf,
    /// Machine level folder for service logs.
    pub log_root: PathBuf,
}

impl Paths {
    /// Everything under one folder. Used by tests.
    pub fn under(root: &Path) -> Self {
        Paths {
            config_dir: root.join("config"),
            cache_dir: root.join("cache"),
            machine_dir: root.join("machine"),
            bin_dir: root.join("machine").join("bin"),
            token_dir: root.join("machine").join("tunnels"),
            log_root: root.join("machine").join("logs"),
        }
    }

    pub fn detect() -> Result<Self> {
        if let Some(home) = std::env::var_os("TUNNELKEEPER_HOME") {
            return Ok(Self::under(Path::new(&home)));
        }
        Self::detect_platform()
    }

    #[cfg(windows)]
    fn detect_platform() -> Result<Self> {
        let var = |k: &str| std::env::var_os(k).map(PathBuf::from).ok_or_else(|| Error::Config(format!("{k} is not set")));
        let machine = var("ProgramData")?.join("tunnelkeeper");
        Ok(Paths {
            config_dir: var("APPDATA")?.join("tunnelkeeper"),
            cache_dir: var("LOCALAPPDATA")?.join("tunnelkeeper"),
            bin_dir: machine.join("bin"),
            token_dir: machine.join("tunnels"),
            log_root: machine.join("logs"),
            machine_dir: machine,
        })
    }

    #[cfg(not(windows))]
    fn detect_platform() -> Result<Self> {
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| Error::Config("HOME is not set".into()))?;
        Ok(Paths {
            config_dir: home.join(".config/tunnelkeeper"),
            cache_dir: home.join(".cache/tunnelkeeper"),
            machine_dir: PathBuf::from("/etc/tunnelkeeper"),
            bin_dir: PathBuf::from("/usr/local/lib/tunnelkeeper"),
            token_dir: PathBuf::from("/etc/tunnelkeeper"),
            log_root: PathBuf::from("/var/log/tunnelkeeper"),
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn journal_dir(&self) -> PathBuf {
        self.config_dir.join("runs")
    }
    pub fn handoff_dir(&self) -> PathBuf {
        self.cache_dir.join("handoff")
    }
    pub fn download_dir(&self) -> PathBuf {
        self.cache_dir.join("downloads")
    }
    pub fn managed_cloudflared(&self) -> PathBuf {
        self.bin_dir.join(if cfg!(windows) { "cloudflared.exe" } else { "cloudflared" })
    }
    pub fn tunnel_token(&self, tunnel: &str) -> PathBuf {
        self.token_dir.join(format!("{tunnel}.token"))
    }
    pub fn log_dir(&self, tunnel: &str) -> PathBuf {
        self.log_root.join(tunnel)
    }
}
