//! The system service layer. We register services ourselves, because
//! `cloudflared service install` does not meet the restart requirements.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::Result;
use crate::paths::Paths;

#[cfg(unix)]
pub mod systemd;
#[cfg(windows)]
pub mod windows;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Missing,
    Stopped,
    Starting,
    Running,
    Stopping,
    Other,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ServiceInfo {
    pub name: String,
    pub state: ServiceState,
    pub pid: Option<u32>,
    pub command_line: Option<String>,
    pub exit_code: Option<u32>,
}

impl ServiceInfo {
    pub fn missing(name: &str) -> Self {
        ServiceInfo { name: name.to_string(), state: ServiceState::Missing, pid: None, command_line: None, exit_code: None }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceSpec {
    pub name: String,
    pub display_name: String,
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub token_path: PathBuf,
    pub log_dir: PathBuf,
}

pub trait ServiceManager: Send {
    /// Works without elevation.
    fn query(&self, name: &str) -> Result<ServiceInfo>;
    /// Creates machine folders with safe permissions. Needs elevation.
    fn prepare_machine_dirs(&self, paths: &Paths) -> Result<()>;
    /// Creates the service, or updates it to match the spec. Needs elevation.
    fn install(&self, spec: &ServiceSpec) -> Result<()>;
    fn start(&self, name: &str) -> Result<()>;
    fn stop(&self, name: &str) -> Result<()>;
    /// Stops and removes the service. A missing service is not an error.
    fn uninstall(&self, name: &str) -> Result<()>;
}

pub fn service_name(tunnel: &str) -> String {
    format!("tunnelkeeper-{tunnel}")
}

/// The arguments for cloudflared. The token is passed as a file path, so it
/// never appears in the service command line.
pub fn cloudflared_args(metrics_port: u16, log_dir: &Path, token_path: &Path) -> Vec<String> {
    vec![
        "tunnel".into(),
        "--no-autoupdate".into(),
        "--metrics".into(),
        format!("127.0.0.1:{metrics_port}"),
        "--loglevel".into(),
        "info".into(),
        "--log-directory".into(),
        log_dir.display().to_string(),
        "run".into(),
        "--token-file".into(),
        token_path.display().to_string(),
    ]
}

pub fn tunnel_spec(paths: &Paths, tunnel: &str, metrics_port: u16) -> ServiceSpec {
    let log_dir = paths.log_dir(tunnel);
    let token_path = paths.tunnel_token(tunnel);
    ServiceSpec {
        name: service_name(tunnel),
        display_name: format!("tunnelkeeper tunnel {tunnel}"),
        binary: paths.managed_cloudflared(),
        args: cloudflared_args(metrics_port, &log_dir, &token_path),
        token_path,
        log_dir,
    }
}

pub fn platform_manager() -> Box<dyn ServiceManager> {
    #[cfg(windows)]
    {
        Box::new(windows::WindowsServices)
    }
    #[cfg(not(windows))]
    {
        Box::new(systemd::SystemdServices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_never_on_command_line_only_its_path() {
        let paths = Paths::under(Path::new("root"));
        let spec = tunnel_spec(&paths, "web", 20301);
        assert_eq!(spec.name, "tunnelkeeper-web");
        assert!(spec.args.contains(&"--token-file".to_string()));
        assert!(!spec.args.contains(&"--token".to_string()));
    }

    #[test]
    fn metrics_bind_to_loopback() {
        let args = cloudflared_args(20301, Path::new("l"), Path::new("t"));
        assert!(args.contains(&"127.0.0.1:20301".to_string()));
    }

    #[test]
    fn tunnel_level_flags_come_before_run() {
        let args = cloudflared_args(1, Path::new("l"), Path::new("t"));
        let run = args.iter().position(|a| a == "run").unwrap();
        let token = args.iter().position(|a| a == "--token-file").unwrap();
        let metrics = args.iter().position(|a| a == "--metrics").unwrap();
        assert!(metrics < run && run < token);
    }
}
