//! The fixed set of operations that need admin rights, and how we get them.
//! There is deliberately no generic command execution here.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::validate_tunnel_name;
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::secret::{Secret, serialize_exposed};
use crate::service::{ServiceManager, ServiceState, platform_manager, service_name, tunnel_spec};
use crate::util::{random_hex, sha256_file, write_private};

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PrivilegedOp {
    /// Copies the binary, stores the token, then creates and starts the service.
    InstallTunnel {
        tunnel: String,
        metrics_port: u16,
        source_binary: PathBuf,
        source_sha256: String,
        #[serde(serialize_with = "serialize_exposed")]
        token: Secret,
    },
    Start { tunnel: String },
    Stop { tunnel: String },
    /// Removes the service and its token. Logs stay.
    Uninstall { tunnel: String },
}

fn install_binary(paths: &Paths, services: &dyn ServiceManager, tunnel: &str, source: &Path, expected: &str) -> Result<()> {
    let target = paths.managed_cloudflared();
    if target.is_file() && sha256_file(&target)? == expected {
        return Ok(());
    }
    if sha256_file(source)? != expected {
        return Err(Error::Service(format!("{} changed since it was checked, refusing to install it", source.display())));
    }
    let name = service_name(tunnel);
    if services.query(&name)?.state == ServiceState::Running {
        services.stop(&name)?;
    }
    let temp = target.with_extension(format!("tmp{}", random_hex(4)));
    std::fs::copy(source, &temp).map_err(|e| Error::io("copy cloudflared", e))?;
    // Checked again after the copy, because the source is user writable.
    if sha256_file(&temp)? != expected {
        let _ = std::fs::remove_file(&temp);
        return Err(Error::Service("copied binary does not match its checksum".into()));
    }
    std::fs::rename(&temp, &target).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        Error::io("put cloudflared in place, another tunnel may be using the old file", e)
    })
}

/// Runs an operation. The caller must already have the needed rights.
pub fn execute(op: &PrivilegedOp, paths: &Paths, services: &dyn ServiceManager) -> Result<()> {
    match op {
        PrivilegedOp::InstallTunnel { tunnel, metrics_port, source_binary, source_sha256, token } => {
            validate_tunnel_name(tunnel)?;
            services.prepare_machine_dirs(paths)?;
            install_binary(paths, services, tunnel, source_binary, source_sha256)?;
            write_private(&paths.tunnel_token(tunnel), token.expose().as_bytes())?;
            services.install(&tunnel_spec(paths, tunnel, *metrics_port))?;
            services.start(&service_name(tunnel))
        }
        PrivilegedOp::Start { tunnel } => {
            validate_tunnel_name(tunnel)?;
            services.start(&service_name(tunnel))
        }
        PrivilegedOp::Stop { tunnel } => {
            validate_tunnel_name(tunnel)?;
            services.stop(&service_name(tunnel))
        }
        PrivilegedOp::Uninstall { tunnel } => {
            validate_tunnel_name(tunnel)?;
            services.uninstall(&service_name(tunnel))?;
            match std::fs::remove_file(paths.tunnel_token(tunnel)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::io("delete tunnel token", e)),
                _ => Ok(()),
            }
        }
    }
}

pub trait Elevator: Send {
    fn run(&self, op: &PrivilegedOp) -> Result<()>;
}

/// Entry point of the hidden `elevated` subcommand. The handoff file holds
/// the operation, and is deleted before anything else happens.
pub fn run_handoff(path: &Path) -> i32 {
    let outcome = (|| -> Result<()> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::io("read handoff file", e))?;
        let _ = std::fs::remove_file(path);
        let op: PrivilegedOp = serde_json::from_str(&text).map_err(|e| Error::Elevation(format!("bad handoff file: {e}")))?;
        execute(&op, &Paths::detect()?, platform_manager().as_ref())
    })();
    match outcome {
        Ok(()) => 0,
        Err(e) => {
            let _ = std::fs::write(path.with_extension("result"), e.to_string());
            1
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::mem::{size_of, zeroed};
    use std::ptr::null;

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, GetLastError};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    use super::*;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn is_elevated() -> bool {
        unsafe { IsUserAnAdmin() != 0 }
    }

    /// Starts this binary through UAC and waits for it.
    pub fn relaunch(handoff: &Path) -> Result<i32> {
        let exe = std::env::current_exe().map_err(|e| Error::io("find own path", e))?;
        let (verb, file) = (wide("runas"), wide(&exe.display().to_string()));
        let params = wide(&format!("elevated --handoff \"{}\"", handoff.display()));
        unsafe {
            let mut info: SHELLEXECUTEINFOW = zeroed();
            info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.lpDirectory = null();
            info.nShow = SW_HIDE;
            if ShellExecuteExW(&mut info) == 0 {
                let code = GetLastError();
                return Err(if code == ERROR_CANCELLED {
                    Error::Elevation("the administrator prompt was declined".into())
                } else {
                    Error::Elevation(format!("could not request administrator rights, Windows error {code}"))
                });
            }
            WaitForSingleObject(info.hProcess, INFINITE);
            let mut exit = 1u32;
            GetExitCodeProcess(info.hProcess, &mut exit);
            CloseHandle(info.hProcess);
            Ok(exit as i32)
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use std::io::IsTerminal;
    use std::process::Command;

    use super::*;

    pub fn is_elevated() -> bool {
        std::fs::read_to_string("/proc/self/status").is_ok_and(|s| {
            s.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|l| l.split_whitespace().nth(1)).is_some_and(|euid| euid == "0")
        })
    }

    /// sudo in a terminal, pkexec otherwise. Without either, the error says
    /// what to run instead.
    pub fn relaunch(handoff: &Path) -> Result<i32> {
        let exe = std::env::current_exe().map_err(|e| Error::io("find own path", e))?;
        let launcher = if std::io::stdin().is_terminal() { "sudo" } else { "pkexec" };
        let status = Command::new(launcher).arg(&exe).arg("elevated").arg("--handoff").arg(handoff).status();
        match status {
            Ok(s) => Ok(s.code().unwrap_or(1)),
            Err(_) => Err(Error::Elevation(format!(
                "{launcher} is not available. Run this tunnelkeeper command again as root"
            ))),
        }
    }
}

pub use platform::is_elevated;

/// Runs in process when already elevated, otherwise asks the OS.
pub struct PlatformElevator {
    pub paths: Paths,
}

impl Elevator for PlatformElevator {
    fn run(&self, op: &PrivilegedOp) -> Result<()> {
        if is_elevated() {
            return execute(op, &self.paths, platform_manager().as_ref());
        }
        let dir = self.paths.handoff_dir();
        std::fs::create_dir_all(&dir).map_err(|e| Error::io("create handoff folder", e))?;
        let file = dir.join(format!("{}.json", random_hex(16)));
        let result_file = file.with_extension("result");
        let json = serde_json::to_vec(op).map_err(|e| Error::Elevation(e.to_string()))?;
        write_private(&file, &json)?;
        let outcome = platform::relaunch(&file);
        let _ = std::fs::remove_file(&file);
        let message = std::fs::read_to_string(&result_file).ok();
        let _ = std::fs::remove_file(&result_file);
        match outcome? {
            0 => Ok(()),
            code => Err(Error::Service(message.unwrap_or_else(|| format!("elevated step failed with exit code {code}")))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_carries_the_token_through_json() {
        let op = PrivilegedOp::InstallTunnel {
            tunnel: "web".into(),
            metrics_port: 1,
            source_binary: "x".into(),
            source_sha256: "y".into(),
            token: Secret::new("the-token"),
        };
        let text = serde_json::to_string(&op).unwrap();
        match serde_json::from_str(&text).unwrap() {
            PrivilegedOp::InstallTunnel { token, .. } => assert_eq!(token.expose(), "the-token"),
            _ => panic!("wrong variant"),
        }
    }
}
