//! systemd units. Commands are run through `systemctl`, so no D-Bus library
//! is needed.
//!
//! The unit runs cloudflared as the unprivileged `tunnelkeeper` system user.
//! The token file belongs to that user with mode 0400.

use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use super::{ServiceInfo, ServiceManager, ServiceSpec, ServiceState};
use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::util::write_atomic;

const SERVICE_USER: &str = "tunnelkeeper";
const START_WAIT: Duration = Duration::from_secs(20);

fn unit_path(name: &str) -> String {
    format!("/etc/systemd/system/{name}.service")
}

fn run(program: &str, args: &[&str]) -> Result<Output> {
    Command::new(program).args(args).output().map_err(|e| Error::io(format!("run {program}"), e))
}

fn must(program: &str, args: &[&str]) -> Result<()> {
    let out = run(program, args)?;
    if out.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&out.stderr);
    if text.contains("Access denied") || text.contains("Interactive authentication required") {
        return Err(Error::Elevation(format!("{program} needs root: {}", text.trim())));
    }
    Err(Error::Service(format!("{program} {} failed: {}", args.join(" "), text.trim())))
}

/// Quotes one ExecStart argument for systemd.
fn quote(arg: &str) -> String {
    if arg.chars().any(|c| c.is_whitespace() || c == '"') {
        format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

/// The full unit file. Pure, so it can be tested on any platform.
pub fn unit_text(spec: &ServiceSpec) -> String {
    let mut exec = quote(&spec.binary.display().to_string());
    for a in &spec.args {
        exec.push(' ');
        exec.push_str(&quote(a));
    }
    format!(
        "[Unit]
Description={display}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=notify
User={user}
ExecStart={exec}
Restart=always
RestartSec=5
TimeoutStartSec=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
ReadWritePaths={logs}

[Install]
WantedBy=multi-user.target
",
        display = spec.display_name,
        user = SERVICE_USER,
        logs = quote(&spec.log_dir.display().to_string()),
    )
}

/// Reads `systemctl show` output into a service state.
pub fn parse_show(name: &str, text: &str) -> ServiceInfo {
    let get = |key: &str| text.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix('=')).unwrap_or("");
    if get("LoadState") != "loaded" {
        return ServiceInfo::missing(name);
    }
    let state = match (get("ActiveState"), get("SubState")) {
        ("active", _) | ("reloading", _) => ServiceState::Running,
        ("activating", _) => ServiceState::Starting,
        ("deactivating", _) => ServiceState::Stopping,
        ("inactive", _) | ("failed", _) => ServiceState::Stopped,
        _ => ServiceState::Other,
    };
    let exec = get("ExecStart");
    let command_line = exec
        .split("argv[]=")
        .nth(1)
        .map(|rest| rest.split(" ;").next().unwrap_or(rest).trim().to_string())
        .filter(|c| !c.is_empty());
    ServiceInfo {
        name: name.to_string(),
        state,
        pid: get("MainPID").parse().ok().filter(|p| *p != 0),
        command_line,
        exit_code: get("ExecMainStatus").parse().ok(),
    }
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| Error::io(format!("chmod {}", path.display()), e))
}

fn ensure_user() -> Result<()> {
    if run("id", &["-u", SERVICE_USER])?.status.success() {
        return Ok(());
    }
    must("useradd", &["--system", "--no-create-home", "--shell", "/usr/sbin/nologin", SERVICE_USER])
}

pub struct SystemdServices;

impl ServiceManager for SystemdServices {
    fn query(&self, name: &str) -> Result<ServiceInfo> {
        let unit = format!("{name}.service");
        let out = run(
            "systemctl",
            &["show", &unit, "--property=LoadState,ActiveState,SubState,MainPID,ExecStart,ExecMainStatus"],
        )?;
        Ok(parse_show(name, &String::from_utf8_lossy(&out.stdout)))
    }

    fn prepare_machine_dirs(&self, paths: &Paths) -> Result<()> {
        ensure_user()?;
        for dir in [&paths.bin_dir, &paths.token_dir, &paths.log_root] {
            std::fs::create_dir_all(dir).map_err(|e| Error::io(format!("create {}", dir.display()), e))?;
            must("chown", &["root:root", &dir.display().to_string()])?;
            // Users may list these, so unelevated checks can see that a token
            // exists. The token files themselves are mode 0400.
            set_mode(dir, 0o755)?;
        }
        Ok(())
    }

    fn install(&self, spec: &ServiceSpec) -> Result<()> {
        let token = spec.token_path.display().to_string();
        must("chown", &[&format!("{SERVICE_USER}:{SERVICE_USER}"), &token])?;
        set_mode(&spec.token_path, 0o400)?;
        std::fs::create_dir_all(&spec.log_dir).map_err(|e| Error::io("create log folder", e))?;
        must("chown", &[&format!("{SERVICE_USER}:{SERVICE_USER}"), &spec.log_dir.display().to_string()])?;
        set_mode(&spec.log_dir, 0o755)?;
        write_atomic(Path::new(&unit_path(&spec.name)), unit_text(spec).as_bytes())?;
        set_mode(Path::new(&unit_path(&spec.name)), 0o644)?;
        must("systemctl", &["daemon-reload"])?;
        must("systemctl", &["enable", &format!("{}.service", spec.name)])
    }

    /// Does not wait for cloudflared to connect. With Type=notify a plain
    /// `systemctl start` would hang for as long as the network is down.
    fn start(&self, name: &str) -> Result<()> {
        must("systemctl", &["start", "--no-block", &format!("{name}.service")])?;
        let begin = Instant::now();
        while begin.elapsed() < START_WAIT {
            if matches!(self.query(name)?.state, ServiceState::Running | ServiceState::Starting) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Err(Error::Service(format!("{name} did not start in time")))
    }

    fn stop(&self, name: &str) -> Result<()> {
        must("systemctl", &["stop", &format!("{name}.service")])
    }

    fn uninstall(&self, name: &str) -> Result<()> {
        if self.query(name)?.state == ServiceState::Missing {
            return Ok(());
        }
        must("systemctl", &["disable", "--now", &format!("{name}.service")])?;
        match std::fs::remove_file(unit_path(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(Error::io("delete unit file", e)),
            _ => {}
        }
        must("systemctl", &["daemon-reload"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::tunnel_spec;

    fn spec() -> ServiceSpec {
        tunnel_spec(&Paths::under(Path::new("/opt/my data")), "web", 20301)
    }

    #[test]
    fn unit_meets_the_restart_requirements() {
        let u = unit_text(&spec());
        for line in ["Restart=always", "StartLimitIntervalSec=0", "WantedBy=multi-user.target", "User=tunnelkeeper", "Type=notify"] {
            assert!(u.lines().any(|l| l == line), "{line}\n{u}");
        }
        assert!(u.contains("--token-file"));
        assert!(!u.contains("--token "), "the token is never on the command line");
    }

    #[test]
    fn start_limit_is_in_the_unit_section() {
        let u = unit_text(&spec());
        assert!(u.find("StartLimitIntervalSec").unwrap() < u.find("[Service]").unwrap());
    }

    #[test]
    fn paths_with_spaces_are_quoted() {
        assert!(unit_text(&spec()).contains("\"/opt/my data/machine/bin/cloudflared\""));
    }

    #[test]
    fn parses_systemctl_show() {
        let text = "MainPID=1234\nExecMainStatus=0\nLoadState=loaded\nActiveState=active\nSubState=running\nExecStart={ path=/x/cloudflared ; argv[]=/x/cloudflared tunnel --metrics 127.0.0.1:20301 run ; ignore_errors=no ; start_time=[n/a] }\n";
        let i = parse_show("tk", text);
        assert_eq!(i.state, ServiceState::Running);
        assert_eq!(i.pid, Some(1234));
        assert_eq!(i.command_line.as_deref(), Some("/x/cloudflared tunnel --metrics 127.0.0.1:20301 run"));
    }

    #[test]
    fn missing_and_restarting_units() {
        assert_eq!(parse_show("tk", "LoadState=not-found\nActiveState=inactive\n").state, ServiceState::Missing);
        assert_eq!(parse_show("tk", "LoadState=loaded\nActiveState=activating\nSubState=auto-restart\nMainPID=0\n").state, ServiceState::Starting);
        assert_eq!(parse_show("tk", "LoadState=loaded\nActiveState=failed\nSubState=failed\n").state, ServiceState::Stopped);
    }
}
