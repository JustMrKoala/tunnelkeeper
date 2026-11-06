//! In memory stand ins for the OS boundaries, shared by the test suites.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::cloudflared::CloudflaredStatus;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::health::{OriginProbe, Probes, ReadyProbe};
use crate::paths::Paths;
use crate::privileged::{Elevator, PrivilegedOp, execute};
use crate::service::{ServiceInfo, ServiceManager, ServiceSpec, ServiceState};

#[derive(Default)]
struct ServiceData {
    services: HashMap<String, ServiceInfo>,
    fail_op: Option<String>,
    log: Vec<String>,
}

/// A fake service manager. Clones share state, so a test keeps a handle.
#[derive(Clone, Default)]
pub struct FakeServices(Arc<Mutex<ServiceData>>);

impl FakeServices {
    /// The next call of this operation fails: install, start, stop or uninstall.
    pub fn fail_next(&self, op: &str) {
        self.0.lock().unwrap().fail_op = Some(op.to_string());
    }
    pub fn clear_failure(&self) {
        self.0.lock().unwrap().fail_op = None;
    }
    pub fn log(&self) -> Vec<String> {
        self.0.lock().unwrap().log.clone()
    }
    pub fn state(&self, name: &str) -> ServiceState {
        self.0.lock().unwrap().services.get(name).map(|s| s.state).unwrap_or(ServiceState::Missing)
    }
    pub fn set_state(&self, name: &str, state: ServiceState) {
        if let Some(s) = self.0.lock().unwrap().services.get_mut(name) {
            s.state = state;
        }
    }
    pub fn set_pid(&self, name: &str, pid: u32) {
        if let Some(s) = self.0.lock().unwrap().services.get_mut(name) {
            s.pid = Some(pid);
        }
    }
    pub fn command_line(&self, name: &str) -> Option<String> {
        self.0.lock().unwrap().services.get(name).and_then(|s| s.command_line.clone())
    }

    fn step(&self, op: &str, name: &str) -> Result<()> {
        let mut d = self.0.lock().unwrap();
        d.log.push(format!("{op} {name}"));
        if d.fail_op.as_deref() == Some(op) {
            d.fail_op = None;
            return Err(Error::Service(format!("injected {op} failure")));
        }
        Ok(())
    }
}

impl ServiceManager for FakeServices {
    fn query(&self, name: &str) -> Result<ServiceInfo> {
        Ok(self.0.lock().unwrap().services.get(name).cloned().unwrap_or_else(|| ServiceInfo::missing(name)))
    }

    fn prepare_machine_dirs(&self, paths: &Paths) -> Result<()> {
        for d in [&paths.bin_dir, &paths.token_dir, &paths.log_root] {
            std::fs::create_dir_all(d).map_err(|e| Error::io("create", e))?;
        }
        Ok(())
    }

    fn install(&self, spec: &ServiceSpec) -> Result<()> {
        self.step("install", &spec.name)?;
        let command = format!("\"{}\" {}", spec.binary.display(), spec.args.join(" "));
        self.0.lock().unwrap().services.insert(
            spec.name.clone(),
            ServiceInfo {
                name: spec.name.clone(),
                state: ServiceState::Stopped,
                pid: None,
                command_line: Some(command),
                exit_code: Some(0),
            },
        );
        Ok(())
    }

    fn start(&self, name: &str) -> Result<()> {
        self.step("start", name)?;
        self.set_state(name, ServiceState::Running);
        self.set_pid(name, 1000);
        Ok(())
    }

    fn stop(&self, name: &str) -> Result<()> {
        self.step("stop", name)?;
        self.set_state(name, ServiceState::Stopped);
        Ok(())
    }

    fn uninstall(&self, name: &str) -> Result<()> {
        self.step("uninstall", name)?;
        self.0.lock().unwrap().services.remove(name);
        Ok(())
    }
}

/// Runs privileged operations in process, against the fake services.
pub struct InlineElevator {
    pub paths: Paths,
    pub services: FakeServices,
    /// Copies of every op name, for asserting what was elevated.
    pub ops: Arc<Mutex<Vec<String>>>,
    pub decline: Arc<Mutex<bool>>,
}

impl Elevator for InlineElevator {
    fn run(&self, op: &PrivilegedOp) -> Result<()> {
        if *self.decline.lock().unwrap() {
            return Err(Error::Elevation("the administrator prompt was declined".into()));
        }
        let name = match op {
            PrivilegedOp::InstallTunnel { .. } => "install_tunnel",
            PrivilegedOp::Start { .. } => "start",
            PrivilegedOp::Stop { .. } => "stop",
            PrivilegedOp::Uninstall { .. } => "uninstall",
        };
        self.ops.lock().unwrap().push(name.to_string());
        execute(op, &self.paths, &self.services)
    }
}

#[derive(Default)]
struct ProbeData {
    ready: Option<ReadyProbe>,
    origins: HashMap<String, OriginProbe>,
    no_dns: bool,
    no_tcp: bool,
    busy_ports: Vec<u16>,
}

#[derive(Clone, Default)]
pub struct FakeProbes(Arc<Mutex<ProbeData>>);

impl FakeProbes {
    pub fn set_ready(&self, r: ReadyProbe) {
        self.0.lock().unwrap().ready = Some(r);
    }
    pub fn set_origin(&self, service: &str, o: OriginProbe) {
        self.0.lock().unwrap().origins.insert(service.to_string(), o);
    }
    pub fn set_network(&self, dns: bool, tcp: bool) {
        let mut d = self.0.lock().unwrap();
        d.no_dns = !dns;
        d.no_tcp = !tcp;
    }
    pub fn set_port_busy(&self, port: u16) {
        self.0.lock().unwrap().busy_ports.push(port);
    }
}

impl Probes for FakeProbes {
    fn ready(&self, _: u16) -> ReadyProbe {
        self.0.lock().unwrap().ready.clone().unwrap_or(ReadyProbe::Ready { connections: 4, connector_id: None })
    }
    fn origin(&self, service: &str) -> OriginProbe {
        self.0.lock().unwrap().origins.get(service).cloned().unwrap_or(OriginProbe::Responding)
    }
    fn port_free(&self, port: u16) -> bool {
        !self.0.lock().unwrap().busy_ports.contains(&port)
    }
    fn resolves(&self, _: &str) -> bool {
        !self.0.lock().unwrap().no_dns
    }
    fn tcp_reachable(&self, _: &str, _: u16) -> bool {
        !self.0.lock().unwrap().no_tcp
    }
}

/// The path tests use for a stand in cloudflared binary.
pub fn fake_binary(paths: &Paths) -> PathBuf {
    paths.cache_dir.join("cloudflared-source")
}

pub fn fake_locate(config: &Config, paths: &Paths) -> CloudflaredStatus {
    let path = fake_binary(paths);
    if !path.is_file() {
        return CloudflaredStatus::missing(&config.cloudflared.min_version);
    }
    CloudflaredStatus {
        found: true,
        version: std::fs::read_to_string(&path).ok(),
        meets_minimum: std::fs::read_to_string(&path).is_ok_and(|v| crate::cloudflared::version_at_least(&v, &config.cloudflared.min_version)),
        path: Some(path),
        via_shim: false,
        minimum: config.cloudflared.min_version.clone(),
    }
}
