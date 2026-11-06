//! All tunnelkeeper logic. Nothing in this crate prints, prompts or serves
//! HTTP. Every operation returns typed data that a front end renders.

// Errors carry the details a person needs, and they are rare, so their size
// does not matter here.
#![allow(clippy::result_large_err)]

pub mod cloudflare;
pub mod cloudflared;
pub mod config;
pub mod doctor;
pub mod error;
pub mod health;
pub mod journal;
pub mod paths;
pub mod plan;
pub mod privileged;
pub mod secret;
pub mod secrets;
pub mod service;
pub mod setup;
pub mod testing;
pub mod util;

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

use cloudflare::{Client, Tunnel, Zone};
use cloudflared::{CloudflaredStatus, ReleaseInfo};
use config::Config;
use error::{Error, Result};
use health::{Probes, RealProbes, RemoteStatus, RouteStatus, TunnelStatus, classify};
use journal::Journal;
use paths::Paths;
use privileged::{Elevator, PlatformElevator, PrivilegedOp};
use secret::{Secret, scrub};
use secrets::{API_TOKEN_KEY, SecretStore};
use service::{ServiceInfo, ServiceManager, ServiceState, service_name};
use setup::{PermissionReport, check_permissions};

/// Everything the core needs from the outside world. Tests swap these out.
pub struct Deps {
    pub paths: Paths,
    pub secrets: Box<dyn SecretStore>,
    pub services: Box<dyn ServiceManager>,
    pub elevator: Box<dyn Elevator>,
    pub probes: Box<dyn Probes>,
    pub locate: fn(&Config, &Paths) -> CloudflaredStatus,
    pub api_base: String,
    pub release_base: String,
    /// The value of CLOUDFLARE_API_TOKEN, which beats the stored token.
    pub env_token: Option<Secret>,
    pub verify_timeout: Duration,
    pub poll_interval: Duration,
    pub delete_attempts: u32,
    pub delete_retry_delay: Duration,
    pub crash_sample: Duration,
}

pub struct Keeper {
    pub(crate) d: Deps,
    pub(crate) config: Config,
}

/// Only loopback addresses may replace the API address. A stray variable
/// must never be able to send the token to another host.
fn loopback_override(var: &str) -> Option<String> {
    let v = std::env::var(var).ok()?;
    (v.starts_with("http://127.0.0.1:") || v.starts_with("http://localhost:")).then_some(v)
}

/// cloudflared writes JSON to its log directory. This keeps what a person
/// needs and leaves any other line as it is.
pub fn format_log_line(line: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return line.to_string();
    };
    let text = |k: &str| v.get(k).and_then(|x| x.as_str());
    let (Some(time), Some(level), Some(message)) = (text("time"), text("level"), text("message")) else {
        return line.to_string();
    };
    let mut out = format!("{time} {} {message}", level.to_ascii_uppercase());
    if let Some(e) = text("error") {
        out.push_str(": ");
        out.push_str(e);
    }
    out
}

/// Terminal pastes often bring a stray space or line break. Those are removed.
/// Anything else that cannot be in a token is refused without echoing it.
pub fn clean_token(token: &Secret) -> Result<Secret> {
    let trimmed = token.expose().trim();
    if trimmed.is_empty() {
        return Err(Error::Invalid("the token is empty. Nothing was pasted, so try again".into()));
    }
    if !trimmed.chars().all(|c| c.is_ascii_graphic()) {
        return Err(Error::Invalid("the token contains spaces or characters a token cannot have. Copy it again and paste it".into()));
    }
    Ok(Secret::new(trimmed))
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct AuthReport {
    pub token_status: String,
    pub stored_in: Option<String>,
    pub permissions: Option<PermissionReport>,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct TunnelRow {
    pub name: String,
    pub id: String,
    pub status: Option<String>,
    pub config_src: Option<String>,
    pub created_at: Option<String>,
    pub managed_here: bool,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RouteRow {
    pub tunnel: String,
    pub hostname: String,
    pub service: String,
}

impl Keeper {
    pub fn open(d: Deps) -> Result<Self> {
        let config = Config::load(&d.paths.config_file())?;
        Ok(Keeper { d, config })
    }

    pub fn production() -> Result<Self> {
        let paths = Paths::detect()?;
        Self::open(Deps {
            secrets: secrets::platform_store(&paths),
            services: service::platform_manager(),
            elevator: Box::new(PlatformElevator { paths: paths.clone() }),
            probes: Box::new(RealProbes),
            locate: cloudflared::locate,
            api_base: loopback_override("TUNNELKEEPER_API_BASE").unwrap_or_else(|| cloudflare::API_BASE.to_string()),
            release_base: loopback_override("TUNNELKEEPER_RELEASE_BASE").unwrap_or_else(|| cloudflared::RELEASE_BASE.to_string()),
            env_token: std::env::var("CLOUDFLARE_API_TOKEN").ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).map(Secret::new),
            verify_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(1),
            delete_attempts: 8,
            delete_retry_delay: Duration::from_secs(30),
            crash_sample: doctor::DEFAULT_CRASH_SAMPLE,
            paths,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn paths(&self) -> &Paths {
        &self.d.paths
    }

    pub(crate) fn save_config(&self) -> Result<()> {
        self.config.save(&self.d.paths.config_file())
    }

    /// Whether an API token is available, without revealing it.
    pub fn has_token(&self) -> bool {
        self.token().is_ok()
    }

    fn token(&self) -> Result<Secret> {
        if let Some(t) = &self.d.env_token {
            return Ok(t.clone());
        }
        self.d
            .secrets
            .get(API_TOKEN_KEY)?
            .ok_or_else(|| Error::Auth("no API token. Run: tunnelkeeper auth login, or set CLOUDFLARE_API_TOKEN".into()))
    }

    pub(crate) fn client(&self) -> Result<Client> {
        Ok(Client::new(&self.d.api_base, self.token()?))
    }

    // Authentication

    fn zone_named(&self, client: &Client, name: &str) -> Result<Zone> {
        client.zone_by_name(name)?.ok_or_else(|| Error::NotFound(format!("zone {name} is not visible to this token")))
    }

    fn permission_report(&self, client: &Client, zone: Option<&str>) -> Result<(String, Option<PermissionReport>)> {
        let z = zone.map(|n| self.zone_named(client, n)).transpose()?;
        let account = z.as_ref().map(|z| z.account.id.clone()).or_else(|| self.config.tunnels.first().map(|t| t.account_id.clone()));
        let token_status = client.verify_token(account.as_deref())?;
        let permissions = match &account {
            Some(a) => Some(PermissionReport {
                token_status: token_status.clone(),
                checks: check_permissions(client, a, z.as_ref())?,
            }),
            None => None,
        };
        Ok((token_status, permissions))
    }

    /// Verifies a token and only stores it if it is active.
    pub fn auth_login(&self, token: Secret, zone: Option<&str>) -> Result<AuthReport> {
        let token = clean_token(&token)?;
        let client = Client::new(&self.d.api_base, token.clone());
        let (token_status, permissions) = self.permission_report(&client, zone).map_err(|e| match e {
            Error::Api { code: Some(6003), .. } => {
                Error::Auth("Cloudflare says this is not a valid token. Check you copied the whole token, then paste it again".into())
            }
            other => other,
        })?;
        if token_status != "active" {
            return Err(Error::Auth(format!("the token is {token_status}, so it was not stored")));
        }
        self.d.secrets.set(API_TOKEN_KEY, &token)?;
        Ok(AuthReport { token_status, stored_in: Some(self.d.secrets.backend().to_string()), permissions })
    }

    pub fn auth_check(&self, zone: Option<&str>) -> Result<AuthReport> {
        let client = self.client()?;
        let (token_status, permissions) = self.permission_report(&client, zone)?;
        Ok(AuthReport { token_status, stored_in: None, permissions })
    }

    pub fn auth_logout(&self) -> Result<()> {
        self.d.secrets.delete(API_TOKEN_KEY)
    }

    // cloudflared

    pub fn cloudflared_status(&self) -> CloudflaredStatus {
        (self.d.locate)(&self.config, &self.d.paths)
    }

    pub fn cloudflared_release(&self, version: Option<&str>) -> Result<ReleaseInfo> {
        cloudflared::fetch_release(&self.d.release_base, version, cloudflared::asset_name()?)
    }

    pub fn cloudflared_download(&self, release: &ReleaseInfo) -> Result<PathBuf> {
        cloudflared::download_verified(release, &self.d.paths)
    }

    // Listings

    pub fn tunnel_list(&self, zone: Option<&str>) -> Result<Vec<TunnelRow>> {
        let client = self.client()?;
        let mut accounts: Vec<String> = Vec::new();
        if let Some(name) = zone {
            accounts.push(self.zone_named(&client, name)?.account.id);
        }
        for t in &self.config.tunnels {
            if !accounts.contains(&t.account_id) {
                accounts.push(t.account_id.clone());
            }
        }
        if accounts.is_empty() {
            return Err(Error::Invalid("no account known yet. Pass --zone example.com".into()));
        }
        let mut rows = Vec::new();
        for a in accounts {
            for Tunnel { id, name, status, config_src, created_at, .. } in client.list_tunnels(&a)? {
                let managed_here = self.config.tunnels.iter().any(|t| t.id == id);
                rows.push(TunnelRow { name, id, status, config_src, created_at, managed_here });
            }
        }
        Ok(rows)
    }

    pub fn route_list(&self, tunnel: Option<&str>) -> Result<Vec<RouteRow>> {
        Ok(self
            .config
            .tunnels
            .iter()
            .filter(|t| tunnel.is_none_or(|n| n == t.name))
            .flat_map(|t| {
                t.routes.iter().map(|r| RouteRow { tunnel: t.name.clone(), hostname: r.hostname.clone(), service: r.service.clone() })
            })
            .collect())
    }

    pub fn runs(&self) -> Result<Vec<Journal>> {
        Journal::list(&self.d.paths.journal_dir())
    }

    // Service control

    pub fn service_info(&self, tunnel: Option<&str>) -> Result<ServiceInfo> {
        let t = self.config.resolve_tunnel(tunnel)?;
        self.d.services.query(&service_name(&t.name))
    }

    pub fn service_install(&self, tunnel: Option<&str>) -> Result<()> {
        let t = self.config.resolve_tunnel(tunnel)?;
        let st = self.cloudflared_status();
        let source = st.path.filter(|_| st.found && st.meets_minimum).ok_or_else(|| {
            Error::CloudflaredMissing(format!("a cloudflared of at least {} is needed. Run: tunnelkeeper cloudflared install", st.minimum))
        })?;
        let op = PrivilegedOp::InstallTunnel {
            tunnel: t.name.clone(),
            metrics_port: t.metrics_port,
            source_sha256: util::sha256_file(&source)?,
            source_binary: source,
            token: self.client()?.tunnel_token(&t.account_id, &t.id)?,
        };
        self.d.elevator.run(&op)
    }

    pub fn service_start(&self, tunnel: Option<&str>) -> Result<()> {
        let t = self.config.resolve_tunnel(tunnel)?;
        self.d.elevator.run(&PrivilegedOp::Start { tunnel: t.name.clone() })
    }

    pub fn service_stop(&self, tunnel: Option<&str>) -> Result<()> {
        let t = self.config.resolve_tunnel(tunnel)?;
        self.d.elevator.run(&PrivilegedOp::Stop { tunnel: t.name.clone() })
    }

    /// Removes only the local service. The tunnel and DNS stay on Cloudflare.
    pub fn service_uninstall(&self, tunnel: Option<&str>) -> Result<()> {
        let t = self.config.resolve_tunnel(tunnel)?;
        self.d.elevator.run(&PrivilegedOp::Uninstall { tunnel: t.name.clone() })
    }

    // Health

    pub fn status(&self, tunnel: Option<&str>) -> Result<TunnelStatus> {
        let t = self.config.resolve_tunnel(tunnel)?;
        let service = self.d.services.query(&service_name(&t.name))?;
        let ready = if service.state == ServiceState::Missing {
            health::ReadyProbe::Unreachable
        } else {
            self.d.probes.ready(t.metrics_port)
        };
        let routes: Vec<RouteStatus> = t
            .routes
            .iter()
            .map(|r| RouteStatus { hostname: r.hostname.clone(), service: r.service.clone(), origin: self.d.probes.origin(&r.service) })
            .collect();
        let (remote, remote_error) = match self.remote_status(&t.account_id, &t.id) {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let (state, message) = classify(service.state, &ready, remote.as_ref(), &routes);
        Ok(TunnelStatus { name: t.name.clone(), id: t.id.clone(), state, message, service, ready, remote, remote_error, routes })
    }

    fn remote_status(&self, account_id: &str, tunnel_id: &str) -> Result<RemoteStatus> {
        let client = self.client()?;
        let tunnel = client.get_tunnel(account_id, tunnel_id)?;
        let connectors = client.connectors(account_id, tunnel_id)?.len();
        Ok(RemoteStatus { status: tunnel.status, connectors })
    }

    pub fn status_all(&self) -> Result<Vec<TunnelStatus>> {
        self.config.tunnels.iter().map(|t| self.status(Some(&t.name))).collect()
    }

    // Logs

    fn known_secrets(&self) -> Vec<Secret> {
        self.token().ok().into_iter().collect()
    }

    fn scrub_lines(&self, text: &str) -> Vec<String> {
        let secrets = self.known_secrets();
        let known: Vec<&str> = secrets.iter().map(Secret::expose).collect();
        text.lines().map(|l| scrub(&format_log_line(l), &known)).collect()
    }

    fn log_file(&self, tunnel: Option<&str>) -> Result<PathBuf> {
        let t = self.config.resolve_tunnel(tunnel)?;
        Ok(self.d.paths.log_dir(&t.name).join("cloudflared.log"))
    }

    /// The last lines of the service log, with secrets scrubbed.
    pub fn logs_tail(&self, tunnel: Option<&str>, lines: usize) -> Result<Vec<String>> {
        let path = self.log_file(tunnel)?;
        let text = match std::fs::read(&path) {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(Error::io(format!("read {}", path.display()), e)),
        };
        let all = self.scrub_lines(&text);
        Ok(all[all.len().saturating_sub(lines)..].to_vec())
    }

    /// New lines since `offset`, for `logs --follow`. A shrunken file means
    /// the log rotated, so reading starts over.
    pub fn logs_since(&self, tunnel: Option<&str>, offset: u64) -> Result<(Vec<String>, u64)> {
        let path = self.log_file(tunnel)?;
        let mut f = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((vec![], 0)),
            Err(e) => return Err(Error::io(format!("open {}", path.display()), e)),
        };
        let len = f.metadata().map_err(|e| Error::io("read log size", e))?.len();
        let start = if len < offset { 0 } else { offset };
        f.seek(SeekFrom::Start(start)).map_err(|e| Error::io("seek log", e))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| Error::io("read log", e))?;
        Ok((self.scrub_lines(&String::from_utf8_lossy(&buf)), start + buf.len() as u64))
    }
}
