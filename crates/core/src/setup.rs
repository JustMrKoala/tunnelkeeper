//! The reconciler. Every step reads real state first and only acts when it
//! differs, which is what makes setup safe to run twice.

use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::Keeper;
use crate::cloudflare::{Client, DnsRecord, Probe, Tunnel, Zone, ingress_service, ingress_upsert};
use crate::config::{RouteConfig, TunnelConfig, normalize_hostname, normalize_service, validate_tunnel_name};
use crate::error::{Error, Result};
use crate::health::{OriginProbe, ReadyProbe, TunnelStatus};
use crate::journal::{Entry, Journal, Resource, RunStatus};
use crate::privileged::PrivilegedOp;
use crate::service::{ServiceState, service_name};
use crate::util::sha256_file;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RouteRequest {
    pub hostname: String,
    pub service: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SetupRequest {
    pub tunnel: String,
    pub routes: Vec<RouteRequest>,
    pub install_service: bool,
    /// Tells us the account when there are no routes to learn it from.
    #[serde(default)]
    pub zone: Option<String>,
    /// Hostnames whose conflicting DNS records the user approved replacing.
    #[serde(default)]
    pub replace_dns: Vec<String>,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Unchanged,
    Changed,
    Warning,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct StepReport {
    pub status: StepStatus,
    pub detail: String,
}

impl StepReport {
    fn unchanged(detail: impl Into<String>) -> Self {
        StepReport { status: StepStatus::Unchanged, detail: detail.into() }
    }
    fn changed(detail: impl Into<String>) -> Self {
        StepReport { status: StepStatus::Changed, detail: detail.into() }
    }
    fn warning(detail: impl Into<String>) -> Self {
        StepReport { status: StepStatus::Warning, detail: detail.into() }
    }
}

#[derive(Serialize, Debug)]
pub struct SetupReport {
    /// None when nothing changed, because no run record is kept then.
    pub run_id: Option<String>,
    pub steps: Vec<StepReport>,
    pub changed: bool,
    pub health: Option<TunnelStatus>,
}

/// What a failed run leaves behind, so the user can decide what to do.
#[derive(Debug)]
pub struct SetupFailure {
    pub run_id: Option<String>,
    pub step: String,
    pub error: Error,
    pub created: Vec<Entry>,
    /// The outcome of these is not known. They may or may not exist.
    pub unknown: Vec<Entry>,
}

/// The failure as plain data, so both front ends show the same thing.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct FailureView {
    pub run_id: Option<String>,
    pub step: String,
    pub error: String,
    pub dns_conflict: Option<DnsConflictView>,
    pub created: Vec<String>,
    pub unknown: Vec<String>,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct DnsConflictView {
    pub hostname: String,
    pub records: Vec<DnsRecord>,
}

impl SetupFailure {
    pub fn view(&self) -> FailureView {
        let describe = |entries: &[Entry]| entries.iter().map(|e| e.resource.describe()).collect();
        let dns_conflict = match &self.error {
            Error::DnsConflict { hostname, records } => Some(DnsConflictView { hostname: hostname.clone(), records: records.clone() }),
            _ => None,
        };
        FailureView {
            run_id: self.run_id.clone(),
            step: self.step.clone(),
            error: self.error.to_string(),
            dns_conflict,
            created: describe(&self.created),
            unknown: describe(&self.unknown),
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct PermissionCheck {
    pub name: String,
    pub needed_for: String,
    pub result: Probe,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct PermissionReport {
    pub token_status: String,
    pub checks: Vec<PermissionCheck>,
}

impl PermissionReport {
    pub fn denied(&self) -> Vec<&PermissionCheck> {
        self.checks.iter().filter(|c| c.result == Probe::Denied).collect()
    }
}

fn read_probe<T>(r: Result<T>) -> Result<Probe> {
    match r {
        Ok(_) => Ok(Probe::Allowed),
        Err(Error::Api { status: 401 | 403, .. }) => Ok(Probe::Denied),
        Err(Error::Network(m)) => Err(Error::Network(m)),
        Err(e) => Ok(Probe::Unknown(e.to_string())),
    }
}

fn check(name: &str, needed_for: &str, result: Probe) -> PermissionCheck {
    PermissionCheck { name: name.into(), needed_for: needed_for.into(), result }
}

/// Proves each permission with calls that change nothing.
pub fn check_permissions(client: &Client, account_id: &str, zone: Option<&Zone>) -> Result<Vec<PermissionCheck>> {
    let mut checks = vec![
        check("Cloudflare Tunnel Read", "listing tunnels", read_probe(client.tunnels_named(account_id, "tunnelkeeper-permission-probe"))?),
        check("Cloudflare Tunnel Edit", "creating tunnels and routes", client.probe_tunnel_write(account_id)?),
    ];
    if let Some(z) = zone {
        checks.push(check("Zone Read", "finding the zone", Probe::Allowed));
        checks.push(check("DNS Read", "reading DNS records", read_probe(client.dns_records_named(&z.id, &format!("tunnelkeeper-probe.{}", z.name)))?));
        checks.push(check("DNS Edit", "creating DNS records", client.probe_dns_write(&z.id)?));
    }
    Ok(checks)
}

/// The fixed comment that marks a DNS record as ours.
pub fn ownership_comment(tunnel_id: &str) -> String {
    format!("tunnelkeeper tunnel={tunnel_id}")
}

pub fn tunnel_target(tunnel_id: &str) -> String {
    format!("{tunnel_id}.cfargotunnel.com")
}

fn zone_error(e: Error) -> Error {
    match e {
        Error::Api { status: 401 | 403, .. } => {
            Error::Permission("the token cannot read zones. It needs Zone Read on the zone".into())
        }
        other => other,
    }
}

impl Keeper {
    pub fn reconcile(
        &mut self,
        request: SetupRequest,
        progress: &mut dyn FnMut(&StepReport),
    ) -> std::result::Result<SetupReport, SetupFailure> {
        let journal = Journal::start(&self.d.paths.journal_dir(), request).map_err(|error| SetupFailure {
            run_id: None,
            step: "start".into(),
            error,
            created: vec![],
            unknown: vec![],
        })?;
        self.drive(journal, progress)
    }

    /// Continues a failed run. The journal stays the same, so a later
    /// rollback still covers everything the earlier attempts created.
    pub fn resume(
        &mut self,
        run_id: &str,
        approved_dns: &[String],
        progress: &mut dyn FnMut(&StepReport),
    ) -> std::result::Result<SetupReport, SetupFailure> {
        let fail = |error| SetupFailure { run_id: Some(run_id.to_string()), step: "resume".into(), error, created: vec![], unknown: vec![] };
        let mut journal = Journal::load(&self.d.paths.journal_dir(), run_id).map_err(fail)?;
        if journal.status == RunStatus::RolledBack {
            return Err(fail(Error::Conflict(format!("run {run_id} was rolled back"))));
        }
        journal.request.replace_dns.extend(approved_dns.iter().cloned());
        journal.status = RunStatus::Running;
        journal.error = None;
        self.drive(journal, progress)
    }

    fn drive(&mut self, mut journal: Journal, progress: &mut dyn FnMut(&StepReport)) -> std::result::Result<SetupReport, SetupFailure> {
        let request = journal.request.clone();
        let mut steps = Vec::new();
        let outcome = {
            let mut emit = |s: StepReport| {
                progress(&s);
                steps.push(s);
            };
            self.run_steps(&request, &mut journal, &mut emit)
        };
        match outcome {
            Ok(health) => {
                journal.status = RunStatus::Complete;
                journal.step = "done".into();
                let changed = steps.iter().any(|s| s.status == StepStatus::Changed);
                let run_id = if journal.entries.is_empty() {
                    journal.remove_file();
                    None
                } else {
                    let _ = journal.save();
                    Some(journal.id.clone())
                };
                Ok(SetupReport { run_id, steps, changed, health })
            }
            Err(error) => {
                journal.status = RunStatus::Failed;
                journal.error = Some(error.to_string());
                let _ = journal.save();
                Err(SetupFailure {
                    run_id: Some(journal.id.clone()),
                    step: journal.step.clone(),
                    error,
                    created: journal.created().into_iter().cloned().collect(),
                    unknown: journal.unknown().into_iter().cloned().collect(),
                })
            }
        }
    }

    fn run_steps(
        &mut self,
        req: &SetupRequest,
        j: &mut Journal,
        emit: &mut dyn FnMut(StepReport),
    ) -> Result<Option<TunnelStatus>> {
        j.step = "validate".into();
        validate_tunnel_name(&req.tunnel)?;
        let mut routes = Vec::new();
        for r in &req.routes {
            routes.push(RouteRequest { hostname: normalize_hostname(&r.hostname)?, service: normalize_service(&r.service)? });
        }

        let mut source = None;
        if req.install_service {
            j.step = "cloudflared".into();
            let st = (self.d.locate)(&self.config, &self.d.paths);
            let Some(path) = st.path.filter(|_| st.found) else {
                return Err(Error::CloudflaredMissing("cloudflared was not found. Run: tunnelkeeper cloudflared install".into()));
            };
            let version = st.version.unwrap_or_default();
            if !st.meets_minimum {
                return Err(Error::CloudflaredMissing(format!(
                    "cloudflared {version} is older than {}, the first version with --token-file. Run: tunnelkeeper cloudflared install",
                    st.minimum
                )));
            }
            emit(StepReport::unchanged(format!("cloudflared {version} found")));
            source = Some(path);
        }

        j.step = "permissions".into();
        let client = self.client()?;
        let known_account = self.config.tunnel(&req.tunnel).map(|t| t.account_id.clone());
        let early = client.verify_token(known_account.as_deref());
        match &early {
            Ok(s) if s != "active" => return Err(Error::Auth(format!("the API token is {s}"))),
            Err(Error::Network(m)) => return Err(Error::Network(m.clone())),
            _ => {}
        }

        let mut zones = Vec::new();
        for r in &routes {
            zones.push(client.zone_for_hostname(&r.hostname).map_err(zone_error)?);
        }
        let hint = match &req.zone {
            Some(name) => Some(
                client
                    .zone_by_name(name)
                    .map_err(zone_error)?
                    .ok_or_else(|| Error::NotFound(format!("zone {name} is not visible to this token")))?,
            ),
            None => None,
        };
        let account_id = known_account
            .or_else(|| zones.first().map(|z| z.account.id.clone()))
            .or_else(|| hint.as_ref().map(|z| z.account.id.clone()))
            .or_else(|| self.config.tunnels.first().map(|t| t.account_id.clone()))
            .ok_or_else(|| Error::Invalid("cannot tell which account to use. Add a route or pass --zone".into()))?;
        if early.is_err() {
            // Account owned tokens only pass the account verify route.
            let status = client.verify_token(Some(&account_id)).map_err(|e| Error::Auth(format!("the API token did not verify: {e}")))?;
            if status != "active" {
                return Err(Error::Auth(format!("the API token is {status}")));
            }
        }
        let mut checks = Vec::new();
        if zones.is_empty() {
            checks.extend(check_permissions(&client, &account_id, hint.as_ref())?);
        }
        let mut seen = Vec::new();
        for z in &zones {
            if !seen.contains(&z.id) {
                seen.push(z.id.clone());
                checks.extend(check_permissions(&client, &account_id, Some(z))?);
            }
        }
        let denied: Vec<String> =
            checks.iter().filter(|c| c.result == Probe::Denied).map(|c| format!("{} (for {})", c.name, c.needed_for)).collect();
        if !denied.is_empty() {
            let mut names = denied;
            names.dedup();
            return Err(Error::Permission(format!("the API token lacks: {}. Nothing was changed", names.join(", "))));
        }
        for c in &checks {
            if let Probe::Unknown(why) = &c.result {
                emit(StepReport::warning(format!("could not prove {}: {why}", c.name)));
            }
        }
        emit(StepReport::unchanged("API token is active and has the required permissions"));

        j.step = "tunnel".into();
        let tunnel = self.ensure_tunnel(&client, &account_id, &req.tunnel, j, emit)?;
        self.ensure_tunnel_config(&req.tunnel, &tunnel.id, &account_id)?;

        for (route, zone) in routes.iter().zip(&zones) {
            j.step = format!("route {}", route.hostname);
            self.ensure_route(&client, &account_id, &req.tunnel, &tunnel.id, route, zone, &req.replace_dns, j, emit)?;
        }

        if !req.install_service {
            return Ok(None);
        }
        j.step = "service".into();
        let source = source.expect("set above when install_service is true");
        self.ensure_service(&client, &account_id, &req.tunnel, &tunnel.id, &source, j, emit)?;

        j.step = "verify".into();
        self.wait_ready(&req.tunnel)?;
        emit(StepReport::unchanged("tunnel is connected to Cloudflare"));
        let health = self.status(Some(&req.tunnel))?;
        for r in &health.routes {
            if let OriginProbe::NotResponding(why) = &r.origin {
                emit(StepReport::warning(format!("{} is set up, but the local app is not responding: {why}", r.hostname)));
            }
        }
        Ok(Some(health))
    }

    fn ensure_tunnel(
        &mut self,
        client: &Client,
        account_id: &str,
        name: &str,
        j: &mut Journal,
        emit: &mut dyn FnMut(StepReport),
    ) -> Result<Tunnel> {
        let is_this = |r: &Resource| matches!(r, Resource::Tunnel { name: n, .. } if n == name);
        if let Some(cfg) = self.config.tunnel(name) {
            match client.get_tunnel(account_id, &cfg.id) {
                Ok(t) if t.deleted_at.is_none() => {
                    emit(StepReport::unchanged(format!("tunnel {name} exists")));
                    return Ok(t);
                }
                Ok(_) => {}
                Err(e) if e.is_not_found() => {}
                Err(e) => return Err(e),
            }
        }
        let mut found = client.tunnels_named(account_id, name)?;
        if found.len() > 1 {
            let ids: Vec<String> = found.iter().map(|t| t.id.clone()).collect();
            return Err(Error::Conflict(format!("{} tunnels are named {name}: {}. Delete the extras or choose another name", ids.len(), ids.join(", "))));
        }
        if let Some(t) = found.pop() {
            if t.config_src.as_deref() != Some("cloudflare") {
                return Err(Error::Conflict(format!(
                    "tunnel {name} ({}) is locally managed, so tunnelkeeper cannot configure it. Choose another name",
                    t.id
                )));
            }
            let resource = Resource::Tunnel { account_id: account_id.into(), tunnel_id: Some(t.id.clone()), name: name.into() };
            if j.claim_unknown(is_this, resource)? {
                emit(StepReport::changed(format!("tunnel {name} was created by the earlier attempt")));
            } else {
                emit(StepReport::unchanged(format!("adopted existing tunnel {name} ({})", t.id)));
            }
            return Ok(t);
        }
        j.drop_unknown(is_this)?;
        let index = j.intent(Resource::Tunnel { account_id: account_id.into(), tunnel_id: None, name: name.into() })?;
        match client.create_tunnel(account_id, name) {
            Ok(t) => {
                j.done(index, Resource::Tunnel { account_id: account_id.into(), tunnel_id: Some(t.id.clone()), name: name.into() })?;
                emit(StepReport::changed(format!("created tunnel {name} ({})", t.id)));
                Ok(t)
            }
            Err(e) => {
                j.failed(index, &e)?;
                Err(e)
            }
        }
    }

    fn ensure_tunnel_config(&mut self, name: &str, id: &str, account_id: &str) -> Result<()> {
        match self.config.tunnel_mut(name) {
            Some(t) if t.id == id => return Ok(()),
            Some(t) => {
                t.id = id.to_string();
                t.account_id = account_id.to_string();
                t.routes.clear();
            }
            None => {
                let probes = &self.d.probes;
                let metrics_port = self.config.next_metrics_port(|p| probes.port_free(p))?;
                self.config.tunnels.push(TunnelConfig {
                    name: name.to_string(),
                    id: id.to_string(),
                    account_id: account_id.to_string(),
                    metrics_port,
                    routes: vec![],
                });
            }
        }
        self.save_config()
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_route(
        &mut self,
        client: &Client,
        account_id: &str,
        tunnel: &str,
        tunnel_id: &str,
        route: &RouteRequest,
        zone: &Zone,
        replace_dns: &[String],
        j: &mut Journal,
        emit: &mut dyn FnMut(StepReport),
    ) -> Result<()> {
        let host = &route.hostname;

        // Ingress first. The whole config is replaced on write, so we edit
        // what is there now and keep every rule that is not ours.
        let is_ingress = |r: &Resource| matches!(r, Resource::Ingress { hostname, .. } if hostname == host);
        let mut doc = client.get_config(account_id, tunnel_id)?;
        let current = ingress_service(&doc, host);
        if current.as_deref() == Some(route.service.as_str()) {
            let resource = Resource::Ingress { account_id: account_id.into(), tunnel_id: tunnel_id.into(), hostname: host.clone(), previous: None };
            if j.claim_unknown(is_ingress, resource)? {
                emit(StepReport::changed(format!("ingress rule for {host} was applied by the earlier attempt")));
            } else {
                emit(StepReport::unchanged(format!("ingress rule {host} to {} exists", route.service)));
            }
        } else {
            j.drop_unknown(is_ingress)?;
            ingress_upsert(&mut doc, host, &route.service);
            let resource = Resource::Ingress {
                account_id: account_id.into(),
                tunnel_id: tunnel_id.into(),
                hostname: host.clone(),
                previous: current.clone(),
            };
            let index = j.intent(resource.clone())?;
            if let Err(e) = client.put_config(account_id, tunnel_id, &doc) {
                j.failed(index, &e)?;
                return Err(e);
            }
            let back = client.get_config(account_id, tunnel_id)?;
            if ingress_service(&back, host).as_deref() != Some(route.service.as_str()) {
                let e = Error::Conflict(format!("the ingress rule for {host} did not persist. Another writer may have changed the tunnel"));
                j.failed(index, &e)?;
                return Err(e);
            }
            j.done(index, resource)?;
            emit(StepReport::changed(format!("ingress rule {host} to {}", route.service)));
        }

        let record_id = self.ensure_dns(client, tunnel_id, host, zone, replace_dns, j, emit)?;

        let cfg = self.config.tunnel_mut(tunnel).expect("tunnel was just added to the config");
        let entry = RouteConfig {
            hostname: host.clone(),
            service: route.service.clone(),
            zone_id: zone.id.clone(),
            dns_record_id: Some(record_id),
        };
        match cfg.routes.iter_mut().find(|r| r.hostname == *host) {
            Some(r) => *r = entry,
            None => cfg.routes.push(entry),
        }
        self.save_config()?;
        if host.matches('.').count() > zone.name.matches('.').count() + 1 {
            emit(StepReport::warning(format!(
                "{host} is more than one level below {}. Universal SSL does not cover it in a full setup zone",
                zone.name
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_dns(
        &mut self,
        client: &Client,
        tunnel_id: &str,
        host: &str,
        zone: &Zone,
        replace_dns: &[String],
        j: &mut Journal,
        emit: &mut dyn FnMut(StepReport),
    ) -> Result<String> {
        let target = tunnel_target(tunnel_id);
        let is_dns = |r: &Resource| matches!(r, Resource::DnsRecord { hostname, .. } if hostname == host);
        let existing = client.dns_records_named(&zone.id, host)?;
        if let Some(r) = existing.iter().find(|r| r.record_type == "CNAME" && r.content.eq_ignore_ascii_case(&target)) {
            let resource = Resource::DnsRecord { zone_id: zone.id.clone(), record_id: Some(r.id.clone()), hostname: host.to_string() };
            if j.claim_unknown(is_dns, resource)? {
                emit(StepReport::changed(format!("DNS record for {host} was created by the earlier attempt")));
            } else {
                emit(StepReport::unchanged(format!("DNS record for {host} is correct")));
            }
            if r.proxied == Some(false) {
                emit(StepReport::warning(format!("the DNS record for {host} is not proxied, so traffic will not reach the tunnel")));
            }
            return Ok(r.id.clone());
        }
        j.drop_unknown(is_dns)?;
        if !existing.is_empty() {
            if !replace_dns.iter().any(|h| h == host) {
                return Err(Error::DnsConflict { hostname: host.to_string(), records: existing });
            }
            for r in &existing {
                self.remove_for_replacement(client, zone, r, j, emit)?;
            }
        }
        let index = j.intent(Resource::DnsRecord { zone_id: zone.id.clone(), record_id: None, hostname: host.to_string() })?;
        match client.create_tunnel_cname(&zone.id, host, &target, &ownership_comment(tunnel_id)) {
            Ok(r) => {
                j.done(index, Resource::DnsRecord { zone_id: zone.id.clone(), record_id: Some(r.id.clone()), hostname: host.to_string() })?;
                emit(StepReport::changed(format!("created DNS record for {host}")));
                Ok(r.id)
            }
            Err(e) => {
                j.failed(index, &e)?;
                Err(e)
            }
        }
    }

    fn remove_for_replacement(
        &mut self,
        client: &Client,
        zone: &Zone,
        record: &DnsRecord,
        j: &mut Journal,
        emit: &mut dyn FnMut(StepReport),
    ) -> Result<()> {
        let resource = Resource::DnsRemoved { zone_id: zone.id.clone(), record: record.clone() };
        let index = j.intent(resource.clone())?;
        match client.delete_dns_record(&zone.id, &record.id) {
            Ok(()) => {
                j.done(index, resource)?;
                emit(StepReport::changed(format!("removed {} record {} {} as approved", record.record_type, record.name, record.content)));
                Ok(())
            }
            Err(e) => {
                j.failed(index, &e)?;
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn ensure_service(
        &mut self,
        client: &Client,
        account_id: &str,
        tunnel: &str,
        tunnel_id: &str,
        source: &std::path::Path,
        j: &mut Journal,
        emit: &mut dyn FnMut(StepReport),
    ) -> Result<()> {
        let name = service_name(tunnel);
        let port = self.config.tunnel(tunnel).expect("tunnel is in config").metrics_port;
        let info = self.d.services.query(&name)?;
        let is_service = |r: &Resource| matches!(r, Resource::Service { tunnel: t } if t == tunnel);
        let matches_config = info.command_line.as_deref().is_some_and(|c| c.contains(&format!("127.0.0.1:{port}")));
        let token_present = self.d.paths.tunnel_token(tunnel).exists();

        if info.state == ServiceState::Missing || !matches_config || !token_present {
            let resource = Resource::Service { tunnel: tunnel.to_string() };
            let index = if info.state == ServiceState::Missing {
                j.drop_unknown(is_service)?;
                Some(j.intent(resource.clone())?)
            } else {
                None
            };
            let outcome = (|| {
                let op = PrivilegedOp::InstallTunnel {
                    tunnel: tunnel.to_string(),
                    metrics_port: port,
                    source_binary: source.to_path_buf(),
                    source_sha256: sha256_file(source)?,
                    token: client.tunnel_token(account_id, tunnel_id)?,
                };
                self.d.elevator.run(&op)
            })();
            match (outcome, index) {
                (Ok(()), Some(i)) => j.done(i, resource)?,
                (Ok(()), None) => {}
                (Err(e), Some(i)) => {
                    j.failed(i, &e)?;
                    return Err(e);
                }
                (Err(e), None) => return Err(e),
            }
            emit(StepReport::changed(format!("installed and started service {name}")));
            return Ok(());
        }
        j.claim_unknown(is_service, Resource::Service { tunnel: tunnel.to_string() })?;
        if matches!(info.state, ServiceState::Running | ServiceState::Starting) {
            emit(StepReport::unchanged(format!("service {name} is running")));
        } else {
            self.d.elevator.run(&PrivilegedOp::Start { tunnel: tunnel.to_string() })?;
            emit(StepReport::changed(format!("started service {name}")));
        }
        Ok(())
    }

    fn wait_ready(&self, tunnel: &str) -> Result<()> {
        let port = self.config.tunnel(tunnel).expect("tunnel is in config").metrics_port;
        let start = Instant::now();
        loop {
            match self.d.probes.ready(port) {
                ReadyProbe::Ready { .. } => return Ok(()),
                other if start.elapsed() >= self.d.verify_timeout => {
                    let detail = if other == ReadyProbe::NotReady { "it has no connection to Cloudflare" } else { "it is not answering" };
                    return Err(Error::Service(format!(
                        "the service started but {detail} after {} seconds. Run: tunnelkeeper doctor",
                        self.d.verify_timeout.as_secs()
                    )));
                }
                _ => std::thread::sleep(self.d.poll_interval),
            }
        }
    }
}
