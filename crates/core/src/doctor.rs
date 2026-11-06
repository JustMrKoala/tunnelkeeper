//! `doctor`: finds common problems and says exactly how to fix them.

use std::time::Duration;

use serde::Serialize;

use crate::Keeper;
use crate::cloudflare::{Client, Probe, ingress_rules, ingress_service};
use crate::config::TunnelConfig;
use crate::error::Error;
use crate::health::{OriginProbe, ReadyProbe};
use crate::service::{ServiceState, service_name};
use crate::setup::{check_permissions, tunnel_target};
use crate::util::now_unix;

const MAX_CLOCK_SKEW_SECS: i64 = 300;
const EDGE_HOST: &str = "region1.v2.argotunnel.com";
const EDGE_PORT: u16 = 7844;
const LOG_LINES_CHECKED: usize = 200;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Ok,
    Info,
    Warning,
    Error,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

fn ok(id: &str, message: impl Into<String>) -> Finding {
    Finding { id: id.into(), severity: Severity::Ok, message: message.into(), fix: None }
}

fn problem(id: &str, severity: Severity, message: impl Into<String>, fix: impl Into<String>) -> Finding {
    Finding { id: id.into(), severity, message: message.into(), fix: Some(fix.into()) }
}

impl Keeper {
    /// Runs every check. A failing check never stops the ones after it.
    pub fn doctor(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        self.doctor_cloudflared(&mut out);
        self.doctor_network(&mut out);
        let client = self.doctor_token(&mut out);
        for t in &self.config.tunnels {
            self.doctor_tunnel(t, client.as_ref(), &mut out);
        }
        out
    }

    fn doctor_cloudflared(&self, out: &mut Vec<Finding>) {
        let st = (self.d.locate)(&self.config, &self.d.paths);
        if !st.found {
            out.push(problem("cloudflared.missing", Severity::Error, "cloudflared was not found", "Run: tunnelkeeper cloudflared install"));
        } else if !st.meets_minimum {
            out.push(problem(
                "cloudflared.old",
                Severity::Error,
                format!("cloudflared {} is older than the required {}", st.version.unwrap_or_default(), st.minimum),
                "Run: tunnelkeeper cloudflared install",
            ));
        } else {
            out.push(ok("cloudflared.version", format!("cloudflared {} found", st.version.unwrap_or_default())));
        }
        if st.via_shim {
            out.push(Finding {
                id: "cloudflared.shim".into(),
                severity: Severity::Info,
                message: "cloudflared on PATH is a launcher in a user folder. Services use a protected copy instead, so this is fine".into(),
                fix: None,
            });
        }
    }

    fn doctor_network(&self, out: &mut Vec<Finding>) {
        if !self.d.probes.resolves(EDGE_HOST) {
            out.push(problem(
                "network.dns",
                Severity::Error,
                format!("{EDGE_HOST} does not resolve"),
                "Check this machine's DNS settings and internet connection",
            ));
        } else if !self.d.probes.tcp_reachable(EDGE_HOST, EDGE_PORT) {
            out.push(problem(
                "network.port",
                Severity::Warning,
                format!("TCP port {EDGE_PORT} to {EDGE_HOST} is blocked"),
                format!("Allow outbound port {EDGE_PORT} on TCP and UDP in your firewall"),
            ));
        } else {
            out.push(ok("network.edge", format!("{EDGE_HOST} is reachable on TCP port {EDGE_PORT}. UDP, used by QUIC, cannot be checked this way")));
        }
    }

    fn doctor_token(&self, out: &mut Vec<Finding>) -> Option<Client> {
        let client = match self.client() {
            Ok(c) => c,
            Err(_) => {
                out.push(problem("token.missing", Severity::Error, "no API token is stored", "Run: tunnelkeeper auth login"));
                return None;
            }
        };
        let account = self.config.tunnels.first().map(|t| t.account_id.as_str());
        match client.verify_token(account) {
            Ok(s) if s == "active" => out.push(ok("token.active", "API token is active")),
            Ok(s) => {
                out.push(problem("token.inactive", Severity::Error, format!("API token is {s}"), "Create a new token, then run: tunnelkeeper auth login"));
                return None;
            }
            Err(Error::Network(m)) => {
                out.push(problem("token.unreachable", Severity::Warning, format!("cannot reach the Cloudflare API: {m}"), "Check the internet connection, then rerun doctor"));
                return None;
            }
            Err(e) => {
                out.push(problem("token.invalid", Severity::Error, format!("API token failed to verify: {e}"), "Create a new token, then run: tunnelkeeper auth login"));
                return None;
            }
        }
        if let Ok(Some(server)) = client.server_time() {
            let skew = (server - now_unix()).abs();
            if skew > MAX_CLOCK_SKEW_SECS {
                out.push(problem("clock.skew", Severity::Warning, format!("this machine's clock is {skew} seconds off"), "Sync the system clock"));
            } else {
                out.push(ok("clock", "system clock is in sync"));
            }
        }
        Some(client)
    }

    fn doctor_tunnel(&self, t: &TunnelConfig, client: Option<&Client>, out: &mut Vec<Finding>) {
        let id = |suffix: &str| format!("{}.{suffix}", t.name);
        let name = service_name(&t.name);
        let info = match self.d.services.query(&name) {
            Ok(i) => i,
            Err(e) => {
                out.push(problem(&id("service.query"), Severity::Error, format!("cannot query service {name}: {e}"), "Check the system service manager"));
                return;
            }
        };

        let token_path = self.d.paths.tunnel_token(&t.name);
        match info.state {
            ServiceState::Missing => out.push(problem(
                &id("service.missing"),
                Severity::Error,
                format!("service {name} is not installed"),
                format!("Run: tunnelkeeper service install --tunnel {}", t.name),
            )),
            ServiceState::Running | ServiceState::Starting => {
                let ready = self.d.probes.ready(t.metrics_port);
                if matches!(ready, ReadyProbe::Ready { .. }) {
                    out.push(ok(&id("tunnel"), format!("tunnel {} is connected", t.name)));
                } else {
                    self.doctor_crash_loop(t, &name, info.pid, out);
                }
            }
            _ => {
                let mut message = format!("service {name} is not running");
                if let Some(code) = info.exit_code.filter(|c| *c != 0) {
                    message = format!("{message}, its last exit code was {code}, which suggests a crash");
                }
                out.push(problem(&id("service.stopped"), Severity::Error, message, format!("Run: tunnelkeeper service start --tunnel {}", t.name)));
                if !self.d.probes.port_free(t.metrics_port) {
                    out.push(problem(
                        &id("metrics.port"),
                        Severity::Warning,
                        format!("metrics port {} is in use by another program", t.metrics_port),
                        "Stop that program, or change metrics_port in the config and reinstall the service",
                    ));
                }
            }
        }

        if info.state != ServiceState::Missing {
            let managed = self.d.paths.managed_cloudflared();
            let safe = info.command_line.as_deref().is_some_and(|c| c.contains(&managed.display().to_string()));
            if !safe {
                out.push(problem(
                    &id("service.path"),
                    Severity::Error,
                    format!("service {name} does not run the protected copy of cloudflared at {}", managed.display()),
                    format!("Run: tunnelkeeper service install --tunnel {}", t.name),
                ));
            }
            if !token_path.exists() {
                out.push(problem(&id("token.file"), Severity::Error, "the stored tunnel token is missing", format!("Run: tunnelkeeper service install --tunnel {}", t.name)));
            } else if !crate::privileged::is_elevated() && std::fs::File::open(&token_path).is_ok() {
                out.push(problem(
                    &id("token.acl"),
                    Severity::Error,
                    format!("{} can be read by this unprivileged user", token_path.display()),
                    format!("Run: tunnelkeeper service install --tunnel {}", t.name),
                ));
            }
        }

        for r in &t.routes {
            if let OriginProbe::NotResponding(why) = self.d.probes.origin(&r.service) {
                out.push(problem(&id("origin"), Severity::Warning, format!("{}: {why}", r.hostname), format!("Start the app behind {}", r.service)));
            }
        }

        if let Some(c) = client {
            self.doctor_remote(t, c, out);
        }
    }

    /// Sampling the process twice separates a crash loop from a tunnel that
    /// is up but simply cannot connect.
    fn doctor_crash_loop(&self, t: &TunnelConfig, name: &str, first_pid: Option<u32>, out: &mut Vec<Finding>) {
        std::thread::sleep(self.d.crash_sample);
        let later = self.d.services.query(name).ok();
        let restarted = later.as_ref().is_some_and(|i| i.pid != first_pid || i.state != ServiceState::Running);
        // A restart cycle can last a minute, far longer than the sample above,
        // so the log is the better witness.
        let lines = self.logs_tail(Some(&t.name), LOG_LINES_CHECKED).unwrap_or_default();
        let shutdowns: Vec<&String> = lines.iter().filter(|l| l.contains("Initiating shutdown")).collect();
        if restarted || shutdowns.len() >= 2 {
            let reason = shutdowns.last().and_then(|l| l.split("Initiating shutdown: ").nth(1)).unwrap_or("see the logs");
            out.push(problem(
                &format!("{}.service.crashloop", t.name),
                Severity::Error,
                format!("service {name} keeps restarting. cloudflared last gave up with: {reason}"),
                "\"Failed to get tunnel\" or \"Unauthorized\" means a bad tunnel token, so run: tunnelkeeper service install. Otherwise run: tunnelkeeper logs",
            ));
        } else {
            out.push(problem(
                &format!("{}.tunnel.down", t.name),
                Severity::Error,
                format!("service {name} is running, but tunnel {} has no connection to Cloudflare", t.name),
                "Check outbound port 7844, then run: tunnelkeeper logs",
            ));
        }
    }

    fn doctor_remote(&self, t: &TunnelConfig, client: &Client, out: &mut Vec<Finding>) {
        let id = |suffix: &str| format!("{}.{suffix}", t.name);
        let remote = match client.get_tunnel(&t.account_id, &t.id) {
            Ok(r) if r.deleted_at.is_none() => r,
            Ok(_) => {
                out.push(problem(&id("remote.deleted"), Severity::Error, format!("tunnel {} was deleted on Cloudflare", t.name), "Run setup again to recreate it"));
                return;
            }
            Err(e) if e.is_not_found() => {
                out.push(problem(&id("remote.missing"), Severity::Error, format!("tunnel {} no longer exists on Cloudflare", t.name), "Run setup again to recreate it"));
                return;
            }
            Err(e) => {
                out.push(problem(&id("remote.error"), Severity::Warning, format!("cannot read tunnel {}: {e}", t.name), "Check the token permissions"));
                return;
            }
        };
        if remote.config_src.as_deref() != Some("cloudflare") {
            out.push(problem(&id("remote.mode"), Severity::Error, format!("tunnel {} is locally managed, not remotely managed", t.name), "Create a new tunnel with tunnelkeeper"));
        }

        let doc = match client.get_config(&t.account_id, &t.id) {
            Ok(d) => d,
            Err(e) => {
                out.push(problem(&id("remote.config"), Severity::Warning, format!("cannot read ingress rules: {e}"), "Check the token permissions"));
                return;
            }
        };
        for r in &t.routes {
            match ingress_service(&doc, &r.hostname) {
                Some(s) if s == r.service => {}
                Some(s) => out.push(problem(
                    &id("drift.ingress"),
                    Severity::Warning,
                    format!("{} goes to {s} on Cloudflare, but {} locally", r.hostname, r.service),
                    format!("Run: tunnelkeeper route add {} {} to restore it", r.hostname, r.service),
                )),
                None => out.push(problem(
                    &id("drift.ingress"),
                    Severity::Warning,
                    format!("{} is in the local config but has no ingress rule on Cloudflare", r.hostname),
                    format!("Run: tunnelkeeper route add {} {}", r.hostname, r.service),
                )),
            }
            self.doctor_dns(t, client, &r.hostname, &r.zone_id, &r.service, out);
        }
        for rule in ingress_rules(&doc) {
            if let Some(h) = rule.get("hostname").and_then(|h| h.as_str())
                && !t.routes.iter().any(|r| r.hostname == h) {
                    out.push(Finding {
                        id: id("drift.foreign"),
                        severity: Severity::Info,
                        message: format!("{h} is on Cloudflare but not in the local config. tunnelkeeper keeps such rules"),
                        fix: None,
                    });
                }
        }

        let Some(host) = t.routes.first().map(|r| r.hostname.as_str()) else {
            return;
        };
        let Ok(zone) = client.zone_for_hostname(host) else {
            return;
        };
        self.doctor_permissions(t, client, &zone, out);
        for r in &t.routes {
            if r.hostname.matches('.').count() > zone.name.matches('.').count() + 1 {
                out.push(problem(
                    &id("tls.depth"),
                    Severity::Warning,
                    format!("{} is more than one level below {}. Universal SSL does not cover it in a full setup zone", r.hostname, zone.name),
                    "Use a first level hostname, or add Total TLS or a custom certificate",
                ));
            }
        }
    }

    fn doctor_permissions(&self, t: &TunnelConfig, client: &Client, zone: &crate::cloudflare::Zone, out: &mut Vec<Finding>) {
        match check_permissions(client, &t.account_id, Some(zone)) {
            Ok(checks) => {
                for c in checks {
                    match c.result {
                        Probe::Denied => out.push(problem(
                            "token.permission",
                            Severity::Error,
                            format!("API token lacks {}, needed for {}", c.name, c.needed_for),
                            format!("Add {} to the token in the Cloudflare dashboard", c.name),
                        )),
                        Probe::Unknown(why) => out.push(Finding {
                            id: "token.permission.unknown".into(),
                            severity: Severity::Info,
                            message: format!("could not prove {}: {why}", c.name),
                            fix: None,
                        }),
                        Probe::Allowed => {}
                    }
                }
            }
            Err(e) => out.push(problem("token.permission.error", Severity::Warning, format!("permission checks failed: {e}"), "Rerun doctor")),
        }
    }

    fn doctor_dns(&self, t: &TunnelConfig, client: &Client, host: &str, zone_id: &str, service: &str, out: &mut Vec<Finding>) {
        let id = format!("{}.dns", t.name);
        let target = tunnel_target(&t.id);
        match client.dns_records_named(zone_id, host) {
            Ok(records) => match records.iter().find(|r| r.record_type == "CNAME" && r.content.eq_ignore_ascii_case(&target)) {
                Some(r) if r.proxied == Some(false) => out.push(problem(
                    &id,
                    Severity::Error,
                    format!("the DNS record for {host} is not proxied, so traffic cannot reach the tunnel"),
                    "Turn on the proxy for this record in the Cloudflare dashboard",
                )),
                Some(_) => {}
                None => out.push(problem(
                    &id,
                    Severity::Error,
                    format!("{host} has no DNS record pointing at this tunnel"),
                    format!("Run: tunnelkeeper route add {host} {service}"),
                )),
            },
            Err(e) => out.push(problem(&id, Severity::Warning, format!("cannot read DNS for {host}: {e}"), "Check the token permissions")),
        }
    }
}

pub const DEFAULT_CRASH_SAMPLE: Duration = Duration::from_secs(3);
