//! Destructive changes go through a plan. The core only accepts a `Confirmed`
//! value, which can only be built from a `Plan` and the right answer, so
//! neither front end can delete anything without asking first. The plan is
//! rebuilt at apply time, and a changed fingerprint stops everything.

use serde::{Deserialize, Serialize};

use crate::Keeper;
use crate::cloudflare::{Client, DnsRecord, TunnelConfigDoc, ingress_remove, ingress_rules, ingress_upsert};
use crate::config::TunnelConfig;
use crate::error::{Error, Result};
use crate::journal::{EntryState, Journal, Resource, RunStatus};
use crate::privileged::PrivilegedOp;
use crate::service::{ServiceState, service_name};
use crate::setup::{ownership_comment, tunnel_target};
use crate::util::sha256_hex;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PlanKind {
    DeleteTunnel {
        name: String,
        /// Finds a tunnel that is not in the local config.
        zone: Option<String>,
        include_unmanaged_dns: bool,
    },
    RemoveRoute { hostname: String, tunnel: Option<String>, include_unmanaged_dns: bool },
    Rollback { run_id: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum Action {
    UninstallService { tunnel: String },
    RemoveIngress { account_id: String, tunnel_id: String, hostname: String },
    RestoreIngress { account_id: String, tunnel_id: String, hostname: String, service: String },
    DeleteDnsRecord { zone_id: String, record_id: String, hostname: String, content: String },
    RestoreDnsRecord { zone_id: String, record: DnsRecord },
    RemoveConnectors { account_id: String, tunnel_id: String },
    DeleteTunnel { account_id: String, tunnel_id: String, name: String },
    ForgetRoute { tunnel: String, hostname: String },
    ForgetTunnel { name: String },
}

impl Action {
    pub fn describe(&self) -> String {
        match self {
            Action::UninstallService { tunnel } => format!("Stop and remove service {} and its stored tunnel token", service_name(tunnel)),
            Action::RemoveIngress { hostname, .. } => format!("Remove the ingress rule for {hostname}"),
            Action::RestoreIngress { hostname, service, .. } => format!("Restore the ingress rule for {hostname} to {service}"),
            Action::DeleteDnsRecord { hostname, content, .. } => format!("DELETE DNS record {hostname} pointing at {content}"),
            Action::RestoreDnsRecord { record, .. } => format!("Restore DNS record {} {} {}", record.record_type, record.name, record.content),
            Action::RemoveConnectors { tunnel_id, .. } => format!("Remove stale connectors from tunnel {tunnel_id}"),
            Action::DeleteTunnel { name, tunnel_id, .. } => format!("DELETE tunnel {name} ({tunnel_id})"),
            Action::ForgetRoute { hostname, .. } => format!("Remove {hostname} from the local config"),
            Action::ForgetTunnel { name } => format!("Remove tunnel {name} from the local config"),
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Plan {
    pub kind: PlanKind,
    pub summary: String,
    /// What the user has to type to confirm.
    pub confirm_phrase: String,
    pub actions: Vec<Action>,
    /// `actions` in words, in the same order.
    pub descriptions: Vec<String>,
    /// Things that match but will be left alone, and why.
    pub kept: Vec<String>,
    pub warnings: Vec<String>,
    pub fingerprint: String,
}

impl Plan {
    fn new(kind: PlanKind, summary: String, confirm_phrase: String, actions: Vec<Action>, kept: Vec<String>, warnings: Vec<String>) -> Result<Self> {
        let basis = serde_json::to_vec(&(&kind, &actions, &kept)).map_err(|e| Error::Config(e.to_string()))?;
        let descriptions = actions.iter().map(Action::describe).collect();
        Ok(Plan { kind, summary, confirm_phrase, actions, descriptions, kept, warnings, fingerprint: sha256_hex(&basis) })
    }

    pub fn confirm(self, answer: &str) -> Result<Confirmed> {
        if answer.trim() == self.confirm_phrase {
            Ok(Confirmed { plan: self })
        } else {
            Err(Error::Invalid(format!("confirmation did not match {:?}, nothing was changed", self.confirm_phrase)))
        }
    }
}

/// Proof that a person saw this plan. The private field means this type can
/// only come from `Plan::confirm`.
pub struct Confirmed {
    plan: Plan,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ApplyReport {
    pub done: Vec<String>,
    pub failed: Option<String>,
    pub not_attempted: Vec<String>,
}

impl ApplyReport {
    pub fn ok(&self) -> bool {
        self.failed.is_none()
    }
}

/// Sorts DNS records for a hostname into ours and not ours.
fn sort_dns(
    client: &Client,
    zone_id: &str,
    host: &str,
    tunnel_id: &str,
    include_unmanaged: bool,
    actions: &mut Vec<Action>,
    kept: &mut Vec<String>,
) -> Result<()> {
    let target = tunnel_target(tunnel_id);
    let marker = ownership_comment(tunnel_id);
    for r in client.dns_records_named(zone_id, host)? {
        let points_here = r.record_type == "CNAME" && r.content.eq_ignore_ascii_case(&target);
        let ours = points_here && r.comment.as_deref() == Some(marker.as_str());
        if ours || (points_here && include_unmanaged) {
            actions.push(Action::DeleteDnsRecord {
                zone_id: zone_id.to_string(),
                record_id: r.id,
                hostname: host.to_string(),
                content: r.content,
            });
        } else if points_here {
            kept.push(format!("DNS record {host} points at this tunnel, but tunnelkeeper did not create it"));
        } else {
            kept.push(format!("DNS record {host} {} {} does not point at this tunnel", r.record_type, r.content));
        }
    }
    Ok(())
}

impl Keeper {
    pub fn plan(&self, kind: PlanKind) -> Result<Plan> {
        match &kind {
            PlanKind::DeleteTunnel { name, zone, include_unmanaged_dns } => {
                self.plan_delete_tunnel(kind.clone(), name, zone.as_deref(), *include_unmanaged_dns)
            }
            PlanKind::RemoveRoute { hostname, tunnel, include_unmanaged_dns } => {
                self.plan_remove_route(kind.clone(), hostname, tunnel.as_deref(), *include_unmanaged_dns)
            }
            PlanKind::Rollback { run_id } => self.plan_rollback(kind.clone(), run_id),
        }
    }

    fn tunnel_for_delete(&self, client: &Client, name: &str, zone: Option<&str>) -> Result<(TunnelConfig, bool)> {
        if let Some(t) = self.config.tunnel(name) {
            return Ok((t.clone(), true));
        }
        let zone = zone.ok_or_else(|| Error::NotFound(format!("tunnel {name} is not in the config. Pass --zone to look it up on Cloudflare")))?;
        let z = client.zone_by_name(zone)?.ok_or_else(|| Error::NotFound(format!("zone {zone}")))?;
        let mut found = client.tunnels_named(&z.account.id, name)?;
        match found.len() {
            1 => {
                let t = found.remove(0);
                Ok((TunnelConfig { name: name.into(), id: t.id, account_id: z.account.id, metrics_port: 0, routes: vec![] }, false))
            }
            0 => Err(Error::NotFound(format!("tunnel {name}"))),
            n => Err(Error::Conflict(format!("{n} tunnels are named {name}, delete them from the Cloudflare dashboard"))),
        }
    }

    fn plan_delete_tunnel(&self, kind: PlanKind, name: &str, zone: Option<&str>, include_unmanaged: bool) -> Result<Plan> {
        let client = self.client()?;
        let (t, in_config) = self.tunnel_for_delete(&client, name, zone)?;
        let mut actions = Vec::new();
        let mut kept = Vec::new();
        if self.d.services.query(&service_name(name))?.state != ServiceState::Missing || self.d.paths.tunnel_token(name).exists() {
            actions.push(Action::UninstallService { tunnel: name.to_string() });
        }
        let doc = client.get_config(&t.account_id, &t.id)?;
        let mut hosts: Vec<(String, Option<String>)> = t.routes.iter().map(|r| (r.hostname.clone(), Some(r.zone_id.clone()))).collect();
        for rule in ingress_rules(&doc) {
            if let Some(h) = rule.get("hostname").and_then(|h| h.as_str())
                && !hosts.iter().any(|(x, _)| x == h) {
                    hosts.push((h.to_string(), None));
                }
        }
        for (host, zone_id) in hosts {
            let zone_id = match zone_id {
                Some(z) => z,
                None => client.zone_for_hostname(&host)?.id,
            };
            sort_dns(&client, &zone_id, &host, &t.id, include_unmanaged, &mut actions, &mut kept)?;
        }
        actions.push(Action::RemoveConnectors { account_id: t.account_id.clone(), tunnel_id: t.id.clone() });
        actions.push(Action::DeleteTunnel { account_id: t.account_id.clone(), tunnel_id: t.id.clone(), name: name.to_string() });
        if in_config {
            actions.push(Action::ForgetTunnel { name: name.to_string() });
        }
        Plan::new(kind, format!("Permanently delete tunnel {name}"), name.to_string(), actions, kept, vec![])
    }

    fn plan_remove_route(&self, kind: PlanKind, hostname: &str, tunnel: Option<&str>, include_unmanaged: bool) -> Result<Plan> {
        let host = crate::config::normalize_hostname(hostname)?;
        let t = match tunnel {
            Some(_) => self.config.resolve_tunnel(tunnel)?.clone(),
            None => self
                .config
                .tunnels
                .iter()
                .find(|t| t.routes.iter().any(|r| r.hostname == host))
                .ok_or_else(|| Error::NotFound(format!("route {host} is not in the config")))?
                .clone(),
        };
        let client = self.client()?;
        let zone_id = match t.routes.iter().find(|r| r.hostname == host) {
            Some(r) => r.zone_id.clone(),
            None => client.zone_for_hostname(&host)?.id,
        };
        let mut actions = vec![Action::RemoveIngress { account_id: t.account_id.clone(), tunnel_id: t.id.clone(), hostname: host.clone() }];
        let mut kept = Vec::new();
        sort_dns(&client, &zone_id, &host, &t.id, include_unmanaged, &mut actions, &mut kept)?;
        actions.push(Action::ForgetRoute { tunnel: t.name.clone(), hostname: host.clone() });
        Plan::new(kind, format!("Remove route {host} from tunnel {}", t.name), host, actions, kept, vec![])
    }

    fn plan_rollback(&self, kind: PlanKind, run_id: &str) -> Result<Plan> {
        let j = Journal::load(&self.d.paths.journal_dir(), run_id)?;
        if j.status == RunStatus::RolledBack {
            return Err(Error::Conflict(format!("run {run_id} was already rolled back")));
        }
        let mut actions = Vec::new();
        let mut warnings = Vec::new();
        for e in j.entries.iter().rev() {
            let done = e.state == EntryState::Done;
            match &e.resource {
                // Uninstall is safe when the service is absent, so it also
                // covers a failed install that left half a service behind.
                Resource::Service { tunnel } => actions.push(Action::UninstallService { tunnel: tunnel.clone() }),
                Resource::DnsRecord { zone_id, record_id: Some(id), hostname } if done => {
                    actions.push(Action::DeleteDnsRecord {
                        zone_id: zone_id.clone(),
                        record_id: id.clone(),
                        hostname: hostname.clone(),
                        content: "this run's tunnel".into(),
                    });
                    actions.push(Action::ForgetRoute { tunnel: j.request.tunnel.clone(), hostname: hostname.clone() });
                }
                Resource::DnsRemoved { zone_id, record } if done => {
                    actions.push(Action::RestoreDnsRecord { zone_id: zone_id.clone(), record: record.clone() });
                }
                Resource::Ingress { account_id, tunnel_id, hostname, previous } if done => match previous {
                    Some(service) => actions.push(Action::RestoreIngress {
                        account_id: account_id.clone(),
                        tunnel_id: tunnel_id.clone(),
                        hostname: hostname.clone(),
                        service: service.clone(),
                    }),
                    None => actions.push(Action::RemoveIngress {
                        account_id: account_id.clone(),
                        tunnel_id: tunnel_id.clone(),
                        hostname: hostname.clone(),
                    }),
                },
                Resource::Tunnel { account_id, tunnel_id: Some(id), name } if done => {
                    actions.push(Action::RemoveConnectors { account_id: account_id.clone(), tunnel_id: id.clone() });
                    actions.push(Action::DeleteTunnel { account_id: account_id.clone(), tunnel_id: id.clone(), name: name.clone() });
                    actions.push(Action::ForgetTunnel { name: name.clone() });
                }
                other => warnings.push(format!(
                    "{} may exist, because its outcome is unknown. Resume the run to find out, or check the Cloudflare dashboard",
                    other.describe()
                )),
            }
        }
        Plan::new(kind, format!("Undo what run {run_id} created"), run_id.to_string(), actions, vec![], warnings)
    }

    /// Runs a confirmed plan. Actions treat "already gone" as success, so
    /// running it again after a partial failure is safe.
    pub fn apply(&mut self, confirmed: Confirmed) -> Result<ApplyReport> {
        let plan = confirmed.plan;
        let current = self.plan(plan.kind.clone())?;
        if current.fingerprint != plan.fingerprint {
            return Err(Error::StalePlan("real state changed since this plan was shown. Review the new plan".into()));
        }
        let mut report = ApplyReport { done: vec![], failed: None, not_attempted: vec![] };
        let mut actions = plan.actions.iter();
        for action in actions.by_ref() {
            match self.apply_action(action) {
                Ok(()) => report.done.push(action.describe()),
                Err(e) => {
                    report.failed = Some(format!("{}: {e}", action.describe()));
                    break;
                }
            }
        }
        report.not_attempted = actions.map(Action::describe).collect();
        if report.ok()
            && let PlanKind::Rollback { run_id } = &plan.kind {
                let mut j = Journal::load(&self.d.paths.journal_dir(), run_id)?;
                j.status = RunStatus::RolledBack;
                j.save()?;
            }
        Ok(report)
    }

    fn apply_action(&mut self, action: &Action) -> Result<()> {
        let tolerate_missing = |r: Result<()>| match r {
            Err(e) if e.is_not_found() => Ok(()),
            other => other,
        };
        match action {
            Action::UninstallService { tunnel } => self.d.elevator.run(&PrivilegedOp::Uninstall { tunnel: tunnel.clone() }),
            Action::RemoveIngress { account_id, tunnel_id, hostname } => {
                self.edit_ingress(account_id, tunnel_id, |doc| ingress_remove(doc, hostname))
            }
            Action::RestoreIngress { account_id, tunnel_id, hostname, service } => {
                self.edit_ingress(account_id, tunnel_id, |doc| ingress_upsert(doc, hostname, service))
            }
            Action::DeleteDnsRecord { zone_id, record_id, .. } => tolerate_missing(self.client()?.delete_dns_record(zone_id, record_id)),
            Action::RestoreDnsRecord { zone_id, record } => self.client()?.restore_record(zone_id, record).map(|_| ()),
            Action::RemoveConnectors { account_id, tunnel_id } => tolerate_missing(self.client()?.remove_connectors(account_id, tunnel_id)),
            Action::DeleteTunnel { account_id, tunnel_id, .. } => self.delete_tunnel_with_retry(account_id, tunnel_id),
            Action::ForgetRoute { tunnel, hostname } => {
                if let Some(t) = self.config.tunnel_mut(tunnel) {
                    t.routes.retain(|r| r.hostname != *hostname);
                }
                self.save_config()
            }
            Action::ForgetTunnel { name } => {
                self.config.tunnels.retain(|t| t.name != *name);
                self.save_config()
            }
        }
    }

    fn edit_ingress(&self, account_id: &str, tunnel_id: &str, edit: impl FnOnce(&mut TunnelConfigDoc)) -> Result<()> {
        let client = self.client()?;
        let mut doc = match client.get_config(account_id, tunnel_id) {
            Ok(d) => d,
            Err(e) if e.is_not_found() => return Ok(()),
            Err(e) => return Err(e),
        };
        edit(&mut doc);
        client.put_config(account_id, tunnel_id, &doc)
    }

    /// Cloudflare tracks connections for several minutes after they close,
    /// and a tunnel with connections cannot be deleted.
    fn delete_tunnel_with_retry(&self, account_id: &str, tunnel_id: &str) -> Result<()> {
        let client = self.client()?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            match client.delete_tunnel(account_id, tunnel_id) {
                Ok(()) => return Ok(()),
                Err(e) if e.is_not_found() => return Ok(()),
                Err(Error::Api { status: 400 | 409, .. }) if attempt < self.d.delete_attempts => {
                    std::thread::sleep(self.d.delete_retry_delay);
                    let _ = client.remove_connectors(account_id, tunnel_id);
                }
                Err(e) => return Err(e),
            }
        }
    }
}
