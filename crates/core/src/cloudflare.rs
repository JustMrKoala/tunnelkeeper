//! Cloudflare API client. Routes verified against the API reference on
//! 2026-11-05. Lookups always filter again client side, so a query filter the
//! server ignores can never cause a wrong match.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::secret::Secret;
use crate::util::{parse_http_date, random_hex, random_uuid};

pub const API_BASE: &str = "https://api.cloudflare.com/client/v4";
const PAGE_SIZE: u32 = 100;
const MAX_ATTEMPTS: u32 = 4;
const MAX_WAIT_SECS: u64 = 30;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub config_src: Option<String>,
    #[serde(default)]
    pub deleted_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AccountRef {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub account: AccountRef,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    #[serde(default)]
    pub proxied: Option<bool>,
    #[serde(default)]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Connector {
    pub id: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub conns: Vec<Value>,
}

/// The tunnel configuration as JSON, so fields we do not model survive the
/// read, modify, write cycle.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelConfigDoc {
    pub config: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Probe {
    Allowed,
    Denied,
    /// The answer proved nothing either way.
    Unknown(String),
}

pub struct Client {
    base: String,
    token: Secret,
    agent: ureq::Agent,
}

fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(crate) fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
        .user_agent(concat!("tunnelkeeper/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

struct Reply {
    status: u16,
    json: Value,
    date: Option<String>,
}

impl Client {
    pub fn new(base: &str, token: Secret) -> Self {
        Client { base: base.trim_end_matches('/').to_string(), token, agent: agent(Duration::from_secs(30)) }
    }

    fn send(&self, method: &str, url: &str, body: Option<&Value>) -> Result<ureq::http::Response<ureq::Body>> {
        let builder = ureq::http::Request::builder()
            .method(method)
            .uri(url)
            .header("Authorization", format!("Bearer {}", self.token.expose()))
            .header("Accept", "application/json");
        let result = match body {
            Some(b) => {
                let req = builder
                    .header("Content-Type", "application/json")
                    .body(b.to_string())
                    .map_err(|e| Error::Network(e.to_string()))?;
                self.agent.run(req)
            }
            None => {
                let req = builder.body(()).map_err(|e| Error::Network(e.to_string()))?;
                self.agent.run(req)
            }
        };
        result.map_err(|e| Error::Network(format!("{method} {}: {e}", route_of(url))))
    }

    /// One logical call. Retries 429 always, and 5xx or network errors only
    /// for GET, because repeating a write could duplicate it.
    fn exchange(&self, method: &str, path: &str, query: &[(&str, String)], body: Option<&Value>) -> Result<Reply> {
        let mut url = format!("{}{}", self.base, path);
        for (i, (k, v)) in query.iter().enumerate() {
            url.push(if i == 0 { '?' } else { '&' });
            url.push_str(k);
            url.push('=');
            url.push_str(&encode(v));
        }
        let mut attempt = 0;
        loop {
            attempt += 1;
            let last = attempt >= MAX_ATTEMPTS;
            let mut resp = match self.send(method, &url, body) {
                Ok(r) => r,
                Err(_) if method == "GET" && !last => {
                    std::thread::sleep(backoff(attempt));
                    continue;
                }
                Err(e) => return Err(e),
            };
            let status = resp.status().as_u16();
            if status == 429 && !last {
                let wait = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map(|s| Duration::from_secs(s.min(MAX_WAIT_SECS)))
                    .unwrap_or_else(|| backoff(attempt));
                std::thread::sleep(wait);
                continue;
            }
            if status >= 500 && method == "GET" && !last {
                std::thread::sleep(backoff(attempt));
                continue;
            }
            let date = resp.headers().get("date").and_then(|v| v.to_str().ok()).map(str::to_string);
            let text = resp
                .body_mut()
                .read_to_string()
                .map_err(|e| Error::Network(format!("{method} {path}: reading reply: {e}")))?;
            let json = serde_json::from_str(&text).unwrap_or(Value::Null);
            return Ok(Reply { status, json, date });
        }
    }

    fn call(&self, method: &str, path: &str, query: &[(&str, String)], body: Option<&Value>) -> Result<Value> {
        let reply = self.exchange(method, path, query, body)?;
        let success = reply.json.get("success").and_then(Value::as_bool).unwrap_or(false);
        if reply.status >= 400 || !success {
            let first = reply.json.get("errors").and_then(|e| e.get(0));
            return Err(Error::Api {
                status: reply.status,
                code: first.and_then(|e| e.get("code")).and_then(Value::as_i64),
                message: first
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("no error message in reply")
                    .to_string(),
                route: format!("{method} {path}"),
            });
        }
        Ok(reply.json)
    }

    fn result<T: DeserializeOwned>(&self, method: &str, path: &str, query: &[(&str, String)], body: Option<&Value>) -> Result<T> {
        let mut v = self.call(method, path, query, body)?;
        let result = v.get_mut("result").map(Value::take).unwrap_or(Value::Null);
        serde_json::from_value(result).map_err(|e| Error::Network(format!("unexpected reply from {method} {path}: {e}")))
    }

    fn paged<T: DeserializeOwned>(&self, path: &str, query: &[(&str, String)]) -> Result<Vec<T>> {
        let mut out = Vec::new();
        let mut page = 1u32;
        loop {
            let mut q = query.to_vec();
            q.push(("page", page.to_string()));
            q.push(("per_page", PAGE_SIZE.to_string()));
            let mut v = self.call("GET", path, &q, None)?;
            let items: Vec<T> = serde_json::from_value(v.get_mut("result").map(Value::take).unwrap_or(json!([])))
                .map_err(|e| Error::Network(format!("unexpected reply from GET {path}: {e}")))?;
            let n = items.len() as u32;
            out.extend(items);
            if n < PAGE_SIZE {
                return Ok(out);
            }
            page += 1;
        }
    }

    // Token checks

    /// Tries the user token route, then the account token route when an
    /// account is known. Returns the token status, normally `active`.
    pub fn verify_token(&self, account_id: Option<&str>) -> Result<String> {
        #[derive(Deserialize)]
        struct V {
            status: String,
        }
        let user = self.result::<V>("GET", "/user/tokens/verify", &[], None);
        match (user, account_id) {
            (Ok(v), _) => Ok(v.status),
            (Err(Error::Network(m)), _) => Err(Error::Network(m)),
            (Err(_), Some(acct)) => {
                let v: V = self.result("GET", &format!("/accounts/{acct}/tokens/verify"), &[], None)?;
                Ok(v.status)
            }
            (Err(e), None) => Err(e),
        }
    }

    /// Server time from the verify route, for the clock skew check.
    pub fn server_time(&self) -> Result<Option<i64>> {
        let reply = self.exchange("GET", "/user/tokens/verify", &[], None)?;
        Ok(reply.date.as_deref().and_then(parse_http_date))
    }

    /// A write permission test that cannot change anything, because the target
    /// does not exist. 404 means the token got past the permission check.
    fn write_probe(&self, method: &str, path: &str, body: &Value) -> Result<Probe> {
        let reply = self.exchange(method, path, &[], Some(body))?;
        Ok(match reply.status {
            404 => Probe::Allowed,
            401 | 403 => Probe::Denied,
            s => Probe::Unknown(format!("HTTP {s}")),
        })
    }

    pub fn probe_dns_write(&self, zone_id: &str) -> Result<Probe> {
        let path = format!("/zones/{zone_id}/dns_records/{}", random_hex(16));
        self.write_probe("PATCH", &path, &json!({"comment": "tunnelkeeper permission probe"}))
    }

    pub fn probe_tunnel_write(&self, account_id: &str) -> Result<Probe> {
        let path = format!("/accounts/{account_id}/cfd_tunnel/{}/configurations", random_uuid());
        self.write_probe("PUT", &path, &json!({"config": {"ingress": [{"service": "http_status:404"}]}}))
    }

    // Zones

    pub fn zone_by_name(&self, name: &str) -> Result<Option<Zone>> {
        let zones: Vec<Zone> = self.result("GET", "/zones", &[("name", name.to_string())], None)?;
        Ok(zones.into_iter().find(|z| z.name.eq_ignore_ascii_case(name)))
    }

    /// Finds the zone that holds a hostname, trying the longest suffix first.
    pub fn zone_for_hostname(&self, hostname: &str) -> Result<Zone> {
        let labels: Vec<&str> = hostname.split('.').collect();
        for start in 0..labels.len().saturating_sub(1) {
            if let Some(z) = self.zone_by_name(&labels[start..].join("."))? {
                return Ok(z);
            }
        }
        Err(Error::NotFound(format!(
            "no Cloudflare zone found for {hostname}. Check the domain is on this account and the token has Zone Read on it"
        )))
    }

    // Tunnels

    pub fn list_tunnels(&self, account_id: &str) -> Result<Vec<Tunnel>> {
        let path = format!("/accounts/{account_id}/cfd_tunnel");
        let all: Vec<Tunnel> = self.paged(&path, &[("is_deleted", "false".to_string())])?;
        Ok(all.into_iter().filter(|t| t.deleted_at.is_none()).collect())
    }

    pub fn tunnels_named(&self, account_id: &str, name: &str) -> Result<Vec<Tunnel>> {
        let path = format!("/accounts/{account_id}/cfd_tunnel");
        let found: Vec<Tunnel> = self.paged(&path, &[("name", name.to_string()), ("is_deleted", "false".to_string())])?;
        Ok(found.into_iter().filter(|t| t.name == name && t.deleted_at.is_none()).collect())
    }

    pub fn get_tunnel(&self, account_id: &str, tunnel_id: &str) -> Result<Tunnel> {
        self.result("GET", &format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}"), &[], None)
    }

    pub fn create_tunnel(&self, account_id: &str, name: &str) -> Result<Tunnel> {
        let body = json!({"name": name, "config_src": "cloudflare"});
        self.result("POST", &format!("/accounts/{account_id}/cfd_tunnel"), &[], Some(&body))
    }

    pub fn delete_tunnel(&self, account_id: &str, tunnel_id: &str) -> Result<()> {
        self.call("DELETE", &format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}"), &[], None).map(|_| ())
    }

    /// Always fetched from this route. The create reply is not relied on,
    /// because the guide and the API reference disagree about it.
    pub fn tunnel_token(&self, account_id: &str, tunnel_id: &str) -> Result<Secret> {
        let t: String = self.result("GET", &format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token"), &[], None)?;
        Ok(Secret::new(t))
    }

    pub fn connectors(&self, account_id: &str, tunnel_id: &str) -> Result<Vec<Connector>> {
        self.result("GET", &format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections"), &[], None)
    }

    pub fn remove_connectors(&self, account_id: &str, tunnel_id: &str) -> Result<()> {
        self.call("DELETE", &format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections"), &[], None).map(|_| ())
    }

    pub fn get_config(&self, account_id: &str, tunnel_id: &str) -> Result<TunnelConfigDoc> {
        let v: Value = self.result("GET", &format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"), &[], None)?;
        let config = v.get("config").cloned().filter(|c| !c.is_null()).unwrap_or_else(|| json!({}));
        Ok(TunnelConfigDoc { config })
    }

    pub fn put_config(&self, account_id: &str, tunnel_id: &str, doc: &TunnelConfigDoc) -> Result<()> {
        let body = json!({"config": doc.config});
        self.call("PUT", &format!("/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations"), &[], Some(&body)).map(|_| ())
    }

    // DNS

    pub fn dns_records_named(&self, zone_id: &str, name: &str) -> Result<Vec<DnsRecord>> {
        let path = format!("/zones/{zone_id}/dns_records");
        let found: Vec<DnsRecord> = self.paged(&path, &[("name.exact", name.to_string())])?;
        Ok(found.into_iter().filter(|r| r.name.eq_ignore_ascii_case(name)).collect())
    }

    pub fn create_tunnel_cname(&self, zone_id: &str, name: &str, target: &str, comment: &str) -> Result<DnsRecord> {
        let body = json!({"type": "CNAME", "name": name, "content": target, "proxied": true, "ttl": 1, "comment": comment});
        self.result("POST", &format!("/zones/{zone_id}/dns_records"), &[], Some(&body))
    }

    /// Recreates a record that rollback has to restore.
    pub fn restore_record(&self, zone_id: &str, r: &DnsRecord) -> Result<DnsRecord> {
        let body = json!({
            "type": r.record_type, "name": r.name, "content": r.content,
            "proxied": r.proxied, "ttl": r.ttl.unwrap_or(1), "comment": r.comment,
        });
        self.result("POST", &format!("/zones/{zone_id}/dns_records"), &[], Some(&body))
    }

    pub fn delete_dns_record(&self, zone_id: &str, record_id: &str) -> Result<()> {
        self.call("DELETE", &format!("/zones/{zone_id}/dns_records/{record_id}"), &[], None).map(|_| ())
    }
}

fn route_of(url: &str) -> String {
    url.split('?').next().unwrap_or(url).to_string()
}

fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(250 * (1u64 << attempt.min(5)))
}

// Ingress rule editing. Pure functions, so they are tested without a server.

pub fn ingress_rules(doc: &TunnelConfigDoc) -> Vec<Value> {
    doc.config.get("ingress").and_then(Value::as_array).cloned().unwrap_or_default()
}

pub fn ingress_service(doc: &TunnelConfigDoc, hostname: &str) -> Option<String> {
    ingress_rules(doc)
        .iter()
        .find(|r| r.get("hostname").and_then(Value::as_str) == Some(hostname) && r.get("path").is_none())
        .and_then(|r| r.get("service").and_then(Value::as_str))
        .map(str::to_string)
}

fn set_rules(doc: &mut TunnelConfigDoc, mut rules: Vec<Value>) {
    let is_catch_all = |r: &Value| r.get("hostname").is_none();
    let catch_all = rules.iter().position(is_catch_all).map(|i| rules.remove(i));
    rules.retain(|r| !is_catch_all(r));
    rules.push(catch_all.unwrap_or_else(|| json!({"service": "http_status:404"})));
    if !doc.config.is_object() {
        doc.config = json!({});
    }
    doc.config["ingress"] = Value::Array(rules);
}

/// Adds or updates a rule. Other rules are kept, the catch all stays last.
pub fn ingress_upsert(doc: &mut TunnelConfigDoc, hostname: &str, service: &str) {
    let mut rules = ingress_rules(doc);
    let existing = rules
        .iter_mut()
        .find(|r| r.get("hostname").and_then(Value::as_str) == Some(hostname) && r.get("path").is_none());
    match existing {
        Some(r) => r["service"] = json!(service),
        None => rules.push(json!({"hostname": hostname, "service": service, "originRequest": {}})),
    }
    set_rules(doc, rules);
}

pub fn ingress_remove(doc: &mut TunnelConfigDoc, hostname: &str) {
    let mut rules = ingress_rules(doc);
    rules.retain(|r| !(r.get("hostname").and_then(Value::as_str) == Some(hostname) && r.get("path").is_none()));
    set_rules(doc, rules);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(v: Value) -> TunnelConfigDoc {
        TunnelConfigDoc { config: v }
    }

    #[test]
    fn upsert_adds_before_catch_all() {
        let mut d = doc(json!({"ingress": [{"hostname": "a.x.com", "service": "http://localhost:1"}, {"service": "http_status:503"}]}));
        ingress_upsert(&mut d, "b.x.com", "http://localhost:2");
        let rules = ingress_rules(&d);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[1]["hostname"], "b.x.com");
        assert_eq!(rules[2]["service"], "http_status:503");
    }

    #[test]
    fn upsert_creates_catch_all_on_empty_config() {
        let mut d = doc(json!({}));
        ingress_upsert(&mut d, "a.x.com", "http://localhost:1");
        let rules = ingress_rules(&d);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1]["service"], "http_status:404");
    }

    #[test]
    fn upsert_is_idempotent_and_keeps_unknown_fields() {
        let mut d = doc(json!({
            "warp-routing": {"enabled": true},
            "ingress": [
                {"hostname": "a.x.com", "service": "http://localhost:1", "originRequest": {"noTLSVerify": true}},
                {"service": "http_status:404"}
            ]
        }));
        let before = d.clone();
        ingress_upsert(&mut d, "a.x.com", "http://localhost:1");
        assert_eq!(d, before);
    }

    #[test]
    fn path_rules_are_not_ours_to_touch() {
        let mut d = doc(json!({"ingress": [
            {"hostname": "a.x.com", "path": "/api", "service": "http://localhost:9"},
            {"service": "http_status:404"}
        ]}));
        ingress_remove(&mut d, "a.x.com");
        assert_eq!(ingress_rules(&d).len(), 2);
    }

    #[test]
    fn remove_keeps_other_rules() {
        let mut d = doc(json!({"ingress": [
            {"hostname": "a.x.com", "service": "http://localhost:1"},
            {"hostname": "b.x.com", "service": "http://localhost:2"},
            {"service": "http_status:404"}
        ]}));
        ingress_remove(&mut d, "a.x.com");
        let rules = ingress_rules(&d);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["hostname"], "b.x.com");
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(encode("a b&c"), "a%20b%26c");
    }
}
