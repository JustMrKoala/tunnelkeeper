//! A fake of the Cloudflare API, served over real HTTP on 127.0.0.1 so tests
//! exercise the real client. It follows the documented behaviour, and is
//! deliberately strict where real Cloudflare is strict:
//!
//! * permission is checked before existence
//! * tunnels with active connections cannot be deleted
//! * tunnel names may repeat, because uniqueness is not documented
//!
//! Failure injection covers errors, lost replies and rate limits.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Method, Response, Server};

pub const ZONE_READ: &str = "zone_read";
pub const DNS_READ: &str = "dns_read";
pub const DNS_WRITE: &str = "dns_write";
pub const TUNNEL_READ: &str = "tunnel_read";
pub const TUNNEL_WRITE: &str = "tunnel_write";
pub const ALL_PERMS: &[&str] = &[ZONE_READ, DNS_READ, DNS_WRITE, TUNNEL_READ, TUNNEL_WRITE];

pub const ACCOUNT: &str = "0123456789abcdef0123456789abcdef";

/// Marker inside every fake tunnel token, so tests can search output for leaks.
pub const TUNNEL_TOKEN_MARKER: &str = "TOPSECRETTUNNELTOKEN";

struct TokenInfo {
    perms: HashSet<String>,
    status: String,
    account_owned: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Injection {
    /// Fail without applying the change.
    Fail,
    /// Apply the change, then fail, as if the reply was lost.
    LoseReply,
}

#[derive(Default)]
pub struct State {
    tokens: HashMap<String, TokenInfo>,
    zones: Vec<Value>,
    tunnels: Vec<Value>,
    configs: HashMap<String, Value>,
    dns: HashMap<String, Vec<Value>>,
    connected: HashSet<String>,
    sticky_connections: u32,
    next_id: u64,
    mutations_seen: usize,
    inject_at: Option<(usize, Injection)>,
    rate_limit_next: u32,
    server_error_next: u32,
    calls: Vec<String>,
    release: Option<(String, String, Vec<u8>, String)>,
    realistic_tokens: bool,
}

impl State {
    fn new_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }
}

pub struct FakeCloudflare {
    state: Arc<Mutex<State>>,
    server: Arc<Server>,
    port: u16,
    handle: Option<JoinHandle<()>>,
}

impl FakeCloudflare {
    pub fn spawn() -> Self {
        Self::spawn_on(0)
    }

    pub fn spawn_on(port: u16) -> Self {
        let server = Arc::new(Server::http(("127.0.0.1", port)).expect("bind fake API"));
        let port = server.server_addr().to_ip().expect("ip listener").port();
        let state = Arc::new(Mutex::new(State::default()));
        let (s, st) = (server.clone(), state.clone());
        let handle = std::thread::spawn(move || {
            for request in s.incoming_requests() {
                serve(request, &st, port);
            }
        });
        FakeCloudflare { state, server, port, handle: Some(handle) }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/client/v4", self.port)
    }

    pub fn release_base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn add_token(&self, token: &str, perms: &[&str]) {
        self.lock().tokens.insert(
            token.to_string(),
            TokenInfo { perms: perms.iter().map(|p| p.to_string()).collect(), status: "active".into(), account_owned: false },
        );
    }

    /// A token that only passes the account verify route.
    pub fn add_account_token(&self, token: &str, perms: &[&str]) {
        self.add_token(token, perms);
        self.lock().tokens.get_mut(token).unwrap().account_owned = true;
    }

    pub fn set_token_status(&self, token: &str, status: &str) {
        self.lock().tokens.get_mut(token).unwrap().status = status.to_string();
    }

    pub fn add_zone(&self, name: &str) -> String {
        let mut s = self.lock();
        let id = format!("zone{:028x}", s.new_id());
        s.zones.push(json!({"id": id, "name": name, "account": {"id": ACCOUNT, "name": "Test account"}}));
        s.dns.insert(id.clone(), vec![]);
        id
    }

    pub fn add_dns(&self, zone_id: &str, record_type: &str, name: &str, content: &str, comment: Option<&str>) -> String {
        let mut s = self.lock();
        let id = format!("rec{:029x}", s.new_id());
        let rec = json!({"id": id, "type": record_type, "name": name, "content": content, "proxied": true, "ttl": 1, "comment": comment});
        s.dns.get_mut(zone_id).expect("zone").push(rec);
        id
    }

    pub fn add_tunnel(&self, name: &str, config_src: &str) -> String {
        let mut s = self.lock();
        let n = s.new_id();
        let id = format!("00000000-0000-4000-8000-{n:012x}");
        s.tunnels.push(json!({
            "id": id, "name": name, "status": "inactive", "config_src": config_src,
            "created_at": "2026-11-05T00:00:00Z", "deleted_at": null,
        }));
        id
    }

    pub fn set_ingress(&self, tunnel_id: &str, ingress: Value) {
        self.lock().configs.insert(tunnel_id.to_string(), json!({"ingress": ingress}));
    }

    pub fn set_connected(&self, tunnel_id: &str, connected: bool) {
        let mut s = self.lock();
        if connected {
            s.connected.insert(tunnel_id.to_string());
        } else {
            s.connected.remove(tunnel_id);
        }
        let status = if connected { "healthy" } else { "down" };
        if let Some(t) = s.tunnels.iter_mut().find(|t| t["id"] == tunnel_id) {
            t["status"] = json!(status);
        }
    }

    pub fn set_tunnel_status(&self, tunnel_id: &str, status: &str) {
        if let Some(t) = self.lock().tunnels.iter_mut().find(|t| t["id"] == tunnel_id) {
            t["status"] = json!(status);
        }
    }

    /// Deleting the tunnel fails this many times after connectors are gone,
    /// because Cloudflare keeps tracking connections for several minutes.
    pub fn set_sticky_connections(&self, attempts: u32) {
        self.lock().sticky_connections = attempts;
    }

    /// The nth real mutation from now (1 based) fails without being applied.
    pub fn fail_mutation(&self, nth: usize) {
        let mut s = self.lock();
        s.inject_at = Some((s.mutations_seen + nth, Injection::Fail));
    }

    /// The nth real mutation from now is applied, but the reply is an error.
    pub fn lose_reply(&self, nth: usize) {
        let mut s = self.lock();
        s.inject_at = Some((s.mutations_seen + nth, Injection::LoseReply));
    }

    pub fn clear_injection(&self) {
        self.lock().inject_at = None;
    }

    pub fn rate_limit_next(&self, n: u32) {
        self.lock().rate_limit_next = n;
    }

    pub fn server_error_next(&self, n: u32) {
        self.lock().server_error_next = n;
    }

    /// Tunnel tokens in the real format, which cloudflared can parse. Its
    /// credentials are made up, so the real edge will reject them.
    pub fn use_realistic_tokens(&self) {
        self.lock().realistic_tokens = true;
    }

    pub fn set_release(&self, tag: &str, asset: &str, bytes: &[u8], published_sha: Option<&str>) {
        let sha = published_sha.map(str::to_string).unwrap_or_else(|| {
            Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
        });
        self.lock().release = Some((tag.to_string(), asset.to_string(), bytes.to_vec(), sha));
    }

    pub fn tunnels(&self) -> Vec<Value> {
        self.lock().tunnels.iter().filter(|t| t["deleted_at"].is_null()).cloned().collect()
    }

    pub fn ingress(&self, tunnel_id: &str) -> Vec<Value> {
        self.lock().configs.get(tunnel_id).and_then(|c| c["ingress"].as_array().cloned()).unwrap_or_default()
    }

    pub fn dns(&self, zone_id: &str) -> Vec<Value> {
        self.lock().dns.get(zone_id).cloned().unwrap_or_default()
    }

    /// Every request as `METHOD /path`.
    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    pub fn clear_calls(&self) {
        self.lock().calls.clear();
    }

    /// The number of real mutations seen so far.
    pub fn mutation_count(&self) -> usize {
        self.lock().mutations_seen
    }
}

impl Drop for FakeCloudflare {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

struct Reply {
    status: u16,
    body: Value,
    retry_after: bool,
}

fn ok(result: Value) -> Reply {
    Reply { status: 200, body: json!({"success": true, "errors": [], "messages": [], "result": result}), retry_after: false }
}

fn ok_list(items: Vec<Value>, query: &HashMap<String, String>) -> Reply {
    let per_page: usize = query.get("per_page").and_then(|p| p.parse().ok()).unwrap_or(20);
    let page: usize = query.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let total = items.len();
    let slice: Vec<Value> = items.into_iter().skip((page - 1) * per_page).take(per_page).collect();
    let mut r = ok(Value::Array(slice.clone()));
    r.body["result_info"] = json!({"count": slice.len(), "page": page, "per_page": per_page, "total_count": total});
    r
}

fn err(status: u16, code: i64, message: &str) -> Reply {
    Reply {
        status,
        body: json!({"success": false, "errors": [{"code": code, "message": message}], "messages": [], "result": null}),
        retry_after: false,
    }
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn serve(mut request: tiny_http::Request, state: &Arc<Mutex<State>>, port: u16) {
    let method = request.method().clone();
    let url = request.url().to_string();
    let (path, query_text) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let query: HashMap<String, String> = query_text
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), decode(v)))
        .collect();
    let auth = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .map(|h| h.value.as_str().trim_start_matches("Bearer ").to_string());
    let mut text = String::new();
    let _ = request.as_reader().read_to_string(&mut text);
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);

    let mut s = state.lock().unwrap();
    s.calls.push(format!("{method} {path}"));

    if let Some(raw) = serve_release(&mut s, path, port) {
        let _ = request.respond(raw);
        return;
    }

    let segments: Vec<&str> = path.trim_start_matches("/client/v4").split('/').filter(|x| !x.is_empty()).collect();
    let reply = route(&mut s, &method, &segments, &query, &body, auth.as_deref());
    drop(s);
    let mut response = Response::from_string(reply.body.to_string())
        .with_status_code(reply.status)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap());
    if reply.retry_after {
        response.add_header(Header::from_bytes("Retry-After", "0").unwrap());
    }
    let _ = request.respond(response);
}

fn serve_release(s: &mut State, path: &str, port: u16) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    if !(path.starts_with("/repos/") || path.starts_with("/download/")) {
        return None;
    }
    let Some((tag, asset, bytes, sha)) = s.release.clone() else {
        return Some(Response::from_data(b"{}".to_vec()).with_status_code(404));
    };
    if path.starts_with("/download/") {
        return Some(Response::from_data(bytes));
    }
    let release = json!({
        "tag_name": tag,
        "body": format!("### SHA256 Checksums:\n```\n{asset}: {sha}\nother-file: 00\n```\n"),
        "assets": [{"name": asset, "browser_download_url": format!("http://127.0.0.1:{port}/download/{asset}")}],
    });
    Some(Response::from_data(release.to_string().into_bytes()))
}

fn route(s: &mut State, method: &Method, seg: &[&str], q: &HashMap<String, String>, body: &Value, auth: Option<&str>) -> Reply {
    if s.rate_limit_next > 0 {
        s.rate_limit_next -= 1;
        let mut r = err(429, 10000, "rate limited");
        r.retry_after = true;
        return r;
    }
    if s.server_error_next > 0 {
        s.server_error_next -= 1;
        return err(500, 10001, "internal error");
    }
    let Some(token) = auth.filter(|t| s.tokens.contains_key(*t)).map(str::to_string) else {
        return err(401, 10000, "Authentication error");
    };
    let info = &s.tokens[&token];
    let status = info.status.clone();
    let account_owned = info.account_owned;
    let perms = info.perms.clone();
    let can = |p: &str| perms.contains(p);
    let denied = || err(403, 10000, "Authentication error");

    match (method, seg) {
        (Method::Get, ["user", "tokens", "verify"]) => {
            if account_owned {
                return err(401, 1000, "Invalid API Token");
            }
            ok(json!({"id": "tok", "status": status}))
        }
        (Method::Get, ["accounts", _, "tokens", "verify"]) => ok(json!({"id": "tok", "status": status})),

        (Method::Get, ["zones"]) => {
            if !can(ZONE_READ) {
                return denied();
            }
            let items = s.zones.iter().filter(|z| q.get("name").is_none_or(|n| z["name"] == n.as_str())).cloned().collect();
            ok_list(items, q)
        }

        (Method::Get, ["zones", zone, "dns_records"]) => {
            if !(can(DNS_READ) || can(DNS_WRITE)) {
                return denied();
            }
            let Some(records) = s.dns.get(*zone) else { return err(404, 7003, "zone not found") };
            let items = records
                .iter()
                .filter(|r| q.get("name.exact").is_none_or(|n| r["name"] == n.as_str()))
                .cloned()
                .collect();
            ok_list(items, q)
        }
        (Method::Post, ["zones", zone, "dns_records"]) => {
            if !can(DNS_WRITE) {
                return denied();
            }
            if !s.dns.contains_key(*zone) {
                return err(404, 7003, "zone not found");
            }
            let id = format!("rec{:029x}", s.new_id());
            let mut rec = body.clone();
            rec["id"] = json!(id);
            let same_name = s.dns[*zone].iter().any(|r| r["name"] == rec["name"] && (r["type"] == "CNAME" || rec["type"] == "CNAME"));
            if same_name {
                return err(400, 81053, "A CNAME record with that host already exists");
            }
            mutate(s, |s| {
                s.dns.get_mut(*zone).unwrap().push(rec.clone());
                ok(rec.clone())
            })
        }
        (Method::Patch, ["zones", zone, "dns_records", id]) => {
            if !can(DNS_WRITE) {
                return denied();
            }
            let found = s.dns.get(*zone).is_some_and(|r| r.iter().any(|x| x["id"] == *id));
            if !found {
                return err(404, 81044, "Record does not exist.");
            }
            err(400, 9999, "the fake does not implement patching real records")
        }
        (Method::Delete, ["zones", zone, "dns_records", id]) => {
            if !can(DNS_WRITE) {
                return denied();
            }
            let found = s.dns.get(*zone).is_some_and(|r| r.iter().any(|x| x["id"] == *id));
            if !found {
                return err(404, 81044, "Record does not exist.");
            }
            mutate(s, |s| {
                s.dns.get_mut(*zone).unwrap().retain(|r| r["id"] != *id);
                ok(json!({"id": id}))
            })
        }

        (Method::Get, ["accounts", _, "cfd_tunnel"]) => {
            if !can(TUNNEL_READ) && !can(TUNNEL_WRITE) {
                return denied();
            }
            let hide_deleted = q.get("is_deleted").is_some_and(|v| v == "false");
            let items = s
                .tunnels
                .iter()
                .filter(|t| q.get("name").is_none_or(|n| t["name"] == n.as_str()))
                .filter(|t| !hide_deleted || t["deleted_at"].is_null())
                .cloned()
                .collect();
            ok_list(items, q)
        }
        (Method::Post, ["accounts", _, "cfd_tunnel"]) => {
            if !can(TUNNEL_WRITE) {
                return denied();
            }
            let n = s.new_id();
            let id = format!("00000000-0000-4000-8000-{n:012x}");
            let tunnel = json!({
                "id": id, "name": body["name"], "status": "inactive", "config_src": body["config_src"],
                "created_at": "2026-11-05T00:00:00Z", "deleted_at": null,
            });
            mutate(s, |s| {
                s.tunnels.push(tunnel.clone());
                ok(tunnel.clone())
            })
        }
        (Method::Get, ["accounts", _, "cfd_tunnel", id]) => {
            if !can(TUNNEL_READ) && !can(TUNNEL_WRITE) {
                return denied();
            }
            match s.tunnels.iter().find(|t| t["id"] == *id) {
                Some(t) => ok(t.clone()),
                None => err(404, 1002, "tunnel not found"),
            }
        }
        (Method::Delete, ["accounts", _, "cfd_tunnel", id]) => {
            if !can(TUNNEL_WRITE) {
                return denied();
            }
            if !s.tunnels.iter().any(|t| t["id"] == *id && t["deleted_at"].is_null()) {
                return err(404, 1002, "tunnel not found");
            }
            if s.connected.contains(*id) {
                return err(400, 1022, "tunnel has active connections");
            }
            if s.sticky_connections > 0 {
                s.sticky_connections -= 1;
                return err(400, 1022, "tunnel has active connections");
            }
            mutate(s, |s| {
                let t = s.tunnels.iter_mut().find(|t| t["id"] == *id).unwrap();
                t["deleted_at"] = json!("2026-11-05T00:00:00Z");
                ok(t.clone())
            })
        }
        (Method::Get, ["accounts", _, "cfd_tunnel", id, "token"]) => {
            if !can(TUNNEL_READ) && !can(TUNNEL_WRITE) {
                return denied();
            }
            if !s.tunnels.iter().any(|t| t["id"] == *id) {
                return err(404, 1002, "tunnel not found");
            }
            if s.realistic_tokens {
                let secret = base64(&[7u8; 32]);
                return ok(json!(base64(json!({"a": ACCOUNT, "t": id, "s": secret}).to_string().as_bytes())));
            }
            ok(json!(format!("eyJ{TUNNEL_TOKEN_MARKER}{id}")))
        }
        (Method::Get, ["accounts", _, "cfd_tunnel", id, "connections"]) => {
            if !can(TUNNEL_READ) && !can(TUNNEL_WRITE) {
                return denied();
            }
            if s.connected.contains(*id) {
                ok(json!([{"id": "11111111-1111-4111-8111-111111111111", "version": "2026.10.7", "conns": [{"colo_name": "ams01"}]}]))
            } else {
                ok(json!([]))
            }
        }
        (Method::Delete, ["accounts", _, "cfd_tunnel", id, "connections"]) => {
            if !can(TUNNEL_WRITE) {
                return denied();
            }
            if !s.tunnels.iter().any(|t| t["id"] == *id) {
                return err(404, 1002, "tunnel not found");
            }
            mutate(s, |s| {
                s.connected.remove(*id);
                ok(Value::Null)
            })
        }
        (Method::Get, ["accounts", _, "cfd_tunnel", id, "configurations"]) => {
            if !can(TUNNEL_READ) && !can(TUNNEL_WRITE) {
                return denied();
            }
            if !s.tunnels.iter().any(|t| t["id"] == *id) {
                return err(404, 1002, "tunnel not found");
            }
            let config = s.configs.get(*id).cloned().unwrap_or(Value::Null);
            ok(json!({"tunnel_id": id, "version": 1, "source": "cloudflare", "config": config}))
        }
        (Method::Put, ["accounts", _, "cfd_tunnel", id, "configurations"]) => {
            if !can(TUNNEL_WRITE) {
                return denied();
            }
            if !s.tunnels.iter().any(|t| t["id"] == *id) {
                return err(404, 1002, "tunnel not found");
            }
            let rules = body["config"]["ingress"].as_array().cloned().unwrap_or_default();
            if rules.last().is_none_or(|r| r.get("hostname").is_some()) {
                return err(400, 1056, "ingress must end with a catch all rule");
            }
            let config = body["config"].clone();
            mutate(s, |s| {
                s.configs.insert(id.to_string(), config.clone());
                ok(json!({"tunnel_id": id, "config": config}))
            })
        }
        _ => err(404, 7000, "No route for that URI"),
    }
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Runs a real mutation through the failure injection.
fn mutate(s: &mut State, apply: impl FnOnce(&mut State) -> Reply) -> Reply {
    s.mutations_seen += 1;
    let injection = s.inject_at.filter(|(at, _)| *at == s.mutations_seen).map(|(_, i)| i);
    match injection {
        Some(Injection::Fail) => err(500, 10001, "injected failure"),
        Some(Injection::LoseReply) => {
            apply(s);
            err(500, 10001, "injected lost reply")
        }
        None => apply(s),
    }
}
