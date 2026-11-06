//! Tests over real sockets. Raw requests are used so headers can be forged
//! in ways a normal HTTP client refuses to send.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fake_cloudflare::*;
use serde_json::{Value, json};
use tunnelkeeper_core::paths::Paths;
use tunnelkeeper_core::secret::Secret;
use tunnelkeeper_core::secrets::FileStore;
use tunnelkeeper_core::service::ServiceState;
use tunnelkeeper_core::testing::*;
use tunnelkeeper_core::util::random_hex;
use tunnelkeeper_core::{Deps, Keeper};

use super::*;

const API_TOKEN: &str = "web-test-api-token-value";
const HOST: &str = "app.example.com";

struct Ui {
    fake: Arc<FakeCloudflare>,
    zone: String,
    services: FakeServices,
    probes: FakeProbes,
    root: PathBuf,
    running: Running,
    port: u16,
    cookie: String,
    csrf: String,
}

impl Drop for Ui {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Http {
    status: u16,
    head: String,
    body: String,
}

impl Http {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

fn raw(port: u16, request: &str) -> Http {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    Http { status: head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0), head: head.to_string(), body: body.to_string() }
}

fn ui_with_token(token: Option<&str>) -> Ui {
    let fake = Arc::new(FakeCloudflare::spawn());
    fake.add_token(API_TOKEN, ALL_PERMS);
    let zone = fake.add_zone("example.com");
    let root = std::env::temp_dir().join(format!("tk-web-{}", random_hex(8)));
    let paths = Paths::under(&root);
    std::fs::create_dir_all(&paths.cache_dir).unwrap();
    std::fs::write(fake_binary(&paths), "2026.10.7").unwrap();
    let services = FakeServices::default();
    let probes = FakeProbes::default();
    let (f, s, p, r) = (fake.clone(), services.clone(), probes.clone(), root.clone());
    let token = token.map(str::to_string);
    let factory: KeeperFactory = Arc::new(move || {
        let paths = Paths::under(&r);
        Keeper::open(Deps {
            secrets: Box::new(FileStore::new(r.join("secrets"))),
            services: Box::new(s.clone()),
            elevator: Box::new(InlineElevator {
                paths: paths.clone(),
                services: s.clone(),
                ops: Arc::new(Mutex::new(vec![])),
                decline: Arc::new(Mutex::new(false)),
            }),
            probes: Box::new(p.clone()),
            locate: fake_locate,
            api_base: f.base_url(),
            release_base: f.release_base(),
            env_token: token.as_deref().map(Secret::new),
            verify_timeout: Duration::from_millis(200),
            poll_interval: Duration::from_millis(20),
            delete_attempts: 2,
            delete_retry_delay: Duration::from_millis(1),
            crash_sample: Duration::from_millis(1),
            paths,
        })
    });
    let running = start(0, factory).unwrap();
    let port = running.port;
    let url = running.launch_url();
    let launch = url.split("?launch=").nth(1).unwrap();
    let opened = raw(port, &format!("GET /?launch={launch} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"));
    assert_eq!(opened.status, 303);
    let set_cookie = opened.head.lines().find(|l| l.to_lowercase().starts_with("set-cookie:")).unwrap().to_string();
    assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Strict"), "{set_cookie}");
    let cookie = set_cookie.split_once(':').unwrap().1.trim().split(';').next().unwrap().to_string();
    let page = raw(port, &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"));
    let csrf = page.body.split("name=\"tk-csrf\" content=\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    Ui { fake, zone, services, probes, root, running, port, cookie, csrf }
}

fn ui() -> Ui {
    ui_with_token(Some(API_TOKEN))
}

impl Ui {
    fn get(&self, path: &str) -> Http {
        raw(self.port, &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: {}\r\nConnection: close\r\n\r\n", self.port, self.cookie))
    }

    fn post(&self, path: &str, body: &Value) -> Http {
        let text = body.to_string();
        raw(
            self.port,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nOrigin: http://127.0.0.1:{p}\r\nSec-Fetch-Site: same-origin\r\nContent-Type: application/json\r\nX-TK-CSRF: {c}\r\nCookie: {k}\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n{text}",
                p = self.port,
                c = self.csrf,
                k = self.cookie,
                n = text.len()
            ),
        )
    }

    fn wait_job(&self) -> Value {
        let start = Instant::now();
        loop {
            let job = self.get("/api/job").json();
            if job["state"] != "running" {
                return job;
            }
            assert!(start.elapsed() < Duration::from_secs(20), "job did not finish");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn setup(&self) -> Value {
        let body = json!({"tunnel": "web", "routes": [{"hostname": HOST, "service": "3000"}], "install_service": true, "zone": null, "replace_dns": []});
        assert_eq!(self.post("/api/setup", &body).status, 202);
        self.wait_job()
    }
}

// Launch and sessions

#[test]
fn listens_on_loopback_only() {
    let u = ui();
    let addr = u.running.server.server_addr().to_ip().unwrap();
    assert!(addr.ip().is_loopback(), "{addr}");
}

#[test]
fn launch_token_works_once() {
    let u = ui();
    let url = u.running.launch_url();
    let launch = url.split("?launch=").nth(1).unwrap();
    let again = raw(u.port, &format!("GET /?launch={launch} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", u.port));
    assert_eq!(again.status, 401);
    assert!(!again.head.to_lowercase().contains("set-cookie"));
}

#[test]
fn wrong_launch_token_gets_nothing_and_does_not_burn_the_real_one() {
    let running = start(0, Arc::new(|| Err(Error::Invalid("unused".into())))).unwrap();
    let port = running.port;
    let bad = raw(port, &format!("GET /?launch=wrong HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"));
    assert_eq!(bad.status, 401);
    let url = running.launch_url();
    let launch = url.split("?launch=").nth(1).unwrap();
    let good = raw(port, &format!("GET /?launch={launch} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"));
    assert_eq!(good.status, 303);
}

#[test]
fn launch_over_a_rebound_host_is_refused() {
    let running = start(0, Arc::new(|| Err(Error::Invalid("unused".into())))).unwrap();
    let port = running.port;
    let url = running.launch_url();
    let launch = url.split("?launch=").nth(1).unwrap();
    let r = raw(port, &format!("GET /?launch={launch} HTTP/1.1\r\nHost: evil.example:{port}\r\nConnection: close\r\n\r\n"));
    assert_eq!(r.status, 403);
    assert!(!r.head.to_lowercase().contains("set-cookie"));
}

#[test]
fn nothing_is_served_without_a_session() {
    let u = ui();
    for path in ["/", "/app.js", "/style.css", "/api/overview", "/api/logs", "/api/job", "/api/doctor"] {
        let r = raw(u.port, &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", u.port));
        assert_eq!(r.status, 401, "{path}");
        assert!(!r.body.contains(&u.csrf), "{path}");
    }
}

// The guards, end to end

#[test]
fn rebound_host_with_a_valid_session_is_refused() {
    let u = ui();
    let r = raw(u.port, &format!("GET /api/overview HTTP/1.1\r\nHost: evil.example:{}\r\nCookie: {}\r\nConnection: close\r\n\r\n", u.port, u.cookie));
    assert_eq!(r.status, 403);
    assert!(!r.body.contains("tunnels"));
}

#[test]
fn forged_writes_change_nothing() {
    let u = ui();
    let (p, k, c) = (u.port, u.cookie.clone(), u.csrf.clone());
    let body = json!({"tunnel": "web", "routes": [], "install_service": false, "zone": "example.com", "replace_dns": []}).to_string();
    let n = body.len();
    let forged = [
        // A page on another site, using a simple form post.
        format!("POST /api/setup HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nOrigin: http://evil.example\r\nSec-Fetch-Site: cross-site\r\nContent-Type: text/plain\r\nCookie: {k}\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n{body}"),
        // Everything right but the Origin.
        format!("POST /api/setup HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nOrigin: http://evil.example\r\nSec-Fetch-Site: same-origin\r\nContent-Type: application/json\r\nX-TK-CSRF: {c}\r\nCookie: {k}\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n{body}"),
        // No CSRF header.
        format!("POST /api/setup HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nOrigin: http://127.0.0.1:{p}\r\nSec-Fetch-Site: same-origin\r\nContent-Type: application/json\r\nCookie: {k}\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n{body}"),
        // Form content type.
        format!("POST /api/setup HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nOrigin: http://127.0.0.1:{p}\r\nSec-Fetch-Site: same-origin\r\nContent-Type: text/plain\r\nX-TK-CSRF: {c}\r\nCookie: {k}\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n{body}"),
        // No session.
        format!("POST /api/setup HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nOrigin: http://127.0.0.1:{p}\r\nSec-Fetch-Site: same-origin\r\nContent-Type: application/json\r\nX-TK-CSRF: {c}\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n{body}"),
    ];
    for f in &forged {
        let r = raw(p, f);
        assert!(r.status == 401 || r.status == 403 || r.status == 415, "{}: {f}", r.status);
    }
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(u.fake.mutation_count(), 0);
    assert_eq!(u.get("/api/job").json(), Value::Null, "no job was started");
}

#[test]
fn state_cannot_change_through_get() {
    let u = ui();
    for path in ["/api/setup", "/api/apply", "/api/service", "/api/auth/logout"] {
        assert_eq!(u.get(path).status, 404, "{path}");
    }
    assert_eq!(u.fake.mutation_count(), 0);
}

#[test]
fn other_methods_are_refused() {
    let u = ui();
    for method in ["PUT", "DELETE", "PATCH", "OPTIONS"] {
        let r = raw(u.port, &format!("{method} /api/setup HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: {}\r\nConnection: close\r\n\r\n", u.port, u.cookie));
        assert_eq!(r.status, 405, "{method}");
    }
}

#[test]
fn no_cors_headers_and_full_security_headers_on_every_reply() {
    let u = ui();
    let replies = [
        u.get("/"),
        u.get("/api/overview"),
        u.get("/nope"),
        raw(u.port, "GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n"),
        raw(u.port, &format!("OPTIONS /api/setup HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: http://evil.example\r\nConnection: close\r\n\r\n", u.port)),
    ];
    for r in replies {
        let head = r.head.to_lowercase();
        assert!(!head.contains("access-control-"), "{head}");
        assert!(head.contains("content-security-policy: default-src 'none'"), "{head}");
        assert!(head.contains("x-frame-options: deny"), "{head}");
        assert!(head.contains("x-content-type-options: nosniff"), "{head}");
        assert!(head.contains("cache-control: no-store"), "{head}");
    }
}

#[test]
fn oversized_bodies_are_refused() {
    let u = ui();
    let big = json!({"token": "x".repeat(70_000)});
    assert_eq!(u.post("/api/auth/login", &big).status, 413);
}

#[test]
fn page_has_no_inline_script_or_style() {
    assert!(!INDEX.contains("<script>"));
    assert!(!INDEX.contains("style="));
    assert!(!INDEX.contains("onclick="));
    assert!(!APP_JS.contains("innerHTML"));
    assert!(!APP_JS.contains("eval("));
    assert!(!STYLE.contains("url("), "no external assets");
}

// API behaviour

#[test]
fn setup_job_reports_steps_and_finishes() {
    let u = ui();
    let job = u.setup();
    assert_eq!(job["state"], "succeeded", "{job}");
    assert!(job["steps"].as_array().unwrap().iter().any(|s| s["detail"].as_str().unwrap().contains("created tunnel")));
    let o = u.get("/api/overview").json();
    assert_eq!(o["tunnels"][0]["name"], "web");
    assert_eq!(o["has_token"], true);
    assert_eq!(u.services.state("tunnelkeeper-web"), ServiceState::Running);
}

#[test]
fn failed_setup_shows_what_was_created_and_can_be_resumed() {
    let u = ui();
    u.fake.fail_mutation(2);
    let job = u.setup();
    assert_eq!(job["state"], "failed");
    let f = &job["failure"];
    assert_eq!(f["created"].as_array().unwrap().len(), 1);
    u.fake.clear_injection();
    let run = f["run_id"].as_str().unwrap();
    assert_eq!(u.post("/api/resume", &json!({"run_id": run})).status, 202);
    assert_eq!(u.wait_job()["state"], "succeeded");
    assert_eq!(u.fake.dns(&u.zone).len(), 1);
}

#[test]
fn dns_conflict_is_shown_and_needs_approval() {
    let u = ui();
    u.fake.add_dns(&u.zone, "A", HOST, "192.0.2.1", None);
    let job = u.setup();
    assert_eq!(job["failure"]["dns_conflict"]["records"][0]["content"], "192.0.2.1");
    assert_eq!(u.fake.dns(&u.zone)[0]["content"], "192.0.2.1");
    let run = job["failure"]["run_id"].as_str().unwrap().to_string();
    u.post("/api/resume", &json!({"run_id": run, "approve_dns": [HOST]}));
    assert_eq!(u.wait_job()["state"], "succeeded");
    assert_eq!(u.fake.dns(&u.zone)[0]["type"], "CNAME");
}

#[test]
fn delete_needs_the_plan_fingerprint_and_the_typed_name() {
    let u = ui();
    u.setup();
    let kind = json!({"kind": "delete_tunnel", "name": "web", "zone": null, "include_unmanaged_dns": false});
    let plan = u.post("/api/plan", &kind).json();
    assert!(plan["descriptions"].as_array().unwrap().iter().any(|d| d.as_str().unwrap().contains("DELETE tunnel")));
    assert_eq!(u.fake.tunnels().len(), 1, "planning deleted nothing");
    let fp = plan["fingerprint"].as_str().unwrap();

    u.post("/api/apply", &json!({"kind": kind, "fingerprint": fp, "confirm": "wrong"}));
    assert_eq!(u.wait_job()["state"], "failed");
    assert_eq!(u.fake.tunnels().len(), 1);

    u.post("/api/apply", &json!({"kind": kind, "fingerprint": "0000", "confirm": "web"}));
    let job = u.wait_job();
    assert_eq!(job["state"], "failed");
    assert!(job["error"].as_str().unwrap().contains("changed"));
    assert_eq!(u.fake.tunnels().len(), 1);

    u.post("/api/apply", &json!({"kind": kind, "fingerprint": fp, "confirm": "web"}));
    assert_eq!(u.wait_job()["state"], "succeeded");
    assert!(u.fake.tunnels().is_empty());
    assert!(u.fake.dns(&u.zone).is_empty());
}

#[test]
fn plan_shown_before_a_change_goes_stale() {
    let u = ui();
    u.setup();
    let kind = json!({"kind": "remove_route", "hostname": HOST, "tunnel": "web", "include_unmanaged_dns": false});
    let plan = u.post("/api/plan", &kind).json();
    u.fake.add_dns(&u.zone, "TXT", HOST, "added later", None);
    u.post("/api/apply", &json!({"kind": kind, "fingerprint": plan["fingerprint"], "confirm": HOST}));
    assert_eq!(u.wait_job()["state"], "failed");
    assert_eq!(u.fake.dns(&u.zone).len(), 2, "nothing was deleted");
}

#[test]
fn only_one_change_runs_at_a_time() {
    let u = ui();
    u.probes.set_ready(tunnelkeeper_core::health::ReadyProbe::NotReady);
    let body = json!({"tunnel": "web", "routes": [{"hostname": HOST, "service": "3000"}], "install_service": true, "zone": null, "replace_dns": []});
    assert_eq!(u.post("/api/setup", &body).status, 202);
    assert_eq!(u.post("/api/setup", &body).status, 409);
    u.wait_job();
}

#[test]
fn reads_keep_working_during_a_change() {
    let u = ui();
    u.probes.set_ready(tunnelkeeper_core::health::ReadyProbe::NotReady);
    let body = json!({"tunnel": "web", "routes": [{"hostname": HOST, "service": "3000"}], "install_service": true, "zone": null, "replace_dns": []});
    u.post("/api/setup", &body);
    assert_eq!(u.get("/api/overview").status, 200);
    u.wait_job();
}

#[test]
fn route_add_and_service_actions() {
    let u = ui();
    u.setup();
    assert_eq!(u.post("/api/route", &json!({"tunnel": "web", "hostname": "api.example.com", "target": "8080"})).status, 202);
    assert_eq!(u.wait_job()["state"], "succeeded");
    assert_eq!(u.fake.dns(&u.zone).len(), 2);

    assert_eq!(u.post("/api/service", &json!({"tunnel": "web", "action": "stop"})).status, 202);
    u.wait_job();
    assert_eq!(u.services.state("tunnelkeeper-web"), ServiceState::Stopped);
    assert_eq!(u.get("/api/overview").json()["tunnels"][0]["state"], "SERVICE_STOPPED");

    assert_eq!(u.post("/api/service", &json!({"tunnel": "web", "action": "format-disk"})).status, 400);
}

#[test]
fn bad_input_gives_a_clear_error() {
    let u = ui();
    assert_eq!(u.post("/api/setup", &json!({"nonsense": true})).status, 400);
    let body = json!({"tunnel": "Bad Name", "routes": [], "install_service": false, "zone": null, "replace_dns": []});
    u.post("/api/setup", &body);
    let job = u.wait_job();
    assert_eq!(job["state"], "failed");
    assert!(job["error"].as_str().unwrap().contains("invalid tunnel name"));
}

#[test]
fn doctor_runs_and_logs_tunnel_and_runs_routes_answer() {
    let u = ui();
    u.setup();
    assert!(u.get("/api/doctor").json().as_array().unwrap().iter().any(|f| f["id"] == "token.active"));
    assert_eq!(u.get("/api/tunnels?zone=example.com").json()[0]["name"], "web");
    assert_eq!(u.get("/api/runs").json()[0]["tunnel"], "web");
    assert_eq!(u.get("/api/logs?tunnel=web").json(), json!([]));
    assert_eq!(u.get("/api/logs?tunnel=missing").status, 404);
}

// Secrets

#[test]
fn login_stores_the_token_and_never_returns_it() {
    let u = ui_with_token(None);
    assert_eq!(u.get("/api/overview").json()["has_token"], false);
    let r = u.post("/api/auth/login", &json!({"token": API_TOKEN, "zone": "example.com"}));
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(!r.body.contains(API_TOKEN));
    assert_eq!(r.json()["token_status"], "active");
    assert_eq!(u.get("/api/overview").json()["has_token"], true);
    assert_eq!(u.post("/api/auth/logout", &json!({})).status, 200);
    assert_eq!(u.get("/api/overview").json()["has_token"], false);
}

#[test]
fn rejected_and_malformed_tokens_are_not_echoed() {
    let u = ui_with_token(None);
    let secret = "not-a-valid-token-but-still-private";
    let r = u.post("/api/auth/login", &json!({"token": secret, "zone": null}));
    assert_ne!(r.status, 200);
    assert!(!r.body.contains(secret), "{}", r.body);
    let r = u.post("/api/auth/login", &json!({"token": {"nested": secret}}));
    assert_eq!(r.status, 400);
    assert!(!r.body.contains(secret), "{}", r.body);
}

#[test]
fn no_reply_ever_contains_a_token() {
    let u = ui();
    let dir = Paths::under(&u.root).log_dir("web");
    u.setup();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cloudflared.log"), format!("bad {API_TOKEN}\nrun --token eyJhIjoiNWFiNGU5ZDEyMyIsInQiOiJ4eXoifQ\n")).unwrap();
    let mut all = String::new();
    for path in ["/api/overview", "/api/job", "/api/doctor", "/api/runs", "/api/logs?tunnel=web", "/api/tunnels?zone=example.com"] {
        all.push_str(&u.get(path).body);
    }
    all.push_str(&u.post("/api/plan", &json!({"kind": "delete_tunnel", "name": "web", "zone": null, "include_unmanaged_dns": false})).body);
    assert!(!all.contains(API_TOKEN));
    assert!(!all.contains(TUNNEL_TOKEN_MARKER));
    assert!(!all.contains("eyJhIjoi"));
}

#[test]
fn query_decoding() {
    assert_eq!(query_param("a=1&zone=ex%2Dample.com", "zone").as_deref(), Some("ex-ample.com"));
    assert_eq!(query_param("a=1", "zone"), None);
    assert_eq!(decode("100%"), "100%");
    assert_eq!(decode("%zz"), "%zz");
}
