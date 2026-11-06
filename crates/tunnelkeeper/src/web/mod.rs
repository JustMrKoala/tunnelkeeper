//! The local web UI. This layer parses requests, guards them and turns core
//! results into JSON. It holds no tunnel logic of its own.

mod guard;
#[cfg(test)]
mod tests;

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response, Server};

use guard::{CSRF_HEADER, Denied, RequestFacts, SESSION_COOKIE, Secrets};
use tunnelkeeper_core::Keeper;
use tunnelkeeper_core::error::{Error, Result};
use tunnelkeeper_core::plan::PlanKind;
use tunnelkeeper_core::secret::Secret;
use tunnelkeeper_core::setup::{FailureView, RouteRequest, SetupFailure, SetupReport, SetupRequest, StepReport};
use tunnelkeeper_core::util::random_hex;

const INDEX: &str = include_str!("../../ui/index.html");
const APP_JS: &str = include_str!("../../ui/app.js");
const STYLE: &str = include_str!("../../ui/style.css");
const WORKERS: usize = 4;
const MAX_BODY: u64 = 64 * 1024;
const MAX_LOG_LINES: usize = 2000;
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                   base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Each request opens its own Keeper, so the UI always sees the same config
/// as the CLI and requests share no mutable state.
pub type KeeperFactory = Arc<dyn Fn() -> Result<Keeper> + Send + Sync>;

#[derive(Serialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
enum JobState {
    Running,
    Succeeded,
    Failed,
}

#[derive(Serialize, Clone, Debug)]
struct Job {
    id: String,
    title: String,
    state: JobState,
    steps: Vec<StepReport>,
    result: Option<Value>,
    error: Option<String>,
    failure: Option<FailureView>,
}

struct State {
    factory: KeeperFactory,
    port: u16,
    session: String,
    csrf: String,
    launch: Mutex<Option<String>>,
    job: Mutex<Option<Job>>,
}

pub struct Running {
    server: Arc<Server>,
    launch_url: String,
    workers: Vec<JoinHandle<()>>,
    #[cfg(test)]
    port: u16,
}

impl Running {
    pub fn launch_url(&self) -> String {
        self.launch_url.clone()
    }

    pub fn wait(mut self) {
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        for _ in 0..WORKERS {
            self.server.unblock();
        }
    }
}

/// Binds to 127.0.0.1 only. There is deliberately no option to change that.
pub fn start(port: u16, factory: KeeperFactory) -> Result<Running> {
    let server = Server::http(("127.0.0.1", port))
        .map_err(|e| Error::Invalid(format!("cannot listen on 127.0.0.1:{port}: {e}. Try --port with another number")))?;
    let server = Arc::new(server);
    let port = server.server_addr().to_ip().map(|a| a.port()).ok_or_else(|| Error::Invalid("no IP listener".into()))?;
    let launch = random_hex(32);
    let launch_url = format!("http://127.0.0.1:{port}/?launch={launch}");
    let state = Arc::new(State {
        factory,
        port,
        session: random_hex(32),
        csrf: random_hex(32),
        launch: Mutex::new(Some(launch)),
        job: Mutex::new(None),
    });
    let workers = (0..WORKERS)
        .map(|_| {
            let (server, state) = (server.clone(), state.clone());
            std::thread::spawn(move || {
                while let Ok(request) = server.recv() {
                    serve(&state, request);
                }
            })
        })
        .collect();
    Ok(Running {
        server,
        launch_url,
        workers,
        #[cfg(test)]
        port,
    })
}

/// The URL holds only a one time launch token, never an API or tunnel token.
pub fn open_browser(url: &str) {
    let result = if cfg!(windows) {
        std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
    if result.is_err() {
        eprintln!("Could not open a browser. Open the link above yourself.");
    }
}

struct Reply {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    headers: Vec<(&'static str, String)>,
}

impl Reply {
    fn json<T: Serialize>(value: &T) -> Reply {
        Reply::json_status(200, value)
    }
    fn json_status<T: Serialize>(status: u16, value: &T) -> Reply {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Reply { status, content_type: "application/json", body, headers: vec![] }
    }
    fn text(status: u16, content_type: &'static str, body: impl Into<Vec<u8>>) -> Reply {
        Reply { status, content_type, body: body.into(), headers: vec![] }
    }
    fn message(status: u16, message: &str) -> Reply {
        Reply::json_status(status, &json!({"error": message}))
    }
    fn denied(d: Denied) -> Reply {
        Reply::message(d.status, d.reason)
    }
    fn error(e: &Error) -> Reply {
        let status = match e {
            Error::Invalid(_) => 400,
            Error::Auth(_) | Error::Permission(_) => 403,
            Error::NotFound(_) => 404,
            Error::Conflict(_) | Error::StalePlan(_) | Error::DnsConflict { .. } => 409,
            Error::Network(_) => 502,
            _ => 500,
        };
        Reply::message(status, &e.to_string())
    }
}

fn header(request: &Request, name: &str) -> Option<String> {
    request.headers().iter().find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name)).map(|h| h.value.as_str().to_string())
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 3 <= bytes.len() && s.is_char_boundary(i + 1) && s.is_char_boundary(i + 3) => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == name).then(|| decode(v))
    })
}

fn serve(state: &Arc<State>, mut request: Request) {
    let url = request.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let post = *request.method() == Method::Post;
    let facts = RequestFacts {
        post,
        host: header(&request, "Host"),
        origin: header(&request, "Origin"),
        sec_fetch_site: header(&request, "Sec-Fetch-Site"),
        content_type: header(&request, "Content-Type"),
        cookie: header(&request, "Cookie"),
        csrf: header(&request, CSRF_HEADER),
    };
    let reply = if !post && *request.method() != Method::Get {
        Reply::message(405, "method not allowed")
    } else if let Err(d) = guard::check_origin_rules(&facts, state.port) {
        Reply::denied(d)
    } else if let Some(reply) = launch(state, &facts, path, query) {
        reply
    } else {
        let secrets = Secrets { port: state.port, session: &state.session, csrf: &state.csrf };
        match guard::check(&facts, &secrets) {
            Err(d) if path == "/" && !post => {
                Reply::text(d.status, "text/plain; charset=utf-8", "Open the link printed by: tunnelkeeper ui\n")
            }
            Err(d) => Reply::denied(d),
            Ok(()) if post => {
                let mut body = Vec::new();
                let read = request.as_reader().take(MAX_BODY + 1).read_to_end(&mut body);
                if read.is_err() {
                    Reply::message(400, "could not read the request")
                } else if body.len() as u64 > MAX_BODY {
                    Reply::message(413, "request too large")
                } else {
                    route_post(state, path, &body)
                }
            }
            Ok(()) => route_get(state, path, query),
        }
    };
    respond(request, reply);
}

fn respond(request: Request, reply: Reply) {
    let mut response = Response::from_data(reply.body).with_status_code(reply.status);
    let fixed = [
        ("Content-Type", reply.content_type),
        ("Content-Security-Policy", CSP),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "no-store"),
    ];
    for (k, v) in fixed {
        response.add_header(Header::from_bytes(k, v).expect("static header"));
    }
    for (k, v) in &reply.headers {
        response.add_header(Header::from_bytes(*k, v.as_bytes()).expect("server made header"));
    }
    let _ = request.respond(response);
}

/// Trades the one time launch token for the session cookie.
fn launch(state: &State, facts: &RequestFacts, path: &str, query: &str) -> Option<Reply> {
    if facts.post || path != "/" {
        return None;
    }
    let given = query_param(query, "launch")?;
    let mut pending = state.launch.lock().unwrap();
    if !pending.as_deref().is_some_and(|p| guard::same(p, &given)) {
        return Some(Reply::text(401, "text/plain; charset=utf-8", "This link was already used. Run tunnelkeeper ui again.\n"));
    }
    *pending = None;
    let mut reply = Reply::text(303, "text/plain; charset=utf-8", "");
    reply.headers.push(("Location", "/".to_string()));
    reply.headers.push(("Set-Cookie", format!("{SESSION_COOKIE}={}; HttpOnly; SameSite=Strict; Path=/", state.session)));
    Some(reply)
}

fn keeper(state: &State) -> std::result::Result<Keeper, Reply> {
    (state.factory)().map_err(|e| Reply::error(&e))
}

fn reply_for<T: Serialize>(result: Result<T>) -> Reply {
    match result {
        Ok(v) => Reply::json(&v),
        Err(e) => Reply::error(&e),
    }
}

fn route_get(state: &Arc<State>, path: &str, query: &str) -> Reply {
    match path {
        "/" => Reply::text(200, "text/html; charset=utf-8", INDEX.replace("__CSRF__", &state.csrf)),
        "/app.js" => Reply::text(200, "text/javascript; charset=utf-8", APP_JS),
        "/style.css" => Reply::text(200, "text/css; charset=utf-8", STYLE),
        "/api/job" => Reply::json(&*state.job.lock().unwrap()),
        _ if path.starts_with("/api/") => {
            let k = match keeper(state) {
                Ok(k) => k,
                Err(r) => return r,
            };
            let param = |n: &str| query_param(query, n).filter(|v| !v.is_empty());
            match path {
                "/api/overview" => reply_for(k.status_all().map(|tunnels| {
                    json!({"tunnels": tunnels, "cloudflared": k.cloudflared_status(), "has_token": k.has_token()})
                })),
                "/api/tunnels" => reply_for(k.tunnel_list(param("zone").as_deref())),
                "/api/doctor" => Reply::json(&k.doctor()),
                "/api/runs" => reply_for(k.runs().map(|runs| runs.iter().map(|j| j.view()).collect::<Vec<_>>())),
                "/api/logs" => {
                    let lines = param("lines").and_then(|l| l.parse().ok()).unwrap_or(200usize).min(MAX_LOG_LINES);
                    reply_for(k.logs_tail(param("tunnel").as_deref(), lines))
                }
                _ => Reply::message(404, "no such route"),
            }
        }
        _ => Reply::message(404, "no such route"),
    }
}

#[derive(Deserialize)]
struct Login {
    token: Secret,
    zone: Option<String>,
}

#[derive(Deserialize)]
struct Resume {
    run_id: String,
    #[serde(default)]
    approve_dns: Vec<String>,
}

#[derive(Deserialize)]
struct AddRoute {
    tunnel: String,
    hostname: String,
    target: String,
}

#[derive(Deserialize)]
struct ServiceAction {
    tunnel: String,
    action: String,
}

#[derive(Deserialize)]
struct Apply {
    kind: PlanKind,
    fingerprint: String,
    confirm: String,
}

#[derive(Deserialize)]
struct Download {
    version: Option<String>,
}

fn parse<'a, T: Deserialize<'a>>(body: &'a [u8]) -> std::result::Result<T, Reply> {
    serde_json::from_slice(body).map_err(|e| {
        // Only the position is reported. Serde messages can quote the input,
        // and the input may hold a token.
        Reply::message(400, &format!("invalid request at line {} column {}", e.line(), e.column()))
    })
}

fn route_post(state: &Arc<State>, path: &str, body: &[u8]) -> Reply {
    macro_rules! body {
        ($t:ty) => {
            match parse::<$t>(body) {
                Ok(v) => v,
                Err(r) => return r,
            }
        };
    }
    match path {
        "/api/auth/login" => {
            let login = body!(Login);
            match keeper(state) {
                Ok(k) => reply_for(k.auth_login(login.token, login.zone.as_deref().filter(|z| !z.is_empty()))),
                Err(r) => r,
            }
        }
        "/api/auth/logout" => match keeper(state) {
            Ok(k) => reply_for(k.auth_logout().map(|()| json!({}))),
            Err(r) => r,
        },
        "/api/plan" => {
            let kind = body!(PlanKind);
            match keeper(state) {
                Ok(k) => reply_for(k.plan(kind)),
                Err(r) => r,
            }
        }
        "/api/apply" => {
            let apply = body!(Apply);
            start_job(state, "Applying changes", move |k, _| {
                let plan = k.plan(apply.kind).map_err(fail)?;
                if plan.fingerprint != apply.fingerprint {
                    return Err(fail(Error::StalePlan("real state changed since this plan was shown. Review it again".into())));
                }
                let report = k.apply(plan.confirm(&apply.confirm).map_err(fail)?).map_err(fail)?;
                let value = json!(report);
                match &report.failed {
                    None => Ok(value),
                    Some(f) => Err(JobError { message: f.clone(), failure: None, result: Some(value) }),
                }
            })
        }
        "/api/setup" => {
            let request = body!(SetupRequest);
            let title = format!("Setting up {}", request.tunnel);
            start_job(state, &title, move |k, job| finish(k.reconcile(request, &mut |s| job.step(s))))
        }
        "/api/resume" => {
            let resume = body!(Resume);
            let title = format!("Resuming run {}", resume.run_id);
            start_job(state, &title, move |k, job| finish(k.resume(&resume.run_id, &resume.approve_dns, &mut |s| job.step(s))))
        }
        "/api/route" => {
            let add = body!(AddRoute);
            let title = format!("Adding route {}", add.hostname);
            let request = SetupRequest {
                tunnel: add.tunnel,
                routes: vec![RouteRequest { hostname: add.hostname, service: add.target }],
                install_service: false,
                zone: None,
                replace_dns: vec![],
            };
            start_job(state, &title, move |k, job| finish(k.reconcile(request, &mut |s| job.step(s))))
        }
        "/api/service" => {
            let a = body!(ServiceAction);
            let title = format!("Service {}: {}", a.tunnel, a.action);
            if !["install", "start", "stop", "uninstall"].contains(&a.action.as_str()) {
                return Reply::message(400, "unknown service action");
            }
            start_job(state, &title, move |k, _| {
                let t = Some(a.tunnel.as_str());
                let done = match a.action.as_str() {
                    "install" => k.service_install(t),
                    "start" => k.service_start(t),
                    "stop" => k.service_stop(t),
                    _ => k.service_uninstall(t),
                };
                done.map(|()| json!({})).map_err(fail)
            })
        }
        "/api/cloudflared/install" => {
            let d = body!(Download);
            start_job(state, "Downloading cloudflared", move |k, _| {
                let release = k.cloudflared_release(d.version.as_deref()).map_err(fail)?;
                let path = k.cloudflared_download(&release).map_err(fail)?;
                Ok(json!({"version": release.version, "path": path}))
            })
        }
        _ => Reply::message(404, "no such route"),
    }
}

struct JobError {
    message: String,
    failure: Option<FailureView>,
    result: Option<Value>,
}

fn fail(e: Error) -> JobError {
    JobError { message: e.to_string(), failure: None, result: None }
}

fn finish(outcome: std::result::Result<SetupReport, SetupFailure>) -> std::result::Result<Value, JobError> {
    match outcome {
        Ok(report) => Ok(json!(report)),
        Err(f) => Err(JobError { message: f.error.to_string(), failure: Some(f.view()), result: None }),
    }
}

struct JobHandle {
    state: Arc<State>,
}

impl JobHandle {
    fn step(&self, s: &StepReport) {
        if let Some(job) = self.state.job.lock().unwrap().as_mut() {
            job.steps.push(s.clone());
        }
    }
}

/// Runs one change at a time in the background. Setup can wait on a UAC
/// prompt and on cloudflared connecting, far too long for one request.
fn start_job<F>(state: &Arc<State>, title: &str, work: F) -> Reply
where
    F: FnOnce(&mut Keeper, &JobHandle) -> std::result::Result<Value, JobError> + Send + 'static,
{
    let id = random_hex(8);
    {
        let mut slot = state.job.lock().unwrap();
        if slot.as_ref().is_some_and(|j| j.state == JobState::Running) {
            return Reply::message(409, "another change is still running");
        }
        *slot = Some(Job {
            id: id.clone(),
            title: title.to_string(),
            state: JobState::Running,
            steps: vec![],
            result: None,
            error: None,
            failure: None,
        });
    }
    let state = state.clone();
    std::thread::spawn(move || {
        let handle = JobHandle { state: state.clone() };
        let outcome = (state.factory)().map_err(fail).and_then(|mut k| work(&mut k, &handle));
        if let Some(job) = state.job.lock().unwrap().as_mut() {
            match outcome {
                Ok(value) => {
                    job.state = JobState::Succeeded;
                    job.result = Some(value);
                }
                Err(e) => {
                    job.state = JobState::Failed;
                    job.error = Some(e.message);
                    job.failure = e.failure;
                    job.result = e.result;
                }
            }
        }
    });
    Reply::json_status(202, &json!({"job": id}))
}
