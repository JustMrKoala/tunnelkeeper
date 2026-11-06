//! End to end flows of the core against the fake Cloudflare API, which is a
//! real HTTP server, so the real client code runs in every test.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fake_cloudflare::*;
use serde_json::json;
use tunnelkeeper_core::cloudflare::Probe;
use tunnelkeeper_core::doctor::Severity;
use tunnelkeeper_core::error::Error;
use tunnelkeeper_core::health::{OriginProbe, ReadyProbe, TunnelState};
use tunnelkeeper_core::journal::RunStatus;
use tunnelkeeper_core::paths::Paths;
use tunnelkeeper_core::plan::{Action, PlanKind};
use tunnelkeeper_core::secret::Secret;
use tunnelkeeper_core::secrets::MemoryStore;
use tunnelkeeper_core::service::ServiceState;
use tunnelkeeper_core::setup::{RouteRequest, SetupFailure, SetupReport, SetupRequest, StepStatus};
use tunnelkeeper_core::testing::*;
use tunnelkeeper_core::util::random_hex;
use tunnelkeeper_core::{Deps, Keeper};

const SERVICE: &str = "tunnelkeeper-web";
const HOST: &str = "app.example.com";
const API_TOKEN: &str = "good-api-token-value";

struct Env {
    fake: FakeCloudflare,
    zone: String,
    services: FakeServices,
    probes: FakeProbes,
    ops: Arc<Mutex<Vec<String>>>,
    decline: Arc<Mutex<bool>>,
    root: PathBuf,
    paths: Paths,
    keeper: Keeper,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn keeper_with_token(fake: &FakeCloudflare, paths: &Paths, services: &FakeServices, probes: &FakeProbes, ops: &Arc<Mutex<Vec<String>>>, decline: &Arc<Mutex<bool>>, token: &str) -> Keeper {
    Keeper::open(Deps {
        paths: paths.clone(),
        secrets: Box::new(MemoryStore::default()),
        services: Box::new(services.clone()),
        elevator: Box::new(InlineElevator { paths: paths.clone(), services: services.clone(), ops: ops.clone(), decline: decline.clone() }),
        probes: Box::new(probes.clone()),
        locate: fake_locate,
        api_base: fake.base_url(),
        release_base: fake.release_base(),
        env_token: Some(Secret::new(token)),
        verify_timeout: Duration::from_millis(200),
        poll_interval: Duration::from_millis(20),
        delete_attempts: 4,
        delete_retry_delay: Duration::from_millis(1),
        crash_sample: Duration::from_millis(1),
    })
    .unwrap()
}

fn env_with_token(token: &str, perms: &[&str]) -> Env {
    let fake = FakeCloudflare::spawn();
    fake.add_token(token, perms);
    let zone = fake.add_zone("example.com");
    let root = std::env::temp_dir().join(format!("tk-flow-{}", random_hex(8)));
    let paths = Paths::under(&root);
    std::fs::create_dir_all(&paths.cache_dir).unwrap();
    std::fs::write(fake_binary(&paths), "2026.10.7").unwrap();
    let services = FakeServices::default();
    let probes = FakeProbes::default();
    let ops = Arc::new(Mutex::new(vec![]));
    let decline = Arc::new(Mutex::new(false));
    let keeper = keeper_with_token(&fake, &paths, &services, &probes, &ops, &decline, token);
    Env { fake, zone, services, probes, ops, decline, root, paths, keeper }
}

fn env() -> Env {
    env_with_token(API_TOKEN, ALL_PERMS)
}

fn request() -> SetupRequest {
    SetupRequest {
        tunnel: "web".into(),
        routes: vec![RouteRequest { hostname: HOST.into(), service: "3000".into(), no_tls_verify: false }],
        install_service: true,
        zone: None,
        replace_dns: vec![],
    }
}

impl Env {
    fn setup(&mut self) -> Result<SetupReport, SetupFailure> {
        self.keeper.reconcile(request(), &mut |_| {})
    }
    fn resume(&mut self, id: &str) -> Result<SetupReport, SetupFailure> {
        self.keeper.resume(id, &[], &mut |_| {})
    }
    fn rollback(&mut self, id: &str) {
        let plan = self.keeper.plan(PlanKind::Rollback { run_id: id.to_string() }).unwrap();
        let phrase = plan.confirm_phrase.clone();
        let report = self.keeper.apply(plan.confirm(&phrase).unwrap()).unwrap();
        assert!(report.ok(), "{report:?}");
    }
    fn assert_fully_set_up(&self) {
        let tunnels = self.fake.tunnels();
        assert_eq!(tunnels.len(), 1, "exactly one tunnel");
        let id = tunnels[0]["id"].as_str().unwrap();
        let rules = self.fake.ingress(id);
        assert_eq!(rules.len(), 2, "one route and the catch all: {rules:?}");
        assert_eq!(rules[0]["hostname"], HOST);
        assert_eq!(rules[0]["service"], "http://localhost:3000");
        assert_eq!(rules[1]["service"], "http_status:404");
        let dns = self.fake.dns(&self.zone);
        assert_eq!(dns.len(), 1, "exactly one DNS record");
        assert_eq!(dns[0]["type"], "CNAME");
        assert_eq!(dns[0]["content"], format!("{id}.cfargotunnel.com"));
        assert_eq!(dns[0]["proxied"], true);
        assert_eq!(self.services.state(SERVICE), ServiceState::Running);
        assert!(self.paths.tunnel_token("web").exists());
    }
    fn assert_clean(&self) {
        assert!(self.fake.tunnels().is_empty(), "tunnel left behind");
        assert!(self.fake.dns(&self.zone).is_empty(), "DNS left behind");
        assert_eq!(self.services.state(SERVICE), ServiceState::Missing, "service left behind");
        assert!(!self.paths.tunnel_token("web").exists(), "token left behind");
        assert!(self.keeper.config().tunnels.is_empty(), "config left behind");
    }
}

// Setup and idempotency

#[test]
fn setup_creates_everything() {
    let mut e = env();
    let report = e.setup().unwrap();
    assert!(report.changed);
    e.assert_fully_set_up();
    assert_eq!(report.health.unwrap().state, TunnelState::Healthy);
    let cfg = &e.keeper.config().tunnels[0];
    assert_eq!(cfg.metrics_port, 20301);
    assert_eq!(cfg.routes[0].hostname, HOST);
    assert!(e.paths.managed_cloudflared().is_file(), "binary copied to the protected folder");
}

#[test]
fn running_setup_twice_changes_nothing() {
    let mut e = env();
    e.setup().unwrap();
    let mutations = e.fake.mutation_count();
    let ops = e.ops.lock().unwrap().len();
    let report = e.setup().unwrap();
    assert!(!report.changed, "{:?}", report.steps);
    assert_eq!(report.run_id, None);
    assert_eq!(e.fake.mutation_count(), mutations, "no write reached Cloudflare");
    assert_eq!(e.ops.lock().unwrap().len(), ops, "no elevation was requested");
    e.assert_fully_set_up();
}

#[test]
fn setup_starts_a_stopped_service_without_reinstalling() {
    let mut e = env();
    e.setup().unwrap();
    e.services.set_state(SERVICE, ServiceState::Stopped);
    e.setup().unwrap();
    assert_eq!(e.services.state(SERVICE), ServiceState::Running);
    assert_eq!(e.ops.lock().unwrap().as_slice(), ["install_tunnel", "start"]);
}

#[test]
fn second_tunnel_gets_its_own_metrics_port() {
    let mut e = env();
    e.probes.set_port_busy(20302);
    e.setup().unwrap();
    let mut r = request();
    r.tunnel = "other".into();
    r.routes[0].hostname = "other.example.com".into();
    e.keeper.reconcile(r, &mut |_| {}).unwrap();
    assert_eq!(e.keeper.config().tunnel("other").unwrap().metrics_port, 20303);
}

// Failure at every step

/// How many real writes a clean setup makes.
fn clean_mutations() -> usize {
    let mut e = env();
    e.setup().unwrap();
    let n = e.fake.mutation_count();
    assert!(n >= 3, "expected tunnel, ingress and DNS writes, saw {n}");
    n
}

#[test]
fn failure_at_every_write_can_be_resumed() {
    for n in 1..=clean_mutations() {
        let mut e = env();
        e.fake.fail_mutation(n);
        let failure = e.setup().expect_err("setup must fail");
        assert_eq!(failure.created.len(), n - 1, "write {n}: everything before it is reported");
        e.fake.clear_injection();
        e.resume(failure.run_id.as_deref().unwrap()).unwrap();
        e.assert_fully_set_up();
    }
}

#[test]
fn failure_at_every_write_can_be_rolled_back() {
    for n in 1..=clean_mutations() {
        let mut e = env();
        e.fake.fail_mutation(n);
        let failure = e.setup().expect_err("setup must fail");
        e.fake.clear_injection();
        e.rollback(failure.run_id.as_deref().unwrap());
        e.assert_clean();
    }
}

#[test]
fn lost_reply_at_every_write_makes_no_duplicates_and_stays_owned() {
    for n in 1..=clean_mutations() {
        let mut e = env();
        e.fake.lose_reply(n);
        let failure = e.setup().expect_err("setup must fail");
        assert_eq!(failure.unknown.len(), 1, "write {n}: reported as unknown, not as created");
        let run = failure.run_id.unwrap();
        e.fake.clear_injection();
        e.resume(&run).unwrap();
        e.assert_fully_set_up();
        e.rollback(&run);
        e.assert_clean();
    }
}

#[test]
fn rollback_warns_about_unknown_outcomes() {
    let mut e = env();
    e.fake.lose_reply(1);
    let failure = e.setup().unwrap_err();
    e.fake.clear_injection();
    let plan = e.keeper.plan(PlanKind::Rollback { run_id: failure.run_id.unwrap() }).unwrap();
    assert_eq!(plan.warnings.len(), 1);
    assert!(plan.warnings[0].contains("may exist"));
}

#[test]
fn failed_service_steps_can_be_resumed_and_rolled_back() {
    for op in ["install", "start"] {
        let mut e = env();
        e.services.fail_next(op);
        let failure = e.setup().expect_err("setup must fail");
        assert_eq!(failure.step, "service");
        assert_eq!(failure.created.len(), 3, "tunnel, ingress, DNS");
        let run = failure.run_id.unwrap();
        e.resume(&run).unwrap();
        e.assert_fully_set_up();

        let mut e = env();
        e.services.fail_next(op);
        let run = e.setup().unwrap_err().run_id.unwrap();
        e.rollback(&run);
        e.assert_clean();
    }
}

#[test]
fn declined_elevation_is_reported_and_resumable() {
    let mut e = env();
    *e.decline.lock().unwrap() = true;
    let failure = e.setup().unwrap_err();
    assert!(matches!(failure.error, Error::Elevation(_)));
    *e.decline.lock().unwrap() = false;
    e.resume(failure.run_id.as_deref().unwrap()).unwrap();
    e.assert_fully_set_up();
}

#[test]
fn tunnel_that_never_connects_fails_verification() {
    let mut e = env();
    e.probes.set_ready(ReadyProbe::NotReady);
    let failure = e.setup().unwrap_err();
    assert_eq!(failure.step, "verify");
    assert!(failure.error.to_string().contains("no connection to Cloudflare"));
}

#[test]
fn local_app_down_is_a_warning_not_a_failure() {
    let mut e = env();
    e.probes.set_origin("http://localhost:3000", OriginProbe::NotResponding("refused".into()));
    let report = e.setup().unwrap();
    assert!(report.steps.iter().any(|s| s.status == StepStatus::Warning && s.detail.contains("not responding")));
    assert_eq!(report.health.unwrap().state, TunnelState::OriginDown);
}

#[test]
fn run_history_records_status() {
    let mut e = env();
    e.fake.fail_mutation(2);
    let failure = e.setup().unwrap_err();
    assert_eq!(e.keeper.runs().unwrap()[0].status, RunStatus::Failed);
    e.fake.clear_injection();
    e.rollback(failure.run_id.as_deref().unwrap());
    assert_eq!(e.keeper.runs().unwrap()[0].status, RunStatus::RolledBack);
    assert!(e.keeper.resume(failure.run_id.as_deref().unwrap(), &[], &mut |_| {}).is_err(), "a rolled back run cannot resume");
}

// cloudflared checks

#[test]
fn missing_cloudflared_stops_before_any_change() {
    let mut e = env();
    std::fs::remove_file(fake_binary(&e.paths)).unwrap();
    let failure = e.setup().unwrap_err();
    assert!(matches!(failure.error, Error::CloudflaredMissing(_)));
    assert_eq!(e.fake.mutation_count(), 0);
    assert!(failure.created.is_empty());
}

#[test]
fn old_cloudflared_is_refused() {
    let mut e = env();
    std::fs::write(fake_binary(&e.paths), "2025.3.0").unwrap();
    assert!(e.setup().unwrap_err().error.to_string().contains("--token-file"));
}

#[test]
fn download_verifies_checksum() {
    let e = env();
    let asset = tunnelkeeper_core::cloudflared::asset_name().unwrap();
    e.fake.set_release("2026.10.7", asset, b"binary bytes", None);
    let release = e.keeper.cloudflared_release(None).unwrap();
    assert_eq!(release.version, "2026.10.7");
    let path = e.keeper.cloudflared_download(&release).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"binary bytes");
}

#[test]
fn download_with_wrong_checksum_is_deleted() {
    let e = env();
    let asset = tunnelkeeper_core::cloudflared::asset_name().unwrap();
    e.fake.set_release("2026.10.7", asset, b"tampered", Some(&"0".repeat(64)));
    let release = e.keeper.cloudflared_release(None).unwrap();
    let error = e.keeper.cloudflared_download(&release).unwrap_err();
    assert!(error.to_string().contains("checksum mismatch"));
    let left: Vec<_> = std::fs::read_dir(e.paths.download_dir()).unwrap().collect();
    assert!(left.is_empty(), "nothing usable may remain");
}

#[test]
fn release_without_checksum_is_refused() {
    let e = env();
    e.fake.set_release("2026.10.7", tunnelkeeper_core::cloudflared::asset_name().unwrap(), b"x", Some("not-a-hash"));
    assert!(e.keeper.cloudflared_release(None).unwrap_err().to_string().contains("no checksum"));
}

// Permissions

#[test]
fn each_missing_permission_stops_setup_before_any_change() {
    for missing in ALL_PERMS {
        let perms: Vec<&str> = ALL_PERMS.iter().copied().filter(|p| p != missing).collect();
        let mut e = env_with_token(API_TOKEN, &perms);
        // Read endpoints also accept the write permission, as in the real API.
        if *missing == DNS_READ || *missing == TUNNEL_READ {
            e.setup().unwrap();
            continue;
        }
        let failure = e.setup().unwrap_err();
        assert!(matches!(failure.error, Error::Permission(_)), "{missing}: {}", failure.error);
        assert_eq!(e.fake.mutation_count(), 0, "{missing}: nothing may change");
        assert!(failure.created.is_empty());
    }
}

#[test]
fn write_probes_change_nothing_and_detect_denial() {
    let e = env_with_token(API_TOKEN, &[ZONE_READ, DNS_READ, TUNNEL_READ]);
    let report = e.keeper.auth_check(Some("example.com")).unwrap();
    let p = report.permissions.unwrap();
    let names: Vec<&str> = p.denied().iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["Cloudflare Tunnel Edit", "DNS Edit"]);
    assert_eq!(e.fake.mutation_count(), 0);
}

#[test]
fn full_token_passes_all_probes_without_writes() {
    let e = env();
    let report = e.keeper.auth_check(Some("example.com")).unwrap();
    let p = report.permissions.unwrap();
    assert_eq!(p.checks.len(), 5);
    assert!(p.checks.iter().all(|c| c.result == Probe::Allowed), "{:?}", p.checks);
    assert_eq!(e.fake.mutation_count(), 0);
}

#[test]
fn inactive_token_is_refused() {
    let mut e = env();
    e.fake.set_token_status(API_TOKEN, "expired");
    assert!(matches!(e.setup().unwrap_err().error, Error::Auth(_)));
}

#[test]
fn unknown_token_is_refused() {
    let mut e = env();
    let (fake, paths) = (&e.fake, e.paths.clone());
    e.keeper = keeper_with_token(fake, &paths, &e.services, &e.probes, &e.ops, &e.decline, "wrong");
    let error = e.setup().unwrap_err().error;
    assert!(matches!(error, Error::Permission(_) | Error::Auth(_)), "{error}");
    assert_eq!(e.fake.mutation_count(), 0);
}

#[test]
fn account_owned_token_works() {
    let mut e = env();
    e.fake.add_account_token("acct-token", ALL_PERMS);
    let (fake, paths) = (&e.fake, e.paths.clone());
    e.keeper = keeper_with_token(fake, &paths, &e.services, &e.probes, &e.ops, &e.decline, "acct-token");
    e.setup().unwrap();
    e.assert_fully_set_up();
}

#[test]
fn login_removes_stray_whitespace_from_a_paste() {
    let e = env();
    for pasted in [format!("{API_TOKEN} "), format!(" {API_TOKEN}\r\n"), format!("\t{API_TOKEN}\n")] {
        assert_eq!(e.keeper.auth_login(Secret::new(pasted), None).unwrap().token_status, "active");
    }
}

#[test]
fn bad_pastes_are_refused_clearly_and_not_echoed() {
    let e = env();
    let calls = e.fake.calls().len();
    for (pasted, words) in [("   ", "empty"), ("two parts-private", "spaces"), ("caf\u{e9}-private", "spaces")] {
        let error = e.keeper.auth_login(Secret::new(pasted), None).unwrap_err().to_string();
        assert!(error.contains(words), "{error}");
        assert!(!error.contains("private"), "{error}");
    }
    assert_eq!(e.fake.calls().len(), calls, "a bad paste is never sent to Cloudflare");
}

#[test]
fn login_only_stores_active_tokens() {
    let e = env();
    e.fake.add_token("dead", ALL_PERMS);
    e.fake.set_token_status("dead", "disabled");
    assert!(e.keeper.auth_login(Secret::new("dead"), None).is_err());
    let report = e.keeper.auth_login(Secret::new(API_TOKEN), Some("example.com")).unwrap();
    assert_eq!(report.stored_in.as_deref(), Some("memory"));
}

// Tunnel lookups

#[test]
fn existing_tunnel_is_adopted_not_duplicated() {
    let mut e = env();
    let id = e.fake.add_tunnel("web", "cloudflare");
    e.setup().unwrap();
    assert_eq!(e.fake.tunnels().len(), 1);
    assert_eq!(e.keeper.config().tunnels[0].id, id);
}

#[test]
fn adopted_tunnel_is_not_deleted_by_rollback() {
    let mut e = env();
    e.fake.add_tunnel("web", "cloudflare");
    let run = e.setup().unwrap().run_id.unwrap();
    e.rollback(&run);
    assert_eq!(e.fake.tunnels().len(), 1, "it existed before this run");
    assert!(e.fake.dns(&e.zone).is_empty());
}

#[test]
fn two_tunnels_with_the_name_stop_setup() {
    let mut e = env();
    e.fake.add_tunnel("web", "cloudflare");
    e.fake.add_tunnel("web", "cloudflare");
    assert!(matches!(e.setup().unwrap_err().error, Error::Conflict(_)));
    assert_eq!(e.fake.mutation_count(), 0);
}

#[test]
fn locally_managed_tunnel_is_refused() {
    let mut e = env();
    e.fake.add_tunnel("web", "local");
    assert!(e.setup().unwrap_err().error.to_string().contains("locally managed"));
}

#[test]
fn tunnel_deleted_remotely_is_recreated() {
    let mut e = env();
    e.setup().unwrap();
    let old = e.keeper.config().tunnels[0].id.clone();
    e.fake.set_connected(&old, false);
    let plan = e.keeper.plan(PlanKind::DeleteTunnel { name: "web".into(), zone: None, include_unmanaged_dns: false }).unwrap();
    e.keeper.apply(plan.confirm("web").unwrap()).unwrap();
    e.setup().unwrap();
    assert_ne!(e.keeper.config().tunnels[0].id, old);
    e.assert_fully_set_up();
}

#[test]
fn listing_pages_through_many_tunnels() {
    let mut e = env();
    for i in 0..250 {
        e.fake.add_tunnel(&format!("t{i}"), "cloudflare");
    }
    e.setup().unwrap();
    let rows = e.keeper.tunnel_list(None).unwrap();
    assert_eq!(rows.len(), 251);
    assert_eq!(rows.iter().filter(|r| r.managed_here).count(), 1);
}

// DNS conflicts

#[test]
fn foreign_dns_record_stops_setup_until_approved() {
    let mut e = env();
    e.fake.add_dns(&e.zone, "A", HOST, "192.0.2.1", Some("my server"));
    let failure = e.setup().unwrap_err();
    match &failure.error {
        Error::DnsConflict { hostname, records } => {
            assert_eq!(hostname, HOST);
            assert_eq!(records[0].content, "192.0.2.1");
        }
        other => panic!("{other}"),
    }
    assert_eq!(e.fake.dns(&e.zone)[0]["content"], "192.0.2.1", "the record is untouched");
    let run = failure.run_id.unwrap();
    e.keeper.resume(&run, &[HOST.to_string()], &mut |_| {}).unwrap();
    e.assert_fully_set_up();
}

#[test]
fn rollback_restores_a_replaced_record() {
    let mut e = env();
    e.fake.add_dns(&e.zone, "A", HOST, "192.0.2.1", Some("my server"));
    let run = e.setup().unwrap_err().run_id.unwrap();
    e.keeper.resume(&run, &[HOST.to_string()], &mut |_| {}).unwrap();
    e.rollback(&run);
    let dns = e.fake.dns(&e.zone);
    assert_eq!(dns.len(), 1);
    assert_eq!(dns[0]["type"], "A");
    assert_eq!(dns[0]["content"], "192.0.2.1");
    assert_eq!(dns[0]["comment"], "my server");
}

#[test]
fn correct_existing_record_is_kept() {
    let mut e = env();
    let id = e.fake.add_tunnel("web", "cloudflare");
    let record = e.fake.add_dns(&e.zone, "CNAME", HOST, &format!("{id}.cfargotunnel.com"), None);
    e.setup().unwrap();
    assert_eq!(e.fake.dns(&e.zone)[0]["id"], record);
}

// Routes

#[test]
fn route_changes_keep_rules_from_elsewhere() {
    let mut e = env();
    let id = e.fake.add_tunnel("web", "cloudflare");
    e.fake.set_ingress(&id, json!([
        {"hostname": "dash.example.com", "service": "http://localhost:9000", "originRequest": {"noTLSVerify": true}},
        {"service": "http_status:503"}
    ]));
    e.setup().unwrap();
    let rules = e.fake.ingress(&id);
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0]["originRequest"]["noTLSVerify"], true);
    assert_eq!(rules[2]["service"], "http_status:503", "their catch all is kept, and stays last");

    let plan = e.keeper.plan(PlanKind::RemoveRoute { hostname: HOST.into(), tunnel: None, include_unmanaged_dns: false }).unwrap();
    e.keeper.apply(plan.confirm(HOST).unwrap()).unwrap();
    let rules = e.fake.ingress(&id);
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["hostname"], "dash.example.com");
    assert!(e.fake.dns(&e.zone).is_empty());
    assert!(e.keeper.config().tunnels[0].routes.is_empty());
}

#[test]
fn changing_a_port_updates_the_rule_and_rollback_restores_it() {
    let mut e = env();
    e.setup().unwrap();
    let mut r = request();
    r.routes[0].service = "4000".into();
    let report = e.keeper.reconcile(r, &mut |_| {}).unwrap();
    let id = e.fake.tunnels()[0]["id"].as_str().unwrap().to_string();
    assert_eq!(e.fake.ingress(&id)[0]["service"], "http://localhost:4000");
    assert_eq!(e.keeper.config().tunnels[0].routes[0].service, "http://localhost:4000");
    e.rollback(&report.run_id.unwrap());
    assert_eq!(e.fake.ingress(&id)[0]["service"], "http://localhost:3000");
}

#[test]
fn self_signed_origin_option_is_set_and_rerun_is_idempotent() {
    let mut e = env();
    let mut r = request();
    r.routes[0].service = "https://localhost:8443".into();
    r.routes[0].no_tls_verify = true;
    e.keeper.reconcile(r.clone(), &mut |_| {}).unwrap();
    let id = e.fake.tunnels()[0]["id"].as_str().unwrap().to_string();
    assert_eq!(e.fake.ingress(&id)[0]["originRequest"]["noTLSVerify"], true);
    let writes = e.fake.mutation_count();
    assert!(!e.keeper.reconcile(r, &mut |_| {}).unwrap().changed);
    assert_eq!(e.fake.mutation_count(), writes);
}

#[test]
fn turning_on_the_option_for_an_existing_route_updates_it() {
    let mut e = env();
    let mut r = request();
    r.routes[0].service = "https://localhost:8443".into();
    e.keeper.reconcile(r.clone(), &mut |_| {}).unwrap();
    r.routes[0].no_tls_verify = true;
    assert!(e.keeper.reconcile(r, &mut |_| {}).unwrap().changed);
    let id = e.fake.tunnels()[0]["id"].as_str().unwrap().to_string();
    assert_eq!(e.fake.ingress(&id)[0]["originRequest"]["noTLSVerify"], true);
}

#[test]
fn hostname_in_another_zone_uses_that_zone() {
    let mut e = env();
    let other = e.fake.add_zone("dev.example.com");
    let mut r = request();
    r.routes[0].hostname = "x.dev.example.com".into();
    e.keeper.reconcile(r, &mut |_| {}).unwrap();
    assert_eq!(e.fake.dns(&other).len(), 1, "the longest matching zone wins");
    assert!(e.fake.dns(&e.zone).is_empty());
}

#[test]
fn deep_hostname_gets_a_certificate_warning() {
    let mut e = env();
    let mut r = request();
    r.routes[0].hostname = "a.b.example.com".into();
    let report = e.keeper.reconcile(r, &mut |_| {}).unwrap();
    assert!(report.steps.iter().any(|s| s.status == StepStatus::Warning && s.detail.contains("Universal SSL")));
}

#[test]
fn bad_input_is_refused_before_any_network_write() {
    for (name, host, target) in [("Bad Name", HOST, "3000"), ("web", "nodots", "3000"), ("web", HOST, "not a target")] {
        let mut e = env();
        let r = SetupRequest { tunnel: name.into(), routes: vec![RouteRequest { hostname: host.into(), service: target.into(), no_tls_verify: false }], install_service: false, zone: None, replace_dns: vec![] };
        assert!(e.keeper.reconcile(r, &mut |_| {}).is_err());
        assert_eq!(e.fake.mutation_count(), 0);
    }
}

// Deletion safety

fn delete_kind() -> PlanKind {
    PlanKind::DeleteTunnel { name: "web".into(), zone: None, include_unmanaged_dns: false }
}

#[test]
fn delete_lists_everything_and_needs_the_exact_name() {
    let mut e = env();
    e.setup().unwrap();
    let plan = e.keeper.plan(delete_kind()).unwrap();
    assert_eq!(plan.confirm_phrase, "web");
    assert!(matches!(plan.actions[0], Action::UninstallService { .. }), "service goes first");
    assert!(plan.actions.iter().any(|a| matches!(a, Action::DeleteDnsRecord { .. })));
    assert!(plan.actions.iter().any(|a| matches!(a, Action::DeleteTunnel { .. })));
    assert!(plan.clone().confirm("yes").is_err());
    assert!(plan.clone().confirm("WEB").is_err());
    assert_eq!(e.fake.tunnels().len(), 1, "planning deleted nothing");
    let before = e.fake.mutation_count();
    let confirmed = plan.confirm("web").unwrap();
    assert_eq!(e.fake.mutation_count(), before);
    e.keeper.apply(confirmed).unwrap();
    e.assert_clean();
}

#[test]
fn stale_plan_deletes_nothing() {
    let mut e = env();
    e.setup().unwrap();
    let plan = e.keeper.plan(delete_kind()).unwrap();
    let confirmed = plan.confirm("web").unwrap();
    let extra = e.fake.add_dns(&e.zone, "TXT", HOST, "new record", None);
    let before = e.fake.mutation_count();
    let result = e.keeper.apply(confirmed);
    assert!(matches!(result, Err(Error::StalePlan(_))));
    assert_eq!(e.fake.mutation_count(), before);
    assert_eq!(e.fake.tunnels().len(), 1);
    assert!(e.fake.dns(&e.zone).iter().any(|r| r["id"] == extra));
}

#[test]
fn records_we_did_not_create_are_kept_unless_asked() {
    let mut e = env();
    let id = e.fake.add_tunnel("web", "cloudflare");
    e.fake.add_dns(&e.zone, "CNAME", HOST, &format!("{id}.cfargotunnel.com"), Some("made by hand"));
    e.setup().unwrap();
    let plan = e.keeper.plan(delete_kind()).unwrap();
    assert_eq!(plan.kept.len(), 1);
    assert!(!plan.actions.iter().any(|a| matches!(a, Action::DeleteDnsRecord { .. })));
    e.keeper.apply(plan.confirm("web").unwrap()).unwrap();
    assert_eq!(e.fake.dns(&e.zone).len(), 1);

    let mut e = env();
    let id = e.fake.add_tunnel("web", "cloudflare");
    e.fake.add_dns(&e.zone, "CNAME", HOST, &format!("{id}.cfargotunnel.com"), Some("made by hand"));
    e.setup().unwrap();
    let plan = e.keeper.plan(PlanKind::DeleteTunnel { name: "web".into(), zone: None, include_unmanaged_dns: true }).unwrap();
    e.keeper.apply(plan.confirm("web").unwrap()).unwrap();
    assert!(e.fake.dns(&e.zone).is_empty());
}

#[test]
fn delete_clears_active_connections_first() {
    let mut e = env();
    e.setup().unwrap();
    let id = e.keeper.config().tunnels[0].id.clone();
    e.fake.set_connected(&id, true);
    let plan = e.keeper.plan(delete_kind()).unwrap();
    let report = e.keeper.apply(plan.confirm("web").unwrap()).unwrap();
    assert!(report.ok(), "{report:?}");
    e.assert_clean();
}

#[test]
fn delete_retries_while_connections_linger() {
    let mut e = env();
    e.setup().unwrap();
    e.fake.set_sticky_connections(2);
    let plan = e.keeper.plan(delete_kind()).unwrap();
    let report = e.keeper.apply(plan.confirm("web").unwrap()).unwrap();
    assert!(report.ok(), "{report:?}");
    assert!(e.fake.tunnels().is_empty());
}

#[test]
fn delete_reports_partial_failure_and_can_be_repeated() {
    let mut e = env();
    e.setup().unwrap();
    e.fake.set_sticky_connections(50);
    let plan = e.keeper.plan(delete_kind()).unwrap();
    let report = e.keeper.apply(plan.confirm("web").unwrap()).unwrap();
    assert!(!report.ok());
    assert!(!report.done.is_empty());
    assert!(report.failed.as_ref().unwrap().contains("DELETE tunnel"));
    assert_eq!(report.not_attempted.len(), 1);
    assert_eq!(e.keeper.config().tunnels.len(), 1, "still known, so the delete can be retried");
    e.fake.set_sticky_connections(0);
    let plan = e.keeper.plan(delete_kind()).unwrap();
    assert!(e.keeper.apply(plan.confirm("web").unwrap()).unwrap().ok());
    e.assert_clean();
}

#[test]
fn tunnel_outside_the_config_can_be_deleted_with_a_zone() {
    let mut e = env();
    e.fake.add_tunnel("old", "cloudflare");
    let kind = PlanKind::DeleteTunnel { name: "old".into(), zone: None, include_unmanaged_dns: false };
    assert!(e.keeper.plan(kind).is_err());
    let kind = PlanKind::DeleteTunnel { name: "old".into(), zone: Some("example.com".into()), include_unmanaged_dns: false };
    let plan = e.keeper.plan(kind).unwrap();
    e.keeper.apply(plan.confirm("old").unwrap()).unwrap();
    assert!(e.fake.tunnels().is_empty());
}

// Health

#[test]
fn status_tells_the_three_states_apart() {
    let mut e = env();
    e.setup().unwrap();
    let id = e.keeper.config().tunnels[0].id.clone();
    e.fake.set_connected(&id, true);
    assert_eq!(e.keeper.status(None).unwrap().state, TunnelState::Healthy);

    e.probes.set_origin("http://localhost:3000", OriginProbe::NotResponding("refused".into()));
    let s = e.keeper.status(None).unwrap();
    assert_eq!(s.state, TunnelState::OriginDown);
    assert!(s.message.contains("app.example.com"));

    e.probes.set_ready(ReadyProbe::NotReady);
    assert_eq!(e.keeper.status(None).unwrap().state, TunnelState::TunnelDown);

    e.services.set_state(SERVICE, ServiceState::Stopped);
    let s = e.keeper.status(None).unwrap();
    assert_eq!(s.state, TunnelState::ServiceStopped);
    assert!(s.message.contains("connector"), "the stale connector is mentioned");
}

#[test]
fn status_survives_an_unreachable_api() {
    let mut e = env();
    e.setup().unwrap();
    e.fake.set_token_status(API_TOKEN, "active");
    let paths = e.paths.clone();
    let dead = FakeCloudflare::spawn();
    let keeper = keeper_with_token(&dead, &paths, &e.services, &e.probes, &e.ops, &e.decline, "nobody");
    let s = keeper.status(None).unwrap();
    assert_eq!(s.state, TunnelState::Healthy, "local checks still work");
    assert!(s.remote.is_none());
    assert!(s.remote_error.is_some());
}

#[test]
fn degraded_comes_from_cloudflare() {
    let mut e = env();
    e.setup().unwrap();
    let id = e.keeper.config().tunnels[0].id.clone();
    e.fake.set_tunnel_status(&id, "degraded");
    assert_eq!(e.keeper.status(None).unwrap().state, TunnelState::Degraded);
}

// Doctor

fn finding_ids(e: &Env) -> Vec<String> {
    e.keeper.doctor().into_iter().filter(|f| f.severity >= Severity::Warning).map(|f| f.id).collect()
}

#[test]
fn doctor_is_quiet_when_all_is_well() {
    let mut e = env();
    e.setup().unwrap();
    // The fake sets no file permissions, so the token file really is readable.
    let ids: Vec<String> = finding_ids(&e).into_iter().filter(|i| i != "web.token.acl").collect();
    assert_eq!(ids, Vec::<String>::new());
}

#[test]
fn doctor_flags_a_token_file_this_user_can_read() {
    let mut e = env();
    e.setup().unwrap();
    if !tunnelkeeper_core::privileged::is_elevated() {
        assert!(finding_ids(&e).contains(&"web.token.acl".to_string()));
    }
}

#[test]
fn doctor_finds_common_problems() {
    let mut e = env();
    e.setup().unwrap();
    let id = e.keeper.config().tunnels[0].id.clone();

    e.probes.set_network(true, false);
    assert!(finding_ids(&e).contains(&"network.port".to_string()));
    e.probes.set_network(false, false);
    assert!(finding_ids(&e).contains(&"network.dns".to_string()));
    e.probes.set_network(true, true);

    e.probes.set_origin("http://localhost:3000", OriginProbe::NotResponding("refused".into()));
    assert!(finding_ids(&e).contains(&"web.origin".to_string()));
    e.probes.set_origin("http://localhost:3000", OriginProbe::Responding);

    e.fake.set_ingress(&id, json!([{"service": "http_status:404"}]));
    assert!(finding_ids(&e).contains(&"web.drift.ingress".to_string()));
    e.fake.set_ingress(&id, json!([{"hostname": HOST, "service": "http://localhost:3000"}, {"service": "http_status:404"}]));

    e.probes.set_ready(ReadyProbe::NotReady);
    assert!(finding_ids(&e).contains(&"web.tunnel.down".to_string()));
    e.probes.set_ready(ReadyProbe::Ready { connections: 4, connector_id: None });

    e.services.set_state(SERVICE, ServiceState::Stopped);
    e.probes.set_port_busy(20301);
    let ids = finding_ids(&e);
    assert!(ids.contains(&"web.service.stopped".to_string()));
    assert!(ids.contains(&"web.metrics.port".to_string()));
    e.services.set_state(SERVICE, ServiceState::Running);

    std::fs::remove_file(e.paths.tunnel_token("web")).unwrap();
    assert!(finding_ids(&e).contains(&"web.token.file".to_string()));
}

#[test]
fn doctor_reads_a_crash_loop_from_the_log() {
    let mut e = env();
    e.setup().unwrap();
    e.probes.set_ready(ReadyProbe::NotReady);
    assert!(finding_ids(&e).contains(&"web.tunnel.down".to_string()), "one bad moment is not a loop");

    // These lines are the format captured from real cloudflared 2026.3.0.
    let shutdown = r#"{"level":"error","error":"Failed to get tunnel","time":"2026-11-05T16:37:02Z","message":"Initiating shutdown"}"#;
    let start = r#"{"level":"info","tunnelID":"x","time":"2026-11-05T16:37:32Z","message":"Starting tunnel"}"#;
    let dir = e.paths.log_dir("web");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cloudflared.log"), format!("{shutdown}
{start}
{shutdown}
{start}
")).unwrap();
    let findings = e.keeper.doctor();
    let f = findings.iter().find(|f| f.id == "web.service.crashloop").expect("crash loop found");
    assert!(f.message.contains("Failed to get tunnel"), "{}", f.message);
}

#[test]
fn doctor_flags_a_service_outside_the_protected_folder() {
    let mut e = env();
    e.setup().unwrap();
    let safe = e.services.command_line(SERVICE).unwrap();
    assert!(safe.contains("cloudflared"));
    std::fs::write(fake_binary(&e.paths), "2024.1.0").unwrap();
    assert!(finding_ids(&e).contains(&"cloudflared.old".to_string()));
}

#[test]
fn doctor_without_a_token_still_runs_local_checks() {
    let mut e = env();
    e.setup().unwrap();
    let paths = e.paths.clone();
    let k = Keeper::open(Deps {
        paths: paths.clone(),
        secrets: Box::new(MemoryStore::default()),
        services: Box::new(e.services.clone()),
        elevator: Box::new(InlineElevator { paths, services: e.services.clone(), ops: e.ops.clone(), decline: e.decline.clone() }),
        probes: Box::new(e.probes.clone()),
        locate: fake_locate,
        api_base: e.fake.base_url(),
        release_base: e.fake.release_base(),
        env_token: None,
        verify_timeout: Duration::from_millis(50),
        poll_interval: Duration::from_millis(10),
        delete_attempts: 1,
        delete_retry_delay: Duration::ZERO,
        crash_sample: Duration::ZERO,
    })
    .unwrap();
    let findings = k.doctor();
    assert!(findings.iter().any(|f| f.id == "token.missing"));
    assert!(findings.iter().any(|f| f.id == "web.tunnel"));
}

// Client behaviour

#[test]
fn rate_limits_and_server_errors_on_reads_are_retried() {
    let mut e = env();
    e.fake.rate_limit_next(2);
    e.setup().unwrap();
    e.assert_fully_set_up();
    e.fake.server_error_next(1);
    e.keeper.tunnel_list(None).unwrap();
}

#[test]
fn writes_are_not_blindly_retried() {
    let mut e = env();
    e.fake.fail_mutation(1);
    e.setup().unwrap_err();
    let posts = e.fake.calls().iter().filter(|c| c.starts_with("POST") && c.ends_with("/cfd_tunnel")).count();
    assert_eq!(posts, 1, "a retry could create a duplicate");
}

// Secrets

#[test]
fn tunnel_token_stays_out_of_every_user_level_file_and_report() {
    let mut e = env();
    let report = e.setup().unwrap();
    let token_file = std::fs::read_to_string(e.paths.tunnel_token("web")).unwrap();
    assert!(token_file.contains(TUNNEL_TOKEN_MARKER), "the token did reach the protected file");

    let mut haystack = serde_json::to_string(&report).unwrap();
    haystack.push_str(&serde_json::to_string(&e.keeper.status(None).unwrap()).unwrap());
    haystack.push_str(&serde_json::to_string(&e.keeper.doctor()).unwrap());
    haystack.push_str(&serde_json::to_string(&e.keeper.runs().unwrap()).unwrap());
    haystack.push_str(&e.services.command_line(SERVICE).unwrap());
    for dir in [&e.paths.config_dir, &e.paths.cache_dir] {
        collect_text(dir, &mut haystack);
    }
    assert!(!haystack.contains(TUNNEL_TOKEN_MARKER), "tunnel token leaked");
    assert!(!haystack.contains(API_TOKEN), "API token leaked");
}

fn collect_text(dir: &std::path::Path, out: &mut String) {
    for item in std::fs::read_dir(dir).unwrap().flatten() {
        let p = item.path();
        if p.is_dir() {
            collect_text(&p, out);
        } else if let Ok(t) = std::fs::read_to_string(&p) {
            out.push_str(&t);
        }
    }
}

#[test]
fn errors_do_not_contain_tokens() {
    let mut e = env();
    e.fake.fail_mutation(1);
    let failure = e.setup().unwrap_err();
    let text = format!("{} {:?}", failure.error, failure.error);
    assert!(!text.contains(API_TOKEN));
}

#[test]
fn logs_are_scrubbed() {
    let mut e = env();
    e.setup().unwrap();
    let dir = e.paths.log_dir("web");
    std::fs::create_dir_all(&dir).unwrap();
    let line = format!(
        "INF ok\nERR bad token {API_TOKEN}\nERR run --token eyJhIjoiNWFiNGU5ZDEyMyIsInQiOiJ4eXoifQ\nINF connected location=ams01\n"
    );
    std::fs::write(dir.join("cloudflared.log"), line).unwrap();
    let lines = e.keeper.logs_tail(None, 3).unwrap();
    assert_eq!(lines.len(), 3, "only the requested tail");
    let all = lines.join("\n");
    assert!(!all.contains(API_TOKEN));
    assert!(!all.contains("eyJhIjoi"));
    assert!(all.contains("location=ams01"));
}

#[test]
fn cloudflared_json_logs_become_readable_and_stay_scrubbed() {
    let line = r#"{"level":"error","event":0,"error":"control stream failed","time":"2026-11-05T16:12:59Z","message":"Serve tunnel error"}"#;
    assert_eq!(
        tunnelkeeper_core::format_log_line(line),
        "2026-11-05T16:12:59Z ERROR Serve tunnel error: control stream failed"
    );
    assert_eq!(tunnelkeeper_core::format_log_line("plain text"), "plain text");
    assert_eq!(tunnelkeeper_core::format_log_line("{\"other\":1}"), "{\"other\":1}");

    let mut e = env();
    e.setup().unwrap();
    let dir = e.paths.log_dir("web");
    std::fs::create_dir_all(&dir).unwrap();
    let secret = format!(r#"{{"level":"error","time":"t","message":"bad {API_TOKEN}"}}"#);
    std::fs::write(dir.join("cloudflared.log"), secret).unwrap();
    assert!(!e.keeper.logs_tail(None, 5).unwrap().join("").contains(API_TOKEN));
}

#[test]
fn log_follow_reads_only_new_lines_and_handles_rotation() {
    let mut e = env();
    e.setup().unwrap();
    let dir = e.paths.log_dir("web");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("cloudflared.log");
    std::fs::write(&file, "one\ntwo\n").unwrap();
    let (first, offset) = e.keeper.logs_since(None, 0).unwrap();
    assert_eq!(first, ["one", "two"]);
    std::fs::write(&file, "one\ntwo\nthree\n").unwrap();
    let (next, offset) = e.keeper.logs_since(None, offset).unwrap();
    assert_eq!(next, ["three"]);
    std::fs::write(&file, "new\n").unwrap();
    let (rotated, _) = e.keeper.logs_since(None, offset).unwrap();
    assert_eq!(rotated, ["new"]);
}

#[test]
fn missing_log_file_is_empty_not_an_error() {
    let mut e = env();
    e.setup().unwrap();
    assert!(e.keeper.logs_tail(None, 10).unwrap().is_empty());
}
