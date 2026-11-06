//! Runs the real binary against the fake API. No service is touched here:
//! every command uses --no-service or only reads service state.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use fake_cloudflare::*;

const API_TOKEN: &str = "cli-test-api-token-value";
const HOST: &str = "app.example.com";

struct Cli {
    fake: FakeCloudflare,
    zone: String,
    home: PathBuf,
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn cli() -> Cli {
    let fake = FakeCloudflare::spawn();
    fake.add_token(API_TOKEN, ALL_PERMS);
    let zone = fake.add_zone("example.com");
    let home = std::env::temp_dir().join(format!("tk-cli-{}-{:?}", std::process::id(), std::thread::current().id()).replace(['(', ')'], ""));
    let _ = std::fs::remove_dir_all(&home);
    Cli { fake, zone, home }
}

impl Cli {
    fn run_with_token(&self, args: &[&str], token: Option<&str>) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_tunnelkeeper"));
        c.args(args)
            .env("TUNNELKEEPER_HOME", &self.home)
            .env("TUNNELKEEPER_API_BASE", self.fake.base_url())
            .env_remove("CLOUDFLARE_API_TOKEN")
            .stdin(Stdio::null());
        if let Some(t) = token {
            c.env("CLOUDFLARE_API_TOKEN", t);
        }
        let out = c.output().expect("run tunnelkeeper");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(!text.contains(API_TOKEN), "API token printed by {args:?}");
        assert!(!text.contains(TUNNEL_TOKEN_MARKER), "tunnel token printed by {args:?}");
        out
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with_token(args, Some(API_TOKEN))
    }

    fn setup(&self) -> Output {
        self.run(&["setup", "--name", "web", "--route", "app.example.com=3000", "--no-service"])
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

#[test]
fn setup_rerun_list_and_remove() {
    let c = cli();
    let first = c.setup();
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert!(stdout(&first).contains("created tunnel web"));

    let writes = c.fake.mutation_count();
    let second = c.setup();
    assert_eq!(second.status.code(), Some(0));
    assert!(stdout(&second).contains("Nothing needed changing"));
    assert_eq!(c.fake.mutation_count(), writes);

    let routes = c.run(&["route", "list", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&routes.stdout).unwrap();
    assert_eq!(v[0]["hostname"], HOST);

    let tunnels = c.run(&["tunnel", "list", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&tunnels.stdout).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["managed_here"], true);
}

#[test]
fn status_reports_not_installed_with_exit_code_3() {
    let c = cli();
    c.setup();
    let out = c.run(&["status", "--json"]);
    assert_eq!(out.status.code(), Some(3));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["state"], "NOT_INSTALLED");
}

#[test]
fn deletes_refuse_to_run_unconfirmed_without_a_terminal() {
    let c = cli();
    c.setup();
    let writes = c.fake.mutation_count();

    let out = c.run(&["route", "remove", HOST]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("--confirm"));
    assert!(stdout(&out).contains("DELETE DNS record"), "the plan is shown");

    let out = c.run(&["tunnel", "delete", "web", "--confirm", "wrong"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(c.fake.mutation_count(), writes, "nothing was deleted");
    assert_eq!(c.fake.dns(&c.zone).len(), 1);
}

#[test]
fn confirmed_route_remove_and_tunnel_delete() {
    let c = cli();
    c.setup();
    let out = c.run(&["route", "remove", HOST, "--confirm", HOST]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(c.fake.dns(&c.zone).is_empty());
    let out = c.run(&["tunnel", "delete", "web", "--confirm", "web"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(c.fake.tunnels().is_empty());
}

#[test]
fn failed_setup_reports_what_was_created_with_exit_code_4() {
    let c = cli();
    c.fake.fail_mutation(2);
    let out = c.setup();
    assert_eq!(out.status.code(), Some(4));
    let err = stderr(&out);
    assert!(err.contains("Created by this run"), "{err}");
    assert!(err.contains("tunnel web"), "{err}");
    assert!(err.contains("--resume"), "{err}");
    assert!(err.contains("--rollback"), "{err}");
    c.fake.clear_injection();

    let list = c.run(&["setup", "--list", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let run = v[0]["id"].as_str().unwrap().to_string();

    let out = c.run(&["setup", "--rollback", &run, "--confirm", &run]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(c.fake.tunnels().is_empty());
}

#[test]
fn resume_finishes_a_failed_setup() {
    let c = cli();
    c.fake.fail_mutation(3);
    c.setup();
    c.fake.clear_injection();
    let list = c.run(&["setup", "--list", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let out = c.run(&["setup", "--resume", v[0]["id"].as_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(c.fake.dns(&c.zone).len(), 1);
    assert_eq!(c.fake.tunnels().len(), 1);
}

#[test]
fn dns_conflict_shows_the_record_and_changes_nothing() {
    let c = cli();
    c.fake.add_dns(&c.zone, "A", HOST, "192.0.2.1", Some("my server"));
    let out = c.setup();
    assert_eq!(out.status.code(), Some(4));
    assert!(stderr(&out).contains("192.0.2.1"));
    assert_eq!(c.fake.dns(&c.zone)[0]["content"], "192.0.2.1");
}

#[test]
fn login_without_a_terminal_needs_the_environment_variable() {
    let c = cli();
    let out = c.run_with_token(&["auth", "login"], None);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("CLOUDFLARE_API_TOKEN"));
}

#[test]
fn there_is_no_token_argument() {
    let c = cli();
    let out = c.run(&["auth", "login", "--token", "abc"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn auth_check_prints_a_result_per_permission() {
    let c = cli();
    let out = c.run(&["auth", "check", "--zone", "example.com"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout(&out);
    for name in ["Cloudflare Tunnel Edit", "DNS Edit", "Zone Read"] {
        assert!(text.contains(name), "{text}");
    }
}

#[test]
fn doctor_runs_without_any_config() {
    let c = cli();
    let out = c.run(&["doctor", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.as_array().unwrap().iter().any(|f| f["id"] == "token.active"));
}

#[test]
fn a_non_loopback_api_override_is_ignored() {
    let c = cli();
    let out = Command::new(env!("CARGO_BIN_EXE_tunnelkeeper"))
        .args(["auth", "check"])
        .env("TUNNELKEEPER_HOME", &c.home)
        .env("TUNNELKEEPER_API_BASE", "http://attacker.example/client/v4")
        .env_remove("CLOUDFLARE_API_TOKEN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let text = stderr(&out);
    assert!(text.contains("no API token") || text.contains("token"), "{text}");
    assert!(!text.contains("attacker.example"), "{text}");
}
