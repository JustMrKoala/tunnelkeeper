//! Text output. Nothing here decides anything.

use tunnelkeeper_core::AuthReport;
use tunnelkeeper_core::RouteRow;
use tunnelkeeper_core::TunnelRow;
use tunnelkeeper_core::cloudflare::Probe;
use tunnelkeeper_core::cloudflared::CloudflaredStatus;
use tunnelkeeper_core::doctor::{Finding, Severity};
use tunnelkeeper_core::error::Error;
use tunnelkeeper_core::health::{OriginProbe, ReadyProbe, TunnelStatus};
use tunnelkeeper_core::journal::Journal;
use tunnelkeeper_core::plan::{ApplyReport, Plan};
use tunnelkeeper_core::setup::{SetupFailure, SetupReport, StepReport, StepStatus};

pub fn step(s: &StepReport) {
    let mark = match s.status {
        StepStatus::Unchanged => "[ok]     ",
        StepStatus::Changed => "[change] ",
        StepStatus::Warning => "[warn]   ",
    };
    println!("{mark}{}", s.detail);
}

pub fn step_fn(s: &StepReport) {
    step(s);
}

pub fn setup_done(r: &SetupReport) {
    if !r.changed {
        println!("\nNothing needed changing.");
    } else if let Some(id) = &r.run_id {
        println!("\nDone. Run ID: {id}");
    }
    if let Some(h) = &r.health {
        println!("{:?}: {}", h.state, h.message);
    }
}

pub fn setup_failed(f: &SetupFailure, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(&f.view()).expect("json"));
        return;
    }
    eprintln!("\nSetup stopped at step \"{}\": {}", f.step, f.error);
    if let Error::DnsConflict { records, .. } = &f.error {
        for r in records {
            eprintln!("  existing record: {} {} {} (comment: {})", r.record_type, r.name, r.content, r.comment.as_deref().unwrap_or("none"));
        }
    }
    if f.created.is_empty() {
        eprintln!("This run created nothing.");
    } else {
        eprintln!("Created by this run:");
        for e in &f.created {
            eprintln!("  {}", e.resource.describe());
        }
    }
    if !f.unknown.is_empty() {
        eprintln!("Outcome unknown, may or may not exist:");
        for e in &f.unknown {
            eprintln!("  {}", e.resource.describe());
        }
    }
    if let Some(id) = &f.run_id {
        eprintln!("To continue:  tunnelkeeper setup --resume {id}");
        if !f.created.is_empty() || !f.unknown.is_empty() {
            eprintln!("To undo:      tunnelkeeper setup --rollback {id}");
        }
    }
}

pub fn plan(p: &Plan) {
    println!("{}", p.summary);
    if p.actions.is_empty() {
        println!("  Nothing to do.");
    }
    for (i, a) in p.actions.iter().enumerate() {
        println!("  {}. {}", i + 1, a.describe());
    }
    for k in &p.kept {
        println!("  Kept: {k}");
    }
    for w in &p.warnings {
        println!("  Warning: {w}");
    }
}

pub fn apply(r: &ApplyReport) {
    for d in &r.done {
        println!("[done]   {d}");
    }
    if let Some(f) = &r.failed {
        println!("[failed] {f}");
    }
    for n in &r.not_attempted {
        println!("[skipped] {n}");
    }
}

pub fn runs(runs: &[Journal]) {
    if runs.is_empty() {
        println!("No runs recorded.");
    }
    for j in runs {
        println!("{}  {:?}  tunnel {}", j.id, j.status, j.request.tunnel);
        for e in j.created() {
            println!("    created: {}", e.resource.describe());
        }
        for e in j.unknown() {
            println!("    unknown: {}", e.resource.describe());
        }
    }
}

pub fn auth(r: &AuthReport) {
    println!("Token status: {}", r.token_status);
    if let Some(s) = &r.stored_in {
        println!("Stored in: {s}");
    }
    match &r.permissions {
        Some(p) => {
            for c in &p.checks {
                let result = match &c.result {
                    Probe::Allowed => "ok".to_string(),
                    Probe::Denied => "MISSING".to_string(),
                    Probe::Unknown(why) => format!("unknown ({why})"),
                };
                println!("  {:<24} {result}", c.name);
            }
        }
        None => println!("Pass --zone example.com to check permissions."),
    }
}

pub fn cloudflared(s: &CloudflaredStatus) {
    match (&s.path, &s.version) {
        (Some(p), Some(v)) => {
            println!("cloudflared {v} at {}", p.display());
            if !s.meets_minimum {
                println!("This is older than the required {}", s.minimum);
            }
            if s.via_shim {
                println!("Found through a launcher. Services will use a protected copy.");
            }
        }
        _ => println!("cloudflared was not found. Run: tunnelkeeper cloudflared install"),
    }
}

pub fn tunnels(rows: &[TunnelRow]) {
    if rows.is_empty() {
        println!("No tunnels.");
    }
    for r in rows {
        let here = if r.managed_here { "managed here" } else { "not managed here" };
        println!("{:<24} {}  {:<9} {here}", r.name, r.id, r.status.as_deref().unwrap_or("unknown"));
    }
}

pub fn routes(rows: &[RouteRow]) {
    if rows.is_empty() {
        println!("No routes.");
    }
    for r in rows {
        println!("{:<32} {:<28} tunnel {}", r.hostname, r.service, r.tunnel);
    }
}

pub fn status(all: &[TunnelStatus]) {
    if all.is_empty() {
        println!("No tunnels configured. Run: tunnelkeeper setup");
    }
    for s in all {
        println!("Tunnel {} ({})", s.name, s.id);
        println!("  State:   {:?}", s.state);
        println!("  {}", s.message);
        println!("  Service: {} is {:?}", s.service.name, s.service.state);
        match &s.ready {
            ReadyProbe::Ready { connections, .. } => println!("  Local:   {connections} edge connections"),
            ReadyProbe::NotReady => println!("  Local:   no edge connections"),
            ReadyProbe::Unreachable => println!("  Local:   metrics port not answering"),
        }
        match (&s.remote, &s.remote_error) {
            (Some(r), _) => println!("  Remote:  {} with {} connectors", r.status.as_deref().unwrap_or("unknown"), r.connectors),
            (None, Some(e)) => println!("  Remote:  unknown, {e}"),
            _ => {}
        }
        for r in &s.routes {
            let origin = match &r.origin {
                OriginProbe::Responding => "responding".to_string(),
                OriginProbe::NotResponding(why) => format!("NOT RESPONDING: {why}"),
                OriginProbe::Unchecked(why) => format!("not checked: {why}"),
            };
            println!("  Route:   {} to {} ({origin})", r.hostname, r.service);
        }
    }
}

pub fn doctor(findings: &[Finding]) {
    for f in findings {
        let mark = match f.severity {
            Severity::Ok => "[ok]   ",
            Severity::Info => "[info] ",
            Severity::Warning => "[warn] ",
            Severity::Error => "[FAIL] ",
        };
        println!("{mark}{}", f.message);
        if let Some(fix) = &f.fix {
            println!("       Fix: {fix}");
        }
    }
}
