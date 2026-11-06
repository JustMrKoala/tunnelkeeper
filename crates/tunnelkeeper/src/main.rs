//! The tunnelkeeper binary. This file only parses arguments, asks questions
//! and renders results. All logic lives in tunnelkeeper-core.

#![allow(clippy::result_large_err)]

mod render;
mod web;

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use tunnelkeeper_core::Keeper;
use tunnelkeeper_core::doctor::Severity;
use tunnelkeeper_core::error::{Error, Result};
use tunnelkeeper_core::health::TunnelState;
use tunnelkeeper_core::plan::PlanKind;
use tunnelkeeper_core::privileged::run_handoff;
use tunnelkeeper_core::secret::Secret;
use tunnelkeeper_core::setup::{RouteRequest, SetupFailure, SetupReport, SetupRequest, StepReport};

const EXIT_ERROR: u8 = 1;
const EXIT_UNHEALTHY: u8 = 3;
const EXIT_PARTIAL: u8 = 4;

#[derive(Parser)]
#[command(name = "tunnelkeeper", version, about = "Creates and manages permanent Cloudflare Tunnels")]
struct Cli {
    /// Print machine readable JSON
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the full setup flow. Safe to run again
    Setup(SetupArgs),
    /// Manage the Cloudflare API token
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Check or download cloudflared
    Cloudflared {
        #[command(subcommand)]
        command: CloudflaredCommand,
    },
    /// Create, list and delete tunnels
    Tunnel {
        #[command(subcommand)]
        command: TunnelCommand,
    },
    /// Map hostnames to local ports
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
    /// Control the system service
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Show health, service state and routes
    Status {
        #[arg(long)]
        tunnel: Option<String>,
    },
    /// Show recent logs
    Logs {
        #[arg(long)]
        tunnel: Option<String>,
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: usize,
        #[arg(long)]
        follow: bool,
    },
    /// Diagnose common problems and suggest fixes
    Doctor,
    /// Open the local web UI
    Ui {
        /// Port on 127.0.0.1. Defaults to the configured port
        #[arg(long)]
        port: Option<u16>,
        /// Print the address without opening a browser
        #[arg(long)]
        no_open: bool,
    },
    /// Internal: performs one privileged step
    #[command(hide = true)]
    Elevated {
        #[arg(long)]
        handoff: PathBuf,
    },
}

#[derive(Args)]
struct SetupArgs {
    /// Tunnel name
    #[arg(long, required_unless_present_any = ["resume", "rollback", "list"])]
    name: Option<String>,
    /// A route such as app.example.com=3000. Can be repeated
    #[arg(long = "route", value_name = "HOST=PORT_OR_URL")]
    routes: Vec<String>,
    /// Zone used to find the account when no route is given
    #[arg(long)]
    zone: Option<String>,
    /// Skip installing the service
    #[arg(long)]
    no_service: bool,
    /// Continue a failed run
    #[arg(long, value_name = "RUN_ID", conflicts_with_all = ["rollback", "list"])]
    resume: Option<String>,
    /// Undo what a run created
    #[arg(long, value_name = "RUN_ID", conflicts_with = "list")]
    rollback: Option<String>,
    /// List past runs and what each created
    #[arg(long)]
    list: bool,
    /// Required with --rollback when there is no terminal: the run ID
    #[arg(long)]
    confirm: Option<String>,
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Read a token from CLOUDFLARE_API_TOKEN or a hidden prompt, then store it
    Login {
        #[arg(long)]
        zone: Option<String>,
    },
    /// Run all permission probes
    Check {
        #[arg(long)]
        zone: Option<String>,
    },
    /// Delete the stored token
    Logout,
}

#[derive(Subcommand)]
enum CloudflaredCommand {
    Check,
    /// Download the official release and verify its SHA256
    Install {
        #[arg(long)]
        version: Option<String>,
        /// Do not ask before downloading
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum TunnelCommand {
    Create {
        name: String,
        #[arg(long)]
        zone: Option<String>,
    },
    List {
        #[arg(long)]
        zone: Option<String>,
    },
    /// Shows a plan, then asks
    Delete {
        name: String,
        /// Finds a tunnel that is not in the local config
        #[arg(long)]
        zone: Option<String>,
        /// Also delete records pointing here that tunnelkeeper did not create
        #[arg(long)]
        include_unmanaged_dns: bool,
        /// Required when there is no terminal: the tunnel name
        #[arg(long)]
        confirm: Option<String>,
    },
}

#[derive(Subcommand)]
enum RouteCommand {
    Add {
        hostname: String,
        /// A port number or a URL
        target: String,
        #[arg(long)]
        tunnel: Option<String>,
    },
    List {
        #[arg(long)]
        tunnel: Option<String>,
    },
    /// Shows a plan, then asks
    Remove {
        hostname: String,
        #[arg(long)]
        tunnel: Option<String>,
        #[arg(long)]
        include_unmanaged_dns: bool,
        /// Required when there is no terminal: the hostname
        #[arg(long)]
        confirm: Option<String>,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    Install {
        #[arg(long)]
        tunnel: Option<String>,
    },
    Start {
        #[arg(long)]
        tunnel: Option<String>,
    },
    Stop {
        #[arg(long)]
        tunnel: Option<String>,
    },
    /// Removes the local service only. The tunnel stays on Cloudflare
    Uninstall {
        #[arg(long)]
        tunnel: Option<String>,
    },
}

fn print_json<T: Serialize>(value: &T) {
    println!("{}", serde_json::to_string_pretty(value).expect("results serialize"));
}

fn ask(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush().map_err(|e| Error::io("write prompt", e))?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| Error::io("read answer", e))?;
    Ok(line.trim().to_string())
}

fn interactive() -> bool {
    std::io::stdin().is_terminal()
}

/// The token comes from the environment or a hidden prompt, never an argument.
fn read_token() -> Result<Secret> {
    if let Some(t) = std::env::var("CLOUDFLARE_API_TOKEN").ok().filter(|t| !t.is_empty()) {
        return Ok(Secret::new(t));
    }
    if !interactive() {
        return Err(Error::Invalid("set CLOUDFLARE_API_TOKEN, or run this in a terminal to get a hidden prompt".into()));
    }
    rpassword::prompt_password("Cloudflare API token (hidden): ").map(Secret::new).map_err(|e| Error::io("read token", e))
}

fn run_plan(keeper: &mut Keeper, kind: PlanKind, confirm: Option<String>, json: bool) -> Result<u8> {
    let plan = keeper.plan(kind)?;
    let answer = match confirm {
        Some(a) => a,
        None if interactive() => {
            render::plan(&plan);
            ask(&format!("Type {} to confirm: ", plan.confirm_phrase))?
        }
        None => {
            if json {
                print_json(&plan);
            } else {
                render::plan(&plan);
            }
            return Err(Error::Invalid(format!("no terminal to ask on. Review the plan, then rerun with --confirm {}", plan.confirm_phrase)));
        }
    };
    let confirmed = plan.confirm(&answer)?;
    let report = keeper.apply(confirmed)?;
    if json {
        print_json(&report);
    } else {
        render::apply(&report);
    }
    Ok(if report.ok() { 0 } else { EXIT_ERROR })
}

fn finish_setup(keeper: &mut Keeper, first: std::result::Result<SetupReport, SetupFailure>, json: bool) -> Result<u8> {
    let mut outcome = first;
    loop {
        let failure = match outcome {
            Ok(report) => {
                if json {
                    print_json(&report);
                } else {
                    render::setup_done(&report);
                }
                return Ok(0);
            }
            Err(f) => f,
        };
        render::setup_failed(&failure, json);
        let Some(run_id) = failure.run_id.clone().filter(|_| interactive() && !json) else {
            return Ok(EXIT_PARTIAL);
        };
        if let Error::DnsConflict { hostname, .. } = &failure.error {
            let answer = ask(&format!("Type {hostname} to replace those records, or press Enter to stop: "))?;
            if answer == *hostname {
                outcome = keeper.resume(&run_id, std::slice::from_ref(hostname), &mut render::step);
                continue;
            }
        }
        match ask("What now? [r]esume, roll[b]ack, or Enter to leave it: ")?.as_str() {
            "r" => outcome = keeper.resume(&run_id, &[], &mut render::step),
            "b" => return run_plan(keeper, PlanKind::Rollback { run_id }, None, json),
            _ => return Ok(EXIT_PARTIAL),
        }
    }
}

fn offer_cloudflared(keeper: &Keeper) -> Result<()> {
    let st = keeper.cloudflared_status();
    if (st.found && st.meets_minimum) || !interactive() {
        return Ok(());
    }
    let release = keeper.cloudflared_release(None)?;
    let answer = ask(&format!("cloudflared is missing or too old. Download official release {} from GitHub? [y/N]: ", release.version))?;
    if answer.eq_ignore_ascii_case("y") {
        let path = keeper.cloudflared_download(&release)?;
        println!("Downloaded and verified {}", path.display());
    }
    Ok(())
}

fn parse_route(text: &str) -> Result<RouteRequest> {
    let (host, target) = text
        .split_once('=')
        .ok_or_else(|| Error::Invalid(format!("invalid route {text:?}: use app.example.com=3000")))?;
    Ok(RouteRequest { hostname: host.to_string(), service: target.to_string() })
}

fn quiet(_: &StepReport) {}

fn progress(json: bool) -> fn(&StepReport) {
    if json { quiet } else { render::step_fn }
}

fn setup(keeper: &mut Keeper, args: SetupArgs, json: bool) -> Result<u8> {
    if args.list {
        let runs = keeper.runs()?;
        if json {
            print_json(&runs);
        } else {
            render::runs(&runs);
        }
        return Ok(0);
    }
    if let Some(run_id) = args.rollback {
        return run_plan(keeper, PlanKind::Rollback { run_id }, args.confirm, json);
    }
    let mut show = progress(json);
    if let Some(run_id) = args.resume {
        let outcome = keeper.resume(&run_id, &[], &mut show);
        return finish_setup(keeper, outcome, json);
    }
    let routes = args.routes.iter().map(|r| parse_route(r)).collect::<Result<Vec<_>>>()?;
    let install_service = !args.no_service;
    if install_service {
        offer_cloudflared(keeper)?;
    }
    let request = SetupRequest {
        tunnel: args.name.expect("clap requires a name here"),
        routes,
        install_service,
        zone: args.zone,
        replace_dns: vec![],
    };
    let outcome = keeper.reconcile(request, &mut show);
    finish_setup(keeper, outcome, json)
}

fn run(cli: Cli) -> Result<u8> {
    let json = cli.json;
    let mut keeper = Keeper::production()?;
    match cli.command {
        Command::Elevated { .. } => unreachable!("handled before the keeper opens"),
        Command::Ui { port, no_open } => {
            let port = port.unwrap_or(keeper.config().ui.port);
            let running = web::start(port, std::sync::Arc::new(Keeper::production))?;
            println!("tunnelkeeper UI: {}", running.launch_url());
            println!("This link works once. Press Ctrl+C to stop.");
            if !no_open {
                web::open_browser(&running.launch_url());
            }
            running.wait();
            Ok(0)
        }
        Command::Setup(args) => setup(&mut keeper, args, json),
        Command::Auth { command } => match command {
            AuthCommand::Login { zone } => {
                let report = keeper.auth_login(read_token()?, zone.as_deref())?;
                if json { print_json(&report) } else { render::auth(&report) }
                Ok(0)
            }
            AuthCommand::Check { zone } => {
                let report = keeper.auth_check(zone.as_deref())?;
                if json { print_json(&report) } else { render::auth(&report) }
                let denied = report.permissions.as_ref().is_some_and(|p| !p.denied().is_empty());
                Ok(if denied { EXIT_ERROR } else { 0 })
            }
            AuthCommand::Logout => {
                keeper.auth_logout()?;
                println!("Stored token deleted");
                Ok(0)
            }
        },
        Command::Cloudflared { command } => match command {
            CloudflaredCommand::Check => {
                let st = keeper.cloudflared_status();
                if json { print_json(&st) } else { render::cloudflared(&st) }
                Ok(if st.found && st.meets_minimum { 0 } else { EXIT_ERROR })
            }
            CloudflaredCommand::Install { version, yes } => {
                let release = keeper.cloudflared_release(version.as_deref())?;
                if !yes {
                    if !interactive() {
                        return Err(Error::Invalid(format!("no terminal to ask on. Rerun with --yes to download {}", release.version)));
                    }
                    let answer = ask(&format!("Download {} {} from {}? [y/N]: ", release.asset, release.version, release.url))?;
                    if !answer.eq_ignore_ascii_case("y") {
                        println!("Nothing was downloaded");
                        return Ok(0);
                    }
                }
                let path = keeper.cloudflared_download(&release)?;
                println!("Downloaded {} and verified its SHA256: {}", release.version, path.display());
                Ok(0)
            }
        },
        Command::Tunnel { command } => match command {
            TunnelCommand::Create { name, zone } => {
                let request = SetupRequest { tunnel: name, routes: vec![], install_service: false, zone, replace_dns: vec![] };
                let mut show = progress(json);
                let outcome = keeper.reconcile(request, &mut show);
                finish_setup(&mut keeper, outcome, json)
            }
            TunnelCommand::List { zone } => {
                let rows = keeper.tunnel_list(zone.as_deref())?;
                if json { print_json(&rows) } else { render::tunnels(&rows) }
                Ok(0)
            }
            TunnelCommand::Delete { name, zone, include_unmanaged_dns, confirm } => {
                run_plan(&mut keeper, PlanKind::DeleteTunnel { name, zone, include_unmanaged_dns }, confirm, json)
            }
        },
        Command::Route { command } => match command {
            RouteCommand::Add { hostname, target, tunnel } => {
                let tunnel = keeper.config().resolve_tunnel(tunnel.as_deref())?.name.clone();
                let request = SetupRequest {
                    tunnel,
                    routes: vec![RouteRequest { hostname, service: target }],
                    install_service: false,
                    zone: None,
                    replace_dns: vec![],
                };
                let mut show = progress(json);
                let outcome = keeper.reconcile(request, &mut show);
                finish_setup(&mut keeper, outcome, json)
            }
            RouteCommand::List { tunnel } => {
                let rows = keeper.route_list(tunnel.as_deref())?;
                if json { print_json(&rows) } else { render::routes(&rows) }
                Ok(0)
            }
            RouteCommand::Remove { hostname, tunnel, include_unmanaged_dns, confirm } => {
                run_plan(&mut keeper, PlanKind::RemoveRoute { hostname, tunnel, include_unmanaged_dns }, confirm, json)
            }
        },
        Command::Service { command } => {
            let (done, result) = match &command {
                ServiceCommand::Install { tunnel } => ("installed and started", keeper.service_install(tunnel.as_deref())),
                ServiceCommand::Start { tunnel } => ("started", keeper.service_start(tunnel.as_deref())),
                ServiceCommand::Stop { tunnel } => ("stopped", keeper.service_stop(tunnel.as_deref())),
                ServiceCommand::Uninstall { tunnel } => ("removed", keeper.service_uninstall(tunnel.as_deref())),
            };
            result?;
            println!("Service {done}");
            Ok(0)
        }
        Command::Status { tunnel } => {
            let statuses = match tunnel {
                Some(t) => vec![keeper.status(Some(&t))?],
                None => keeper.status_all()?,
            };
            if json { print_json(&statuses) } else { render::status(&statuses) }
            Ok(if statuses.iter().all(|s| s.state == TunnelState::Healthy) { 0 } else { EXIT_UNHEALTHY })
        }
        Command::Logs { tunnel, lines, follow } => {
            for line in keeper.logs_tail(tunnel.as_deref(), lines)? {
                println!("{line}");
            }
            if follow {
                let (_, mut offset) = keeper.logs_since(tunnel.as_deref(), u64::MAX)?;
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    let (new, next) = keeper.logs_since(tunnel.as_deref(), offset)?;
                    offset = next;
                    for line in new {
                        println!("{line}");
                    }
                }
            }
            Ok(0)
        }
        Command::Doctor => {
            let findings = keeper.doctor();
            if json { print_json(&findings) } else { render::doctor(&findings) }
            let worst = findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Ok);
            Ok(if worst >= Severity::Warning { EXIT_UNHEALTHY } else { 0 })
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Command::Elevated { handoff } = &cli.command {
        return ExitCode::from(run_handoff(handoff) as u8);
    }
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}
