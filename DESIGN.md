# tunnelkeeper: Stage 1 design proposal

Status: proposal, awaiting approval. No application code exists yet.
Docs and source checked on 2026-11-05. Latest cloudflared at that date: 2026.10.7.

## 1. Facts that shaped the design

Each of these was checked against current docs, cloudflared source, or this machine.

| Finding | Source | Design consequence |
| --- | --- | --- |
| `POST /accounts/{id}/cfd_tunnel` with `config_src: "cloudflare"` creates a remotely managed tunnel. | API reference | Used as is. |
| The guide shows a `token` in the create response, the API reference does not. | Docs conflict | Never read it from the create response. Always call `GET .../cfd_tunnel/{id}/token`. |
| Tunnel name uniqueness is not documented. | API reference | Idempotency cannot depend on the API rejecting duplicates. We look up first, and stop if more than one tunnel matches. |
| `PUT .../configurations` replaces the whole config, and a catch-all rule must be last. | API reference, guide | Every route change is read, modify, write, then read back. Rules we did not create are preserved. |
| Deleting a tunnel requires no active connections. `DELETE .../connections` removes connectors, and connections stay tracked for several minutes after disconnecting. | API reference | Delete order is fixed (section 7), with retry and backoff. |
| No endpoint shows a token's own permissions. `tokens/verify` only reports active, disabled, or expired, and user and account tokens have separate verify routes. | API reference | Permissions must be proven by probing (section 6). |
| Permission labels disagree: "DNS Edit" against "DNS Write", "Cloudflare Tunnel Edit" against "Write". | Docs conflict | The README will give both labels. Real behavior gets confirmed in Stage 5. |
| `GET /zones?name=` needs Zone Read and returns the owning `account.id`. | API reference | The user supplies only a hostname. Zone and account are discovered. |
| DNS comments are on all plans (100 characters on Free). Tags are not on Free. | DNS docs | Ownership is marked with a comment, not a tag. |
| Universal SSL does not cover `a.b.example.com` in a full setup zone. | SSL docs | `route add` and `doctor` warn about deep hostnames. |
| `--token-file` exists from cloudflared 2025.4.0. A `--token` argument would be visible in the service command line. | Docs, local `--help` | Always `--token-file`. Refuse older versions. |
| `/ready` returns 200 with `readyConnections` and `connectorId` when connected to the edge, otherwise 503. It is only in source, not in the docs. | `metrics/readiness.go` | Primary local health signal. Pinned to a known port per tunnel. |
| The metrics server also exposes `/config` and `/debug/pprof`. | `metrics/metrics.go` | Must always bind to 127.0.0.1. |
| `--logfile` is not rotated. `--log-directory` rotates at 1 MB and keeps 5 backups. `debug` level can log sensitive headers. | Docs, local `--help` | Use `--log-directory`, level `info`, and never offer `debug` in the service. |
| The cloudflared SCM dispatch name is hard coded to `Cloudflared`, but Microsoft documents that the name is ignored for own process services. Its fallback path on failure is interactive mode. | cloudflared source, Microsoft docs | Custom service names should work. **Not yet proven. First test of Stage 2.** |
| cloudflared itself sets a Windows restart delay of 20 s, and `Restart=on-failure` on Linux. | cloudflared source | Not enough for the spec, so we do not use `cloudflared service install`. We register services ourselves. |
| Failure actions only apply to non-crash exits if `FailureActionsOnNonCrashFailures` is set, and Microsoft says the change takes effect at next system start. | Microsoft docs | We set it, and Stage 5 tests it before and after reboot. |
| systemd stops restarting after the start limit is reached, even with `Restart=always`. `StartLimitIntervalSec=0` disables that. | systemd docs (summary, recheck in Stage 4) | Set in the unit. |
| Release checksums exist only in the GitHub release body as `<file>: <sha256>`. There are no signature files. | GitHub release | Download verifies SHA256 from the release body. This proves integrity against the release page, not authorship. |
| On this machine `cloudflared` is a Scoop shim in a user writable folder. | Local check | A service must not point at it (section 5). |

## 2. Project structure

```
tunnelkeeper/
  Cargo.toml                    workspace
  crates/
    core/                       ALL logic. No printing, no prompting, no HTTP serving.
      src/
        lib.rs                  Keeper: the single entry point both front ends call
        config.rs               config.toml load, save, validation
        paths.rs                per OS paths
        redact.rs               Secret<T> wrapper and log scrubber
        cloudflare/             trait CloudflareApi + real HTTP client
        cloudflared/            locate, version check, download, verify, install
        secrets/                trait SecretStore: wincred, secret-tool, file
        service/                trait ServiceManager: windows.rs, systemd.rs
        elevate/                trait Elevator + fixed privileged operations
        setup/                  reconcile steps, journal, resume, rollback
        plan.rs                 destructive Plan and Confirmed values
        health.rs               state classification, origin probes, /ready
        doctor.rs               checks returning finding + suggested fix
        logs.rs                 tail, scrub
    tunnelkeeper/               the binary
      src/
        main.rs
        cli/                    argument parsing and rendering only
        web/                    tiny_http server, guards, JSON routes
      ui/                       static HTML, CSS, JS, embedded with include_str!
    fake-cloudflare/            dev only: in process fake API with failure injection
```

The rule that keeps logic out of the front ends: `core` has no `println!`, no prompts, and no HTTP server. Every operation returns a typed result that the CLI prints and the UI serializes to JSON. Every OS and network boundary is a trait, so setup, rollback, and health all run in tests against fakes.

**Confirmation is enforced by the type system.** A destructive function in `core` takes a `Confirmed<Plan>`. The caller first gets a `Plan` listing exactly what will be deleted, shows it to the user, then confirms. If the real state changed since the plan was built, its fingerprint no longer matches and nothing is deleted. Neither front end can skip this step by accident.

### Dependencies (10 direct)

`ureq` (HTTP client, rustls), `tiny_http` (UI server), `serde`, `serde_json`, `toml`, `clap`, `rpassword` (hidden prompt), `sha2`, `getrandom`, and `windows-sys` on Windows only.

No async runtime: the tool makes a handful of sequential calls, so tokio would add weight without benefit. I built this exact set on this machine: it compiles with the MSVC toolchain in about 30 s, about 73 crates in total.

## 3. Commands

```
tunnelkeeper setup --name web --route app.example.com=3000   full idempotent flow
tunnelkeeper setup --resume <run-id>
tunnelkeeper setup --rollback <run-id>
tunnelkeeper setup --list                                    past runs and what each created

tunnelkeeper auth login        reads CLOUDFLARE_API_TOKEN, else hidden prompt, then stores it
tunnelkeeper auth check [--zone example.com]                 runs all permission probes
tunnelkeeper auth logout

tunnelkeeper cloudflared check
tunnelkeeper cloudflared install [--version X]               asks first, verifies SHA256

tunnelkeeper tunnel create <name>
tunnelkeeper tunnel list
tunnelkeeper tunnel delete <name>                            shows the plan, asks

tunnelkeeper route add <hostname> <port|url> [--tunnel name]
tunnelkeeper route list
tunnelkeeper route remove <hostname>                         shows the plan, asks

tunnelkeeper service install|start|stop|uninstall [--tunnel name]

tunnelkeeper status [--tunnel name]                          health, service, routes
tunnelkeeper logs [-n 100] [--follow]
tunnelkeeper doctor
tunnelkeeper ui [--port 17844] [--no-open]
```

Global flags: `--json` for machine output, `--tunnel` when more than one exists.

`--tunnel` may be omitted when only one is configured. There is deliberately no blanket `--yes`. Scripts must name the target: `tunnel delete web --confirm web`.

Exit codes: 0 ok, 1 error, 2 usage, 3 unhealthy (`status`, `doctor`), 4 partial setup that can be resumed.

## 4. Config and files

`config.toml` holds no secrets:

```toml
version = 1

[cloudflared]
path = "managed"            # or an absolute path
min_version = "2025.4.0"

[ui]
port = 17844

[[tunnel]]
name = "web"
id = "c1744f8b-faa1-48a4-9e5c-02ac921467fa"
account_id = "..."
metrics_port = 20301        # allocated once, avoids cloudflared's default 20241 to 20245

  [[tunnel.route]]
  hostname = "app.example.com"
  service = "http://localhost:3000"
  zone_id = "..."
  dns_record_id = "..."
```

Cloudflare is authoritative for routes. The local copy lets `status` keep probing local apps when the API is unreachable. `doctor` reports any drift between the two.

| Item | Windows | Linux |
| --- | --- | --- |
| Config, journal | `%APPDATA%\tunnelkeeper\` | `~/.config/tunnelkeeper/` |
| API token | Credential Manager | Secret Service via `secret-tool` if usable, otherwise 0600 file |
| Managed cloudflared | `%ProgramData%\tunnelkeeper\bin\` | `/usr/local/lib/tunnelkeeper/` |
| Tunnel token | `%ProgramData%\tunnelkeeper\tunnels\<name>.token` (ACL) | `/etc/tunnelkeeper/<name>.token` (0600 root) |
| Logs | `%ProgramData%\tunnelkeeper\logs\<name>\` | `/var/log/tunnelkeeper/<name>/` |

## 5. Service design

One service per tunnel, named `tunnelkeeper-<name>`, launching cloudflared directly with no wrapper process:

```
cloudflared tunnel --no-autoupdate --metrics 127.0.0.1:<port> --loglevel info
  --log-directory <dir> run --token-file <file>
```

**Windows:** created through the service control APIs, automatic start, restart actions at 5 s, 5 s, 30 s, reset after 24 h, `FailureActionsOnNonCrashFailures` on.

**Linux:** `Restart=always`, `RestartSec=5`, `StartLimitIntervalSec=0`, `After=` and `Wants=network-online.target`, `Type=notify`, enabled at boot, with systemd sandboxing options.

**Least privilege:** run as `NT AUTHORITY\LocalService` on Windows and a dedicated unprivileged account on Linux. If LocalService fails in testing, I will report it before falling back to SYSTEM.

**Why a managed binary copy:** the service runs with more rights than the user. If it pointed at a user writable path such as Scoop's folder, any user level process could replace that file and gain those rights. A Scoop shim would also break the SCM handshake. So `service install` copies the resolved real binary to the admin only folder, and `doctor` flags any service pointing elsewhere.

**Updates:** no auto update, per the out of scope list. `cloudflared install` replaces the binary on request.

## 6. Reliability

### Setup is a reconciler

Each step checks real state first, and only acts if it differs:

1. cloudflared present and new enough.
2. Token valid, permissions proven.
3. Zone found for each hostname.
4. Tunnel exists (adopt the one match, stop if several).
5. Ingress contains the route.
6. DNS record is correct.
7. Tunnel token stored.
8. Service installed, then running.
9. Tunnel reports ready and the local app answers.

A second run makes no changes and says so.

**DNS conflicts:** an existing record pointing at this tunnel is fine. Any other record for that hostname stops setup, shows the record, and requires explicit approval.

### Journal, resume, rollback

Before each mutation, a run file records the intent. After it, the file records the outcome and the resource ID. On failure the user gets an exact list of what was created in this run and what already existed, then is offered resume or rollback. Rollback undoes only what that run created, in reverse order, after showing a plan.

### Permission checks

| Need | Probe | Changes anything? |
| --- | --- | --- |
| Token active | user verify, then account verify | No |
| Zone Read | `GET /zones?name=` | No |
| DNS read | `GET dns_records` | No |
| Tunnel read | `GET cfd_tunnel` | No |
| DNS write | `PATCH` on a random nonexistent record ID | No, expects 404, a 403 means missing |
| Tunnel write | `PUT configurations` on a random nonexistent tunnel ID | No, expects 404, a 403 means missing |

The two write probes rely on Cloudflare checking permission before existence. That is **an assumption I cannot confirm without a real token**. Stage 5 tests it with tokens that have and lack each permission. If it does not hold, the fallback is a TXT record created and removed under `_tunnelkeeper-probe`.

### Health states

Inputs are service state, local `/ready`, Cloudflare tunnel status, connector list, and a probe per route.

| State | Condition | Message |
| --- | --- | --- |
| `NOT_INSTALLED` | No service | Run `service install` |
| `SERVICE_STOPPED` | Service not running | The service is stopped. Adds a note if Cloudflare still sees another connector. |
| `TUNNEL_DOWN` | Service running, `/ready` is 503 or unreachable | Running but not connected to Cloudflare. Points at network or token checks. |
| `ORIGIN_DOWN` | `/ready` 200, a route's local app does not answer | Tunnel healthy, local app not responding, names the route and port. |
| `DEGRADED` | Cloudflare reports degraded | Serving, with reduced connections |
| `HEALTHY` | All pass | |
| `UNKNOWN` (remote part) | API unreachable | Local results are shown and the gap is stated. |

Any HTTP response from the local app counts as answering, even a 500, because the app is up. Non HTTP services use a TCP connect.

### Doctor checks

cloudflared missing, old, or a shim. Token invalid, expired, or missing permissions. Clock skew. DNS resolution of `region1.v2.argotunnel.com`. Port 7844 reachable on TCP (a UDP check is best effort). Service missing, stopped, or crash looping. Service binary path unsafe. Token file ACL too open. Metrics port taken. Ingress or DNS drift. Deep hostnames without certificate coverage. DNS record not proxied. Tunnel not in `cloudflare` config mode. Each finding includes a specific fix.

## 7. Deletion order

`tunnel delete` shows this as a plan and runs it only after confirmation:

1. Stop and uninstall the service.
2. Delete the stored tunnel token.
3. Delete DNS records that carry our comment and point at this tunnel. Others are listed and kept unless separately confirmed.
4. Remove stale connectors with `DELETE .../connections`.
5. `DELETE .../cfd_tunnel/{id}`, with backoff if connections are still tracked.

## 8. Elevation

Normal operation runs as the user. All Cloudflare calls happen unelevated.

Only these need admin or root: install or uninstall the service, start or stop it, copy the managed binary, write the tunnel token. Those are fixed operations in a hidden `tunnelkeeper elevated <op>` subcommand, with no generic command execution.

* **Windows:** one UAC prompt through `ShellExecuteW` with `runas`, for both CLI and UI.
* **Linux:** CLI uses `sudo`. UI uses `pkexec` if available, otherwise it shows the exact command to run.
* **Token handoff:** a short lived file readable only by the user and administrators, deleted by the helper at once. Never on a command line.

## 9. Security

**Secrets**
* All tokens live in a `Secret` type with no `Debug`, `Display`, or `Serialize`, so printing one fails to compile.
* Logs shown by `logs` and the UI pass through a scrubber as a second layer. Tests search all output for planted token values.
* The API token comes from `CLOUDFLARE_API_TOKEN` or a hidden prompt, or a password field on the local UI.

**Tunnel token exception:** a service account cannot read the logged in user's Credential Manager or Secret Service. So the tunnel token sits in a file readable only by its service account and administrators. This matches your "file readable only by the owner" fallback, but it will apply on every platform, so I want your explicit approval.

**Web UI**
* Binds to 127.0.0.1 only, and runs only while `tunnelkeeper ui` runs.
* DNS rebinding: requests are rejected unless `Host` is exactly `127.0.0.1:<port>` or `localhost:<port>`.
* Cross site: mutating requests require a matching `Origin`, `Sec-Fetch-Site: same-origin`, JSON content type, and a CSRF header. No CORS headers are ever sent.
* Access: a random launch token in the opening URL is swapped for an `HttpOnly`, `SameSite=Strict` cookie, so other local users and processes cannot drive the UI.
* Strict CSP with no external assets, and `X-Frame-Options: DENY`.
* Destructive actions use the same `Plan`, and the user types the tunnel name to confirm.

## 10. Test plan

| Stage | Tested by | Needs from you |
| --- | --- | --- |
| 2 | Unit and integration tests against the fake API, including failure at every setup step, rerun, resume, rollback, redaction. Real Windows service using a local dummy target. | Approve a few UAC prompts (this session is not elevated) |
| 3 | Guard tests with forged `Host`, `Origin`, and missing tokens. Browser test of the UI. | Nothing |
| 4 | Real systemd in WSL or a VM | A Linux distro with systemd. WSL currently only has `docker-desktop`, which is not suitable |
| 5 | Real domain, reboot, forced kill of cloudflared, killed local app, blocked network, permission probe matrix | Test domain, scoped tokens set by you in an environment variable, permission to reboot |
| 6 | Follow the README from a clean state | Nothing |

## 11. Risks and what testing showed

Updated at the end of Stage 2 (2026-11-05).

| Risk | Status | Evidence |
| --- | --- | --- |
| Custom named Windows service running cloudflared | **Resolved** | Reached RUNNING on the real SCM |
| cloudflared running as LocalService | **Resolved** | Ran under LocalService, with the token readable through the per service SID |
| cloudflared giving up on its own | **Resolved for bad credentials** | Exits with 1067 after about 35 s. Windows restarted it 6 of 6 times with no help |
| Exit code 0 in an unrequested stop | Open | Not seen. Only a requested stop gave code 0. Stage 5 |
| Failure flag only applying after reboot | Open | Restarts worked before any reboot, reboot itself is Stage 5 |
| Write probe behavior on the real API | Open | Only proven against the fake. Stage 5 |
| `/ready` is undocumented | Accepted | Format confirmed on real cloudflared, 503 case only. The 200 case needs a real tunnel |
| Authenticode signing | Partly resolved | Version 2026.3.0 has a valid Cloudflare signature. tunnelkeeper does not check it yet |
| Rate limits | Accepted | Client backs off on 429 and honors `Retry-After` |

### Linux results (Stage 4)

Run on Ubuntu 26.04 in WSL with systemd 259 as PID 1, as an unprivileged user going through sudo.

| Check | Result |
| --- | --- |
| Automated tests | 169 pass natively on Linux |
| Unit contents, enabled at boot | Confirmed with `systemctl cat` and `is-enabled` |
| Runs as the `tunnelkeeper` user | Confirmed with `ps` |
| Token file | Mode 0400, unprivileged read denied, not on any command line |
| `kill -9` | Restarted with a new PID within 8 s |
| cloudflared giving up by itself | systemd restarted it, no start limit reached |
| Requested stop | Stayed stopped |
| Distro shut down and started again | Service came back by itself. WSL keeps its kernel running, so this restarts systemd but is not a full machine reboot |
| Rerun of setup | No changes and no sudo prompt |
| `doctor` during a live crash loop | Found it and named the cause |
| cloudflared download | Real GitHub release, SHA256 verified |
| Rollback | Removed the unit, token and all entries |

Not covered on Linux: the Secret Service path (no keyring in this environment, so the owner only file was used), pkexec, and a tunnel that really connects. With Type=notify a service shows as activating until cloudflared first connects, which tunnelkeeper reports as Starting.

### Real domain results (Stage 5)

Run on Windows 11 against the real Cloudflare API, with a real domain and cloudflared 2026.10.7.

| Check | Result |
| --- | --- |
| Token permission probes, allowed path | All five pass, and change nothing |
| Setup | Healthy on the first try, 4 edge connections |
| Public request | 200 through Cloudflare, with the right page |
| Rerun of setup | No changes, no elevation |
| Local app stopped | Public 502, status `OriginDown`, back to 200 after restart |
| Forced kill of the service process | Public 200 again after 6 s, with a new PID |
| Requested stop | Public 502, stayed stopped for 30 s, status `ServiceStopped` |
| Service start | Public 200 after 2 s |
| Real cloudflared download | SHA256 verified, valid Cloudflare signature |

Still open: a real Windows restart, the denied path of the write probes (needs a token without those permissions), installing a real service from the web UI, and exit code 0 in an unrequested stop.

## 12. Changes from the original proposal

* The fake API is a real HTTP server rather than a `CloudflareApi` trait, so tests run the real client. That trait was dropped.
* Users may list the token folder, without any access to the token files. Unelevated checks could not otherwise see whether a token exists.
* `logs` reformats cloudflared's JSON lines, because `--log-directory` writes JSON.
* `install.sh` and GitHub release binaries were added on request, to make installation easy. Linux binaries are static (musl) so they run on any distribution.

* The UI opens a fresh `Keeper` per request, so it always reads the same config as the CLI. Slow changes run as background jobs, one at a time, and the page polls them. Reads keep working during a job.
* Running the CLI and the UI at once is not locked against each other. Avoid changing the same tunnel from both at the same moment.

## 13. Building in this folder

This folder's path is too long for the MSVC linker, which fails with LNK1104. Set `CARGO_TARGET_DIR` to a short path. The problem goes away if the project moves to a normal folder.
