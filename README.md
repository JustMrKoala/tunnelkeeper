# tunnelkeeper

tunnelkeeper maps a local port to a permanent hostname on your Cloudflare domain, such as `app.example.com`. The tunnel starts with the machine and recovers from crashes without manual action.

It is one binary for Windows and Linux, with a CLI and a local web UI. The tunnel itself is run by Cloudflare's [cloudflared](https://github.com/cloudflare/cloudflared).

## Quick start

```bash
tunnelkeeper auth login --zone example.com
```

```bash
tunnelkeeper setup --name web --route app.example.com=3000
```

```bash
tunnelkeeper status
```

`setup` creates the tunnel, the route and the DNS record, then installs and starts the service. It is safe to run again: anything already correct is left alone.

Prefer a browser? Run `tunnelkeeper ui`.

## Installation

There is one binary and nothing else to install.

**Linux** (any distribution with systemd, x86_64 or ARM64):

```bash
curl -fsSL https://raw.githubusercontent.com/JustMrKoala/tunnelkeeper/main/install.sh | sh
```

The script downloads a static binary, checks its SHA256 and copies it to `/usr/local/bin`.

**Windows:** download `tunnelkeeper-windows-x86_64.exe` from the [latest release](https://github.com/JustMrKoala/tunnelkeeper/releases/latest), rename it to `tunnelkeeper.exe`, and put it in a folder on your `PATH`.

**From source:** with a current stable [Rust](https://rustup.rs) toolchain, and a C compiler on Linux:

```bash
cargo build --release -p tunnelkeeper
```

**cloudflared** version 2025.4.0 or later is required. tunnelkeeper finds an existing copy, or downloads the official release:

```bash
tunnelkeeper cloudflared install
```

The download is checked against the SHA256 published in the GitHub release notes. Services never run a copy from a user folder. `service install` copies the binary to a folder only administrators can change.

**Requirements**

* Windows 10 or later, or Linux with systemd
* Administrator or root rights for service steps only
* Outbound port 7844 on TCP and UDP to Cloudflare
* A domain active on Cloudflare

## Creating an API token

In the Cloudflare dashboard, go to **My Profile**, **API Tokens**, **Create Token**, **Create Custom Token**, and add:

| Scope | Permission | Level | Used for |
| --- | --- | --- | --- |
| Account | Cloudflare Tunnel | Edit | Creating and configuring tunnels |
| Zone | DNS | Edit | Creating route DNS records |
| Zone | Zone | Read | Finding the zone and account |

Cloudflare's documentation sometimes writes Edit as Write. Limit **Zone Resources** to the zones you need, and **Account Resources** to the one account.

Give the token to tunnelkeeper in one of these ways:

* Run `tunnelkeeper auth login`, which reads `CLOUDFLARE_API_TOKEN` or shows a hidden prompt
* Use the Account page of the web UI
* Set `CLOUDFLARE_API_TOKEN` for every command, which overrides the stored token

There is deliberately no command line argument for the token. Check a token at any time, without changing anything:

```bash
tunnelkeeper auth check --zone example.com
```

## Commands

| Command | What it does |
| --- | --- |
| `setup --name N --route HOST=PORT` | Full setup. `--route` can repeat, and `--no-service` skips the service |
| `setup --list` | Past runs, and what each created |
| `setup --resume RUN_ID` | Continues a failed run |
| `setup --rollback RUN_ID` | Undoes what a run created |
| `auth login`, `auth check`, `auth logout` | Manage the API token |
| `cloudflared check`, `cloudflared install` | Check or download cloudflared |
| `tunnel create NAME --zone Z` | Creates a tunnel without routes |
| `tunnel list [--zone Z]` | Lists tunnels on the account |
| `tunnel delete NAME` | Deletes a tunnel, its service and its DNS records |
| `route add HOST PORT_OR_URL` | Adds or updates a route and its DNS record |
| `route list`, `route remove HOST` | List or remove routes |
| `service install`, `start`, `stop`, `uninstall` | Control the local service |
| `status` | Health, service state and routes |
| `logs [-n 100] [--follow]` | Recent logs, with secrets removed |
| `doctor` | Finds common problems and suggests fixes |
| `ui [--port P] [--no-open]` | Opens the local web UI |

`--tunnel NAME` can be left out when only one tunnel is configured. `--json` gives machine readable output.

**Exit codes:** 0 ok, 1 error, 2 usage, 3 unhealthy, 4 partial setup that can be resumed.

### When setup fails

Setup records each step before it happens. If a step fails, it reports exactly what this run created, and any step whose outcome is unknown, then offers to resume or roll back. Rollback only undoes what that run created, so anything that already existed stays.

### Deleting

Commands that delete real tunnels or DNS records first show a plan, then ask you to type the name. Without a terminal, pass `--confirm NAME`.

DNS records tunnelkeeper did not create are kept, and the plan lists them. To include records that point at the tunnel but were made by hand, add `--include-unmanaged-dns`.

If a hostname already has a record pointing somewhere else, setup stops and shows it. It is only replaced after you approve it, and rollback restores it.

## Health states

| State | Meaning | Next step |
| --- | --- | --- |
| `Healthy` | Tunnel and local apps are fine | None |
| `OriginDown` | Tunnel is healthy, but the local app is not responding | Start your app |
| `TunnelDown` | Service is running, but it is not connected to Cloudflare | `tunnelkeeper doctor` |
| `ServiceStopped` | The service is stopped | `tunnelkeeper service start` |
| `NotInstalled` | No service on this machine | `tunnelkeeper service install` |
| `Degraded` | Serving traffic, but Cloudflare reports a problem | `tunnelkeeper logs` |

Any HTTP reply from your app counts as responding, even a 500, because the app is up.

## The web UI

`tunnelkeeper ui` prints a link and opens it. The link works once. To open the UI in another browser, run the command again. It runs only while the command runs, and only on `127.0.0.1`.

On a server without a browser, forward the port over SSH from your own machine, then open the printed link there:

```bash
ssh -L 17844:127.0.0.1:17844 user@server
```

```bash
tunnelkeeper ui --no-open
```

## How services run

| | Windows | Linux |
| --- | --- | --- |
| Service | `tunnelkeeper-NAME` | `tunnelkeeper-NAME.service` |
| Account | `NT AUTHORITY\LocalService` | `tunnelkeeper` system user |
| Starts at boot | Automatic start | Enabled, `WantedBy=multi-user.target` |
| Crash recovery | Restart after 5 s, 5 s, then every 30 s | `Restart=always` after 5 s, with no start limit |

## Where files live

| Item | Windows | Linux |
| --- | --- | --- |
| Config and run records | `%APPDATA%\tunnelkeeper` | `~/.config/tunnelkeeper` |
| API token | Credential Manager | Secret Service if a keyring is running, otherwise an owner only file |
| cloudflared | `%ProgramData%\tunnelkeeper\bin` | `/usr/local/lib/tunnelkeeper` |
| Tunnel token | `%ProgramData%\tunnelkeeper\tunnels` | `/etc/tunnelkeeper` |
| Logs | `%ProgramData%\tunnelkeeper\logs\NAME` | `/var/log/tunnelkeeper/NAME` |

`config.toml` holds no secrets. Cloudflare is the source of truth for routes, and `doctor` reports any drift. Ingress rules added elsewhere, such as in the dashboard, are kept.

## Security

* API and tunnel tokens are never printed, logged or placed on a command line.
* A service account cannot read your personal credential store, so each tunnel token sits in a file readable only by that service and administrators.
* Admin rights are requested only for service steps, and those run a fixed set of operations.
* The web UI refuses requests with an unexpected `Host` or `Origin`, needs a session from the one time link, needs a CSRF token for changes, and sends no CORS headers.
* Metrics stay on `127.0.0.1`, because that port also exposes debug routes.

## Troubleshooting

Start with `tunnelkeeper doctor`, which checks the items below and gives a fix for each.

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `the API token lacks ...` | A permission is missing | Add it to the token, see [Creating an API token](#creating-an-api-token) |
| `no Cloudflare zone found` | Domain not on this account, or no Zone Read | Check the token's Zone Resources |
| `TunnelDown` | Port 7844 blocked | Allow outbound 7844 on TCP and UDP |
| Service keeps restarting, log says `Failed to get tunnel` | Tunnel token is invalid, or the tunnel was deleted | `tunnelkeeper service install`, or run setup again |
| `OriginDown` | Your app is not running on that port | Start it, and check the port in `route list` |
| Browser shows a certificate error on `a.b.example.com` | Universal SSL covers one subdomain level in a full setup zone | Use a first level hostname, or add Total TLS |
| `does not point at this tunnel` | The hostname already has a DNS record | Review it, then approve the replacement |
| Tunnel will not delete | Cloudflare tracks connections for several minutes | tunnelkeeper retries for a few minutes. Run the delete again if it stops |
| Several tunnels share a name | Cloudflare allows this | Delete the extras in the dashboard, or pick another name |
| `This link was already used` | The UI link works once | Run `tunnelkeeper ui` again |
| Linux: `pkexec is not available` | No graphical prompt on this machine | Run the command in a terminal, where `sudo` is used |
| Windows build fails with `LNK1104` | The folder path is too long | Move the project, or set `CARGO_TARGET_DIR` to a short path |

Logs are in the folder listed in [Where files live](#where-files-live), and `tunnelkeeper logs --follow` shows them live.

## Removing tunnelkeeper

Run `tunnelkeeper tunnel delete NAME` for each tunnel, then `tunnelkeeper auth logout`. Then delete the binary and the folders listed above.

## Development

```bash
cargo test --workspace
```

Tests run against `crates/fake-cloudflare`, a fake Cloudflare API served over real HTTP, with failure injection. All logic lives in `crates/core`. `crates/tunnelkeeper` holds only the CLI and web front ends. See [DESIGN.md](DESIGN.md) for the design and test history.
