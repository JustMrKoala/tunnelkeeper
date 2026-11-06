// Display only. Every decision is made by the core, behind the API.
// All data reaches the page through textContent, never as HTML.
"use strict";

const csrf = document.querySelector('meta[name="tk-csrf"]').content;
const $ = (id) => document.getElementById(id);

function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") node.className = v;
    else if (k === "onclick") node.addEventListener("click", v);
    else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c !== null && c !== undefined) node.append(c);
  }
  return node;
}

async function api(path, body) {
  const options = { credentials: "same-origin" };
  if (body !== undefined) {
    options.method = "POST";
    options.headers = { "Content-Type": "application/json", "X-TK-CSRF": csrf };
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed with status " + response.status);
  return data;
}

function showError(error) {
  const b = $("banner");
  b.className = "banner bad";
  b.textContent = error.message || String(error);
  b.hidden = false;
}

function clearError() {
  $("banner").hidden = true;
}

const STATES = {
  HEALTHY: ["Healthy", "good"],
  DEGRADED: ["Degraded", "warn"],
  ORIGIN_DOWN: ["Local app not responding", "warn"],
  TUNNEL_DOWN: ["Tunnel down", "bad"],
  SERVICE_STOPPED: ["Service stopped", "bad"],
  NOT_INSTALLED: ["Service not installed", "warn"],
};

function originBadge(origin) {
  if (origin.result === "responding") return el("span", { class: "badge good" }, "Responding");
  if (origin.result === "not_responding") return el("span", { class: "badge bad", title: origin.detail }, "Not responding");
  return el("span", { class: "badge warn", title: origin.detail }, "Not checked");
}

function localText(ready) {
  if (ready.result === "ready") return ready.connections + " edge connections";
  if (ready.result === "not_ready") return "No edge connections";
  return "Metrics port not answering";
}

function remoteText(t) {
  if (t.remote) return (t.remote.status || "unknown") + " with " + t.remote.connectors + " connectors";
  return "Unknown: " + (t.remote_error || "no answer");
}

function tunnelCard(t) {
  const [label, tone] = STATES[t.state] || [t.state, "warn"];
  const installed = t.service.state !== "missing";
  const running = t.service.state === "running";
  const service = (action) => () => runJob("/api/service", { tunnel: t.name, action });

  const routes = el("tbody");
  for (const r of t.routes) {
    routes.append(el("tr", {},
      el("td", { class: "host" }, r.hostname),
      el("td", { class: "host" }, r.service),
      el("td", {}, originBadge(r.origin)),
      el("td", {}, el("button", {
        class: "quiet-danger",
        onclick: () => confirmPlan({ kind: "remove_route", hostname: r.hostname, tunnel: t.name, include_unmanaged_dns: false }),
      }, "Remove"))));
  }

  return el("article", { class: "card" },
    el("div", { class: "card-head" }, el("h2", {}, t.name), el("span", { class: "badge " + tone }, label)),
    el("p", { class: "message" }, t.message),
    el("dl", { class: "facts" },
      el("dt", {}, "Service"), el("dd", {}, t.service.name + " is " + t.service.state),
      el("dt", {}, "Local"), el("dd", {}, localText(t.ready)),
      el("dt", {}, "Cloudflare"), el("dd", {}, remoteText(t)),
      el("dt", {}, "Tunnel ID"), el("dd", {}, el("code", {}, t.id))),
    t.routes.length
      ? el("div", { class: "table-wrap" }, el("table", {},
          el("thead", {}, el("tr", {}, el("th", {}, "Hostname"), el("th", {}, "Goes to"), el("th", {}, "Local app"), el("th", {}, ""))),
          routes))
      : el("p", { class: "muted" }, "No routes yet."),
    el("div", { class: "row" },
      el("button", { onclick: () => openRouteDialog(t.name) }, "Add route"),
      installed
        ? el("button", { onclick: service(running ? "stop" : "start") }, running ? "Stop service" : "Start service")
        : el("button", { class: "primary", onclick: service("install") }, "Install service"),
      installed ? el("button", { onclick: service("uninstall") }, "Remove service") : null,
      el("button", {
        class: "quiet-danger",
        onclick: () => confirmPlan({ kind: "delete_tunnel", name: t.name, zone: null, include_unmanaged_dns: false }),
      }, "Delete tunnel")));
}

let known = [];

async function refresh() {
  if ($("confirm").open || $("route-dialog").open) return;
  try {
    const o = await api("/api/overview");
    const list = $("tunnels");
    list.replaceChildren(...o.tunnels.map(tunnelCard));
    if (!o.tunnels.length) {
      list.append(el("div", { class: "panel" }, el("p", { class: "muted" }, "No tunnels on this machine yet. Use New tunnel to create one.")));
    }
    const names = o.tunnels.map((t) => t.name);
    if (names.join() !== known.join()) {
      known = names;
      $("log-tunnel").replaceChildren(...names.map((n) => el("option", {}, n)));
    }
    $("token-state").textContent = o.has_token ? "A token is available." : "No token is stored yet.";
    const c = o.cloudflared;
    $("cf-state").textContent = c.found
      ? "Version " + c.version + (c.meets_minimum ? "" : ", older than the required " + c.minimum)
      : "cloudflared was not found.";
    const b = $("banner");
    const problems = [];
    if (!o.has_token) problems.push("No API token yet. Add one under Account.");
    if (!c.found || !c.meets_minimum) problems.push("cloudflared is missing or too old. Download it under Account.");
    if (problems.length) {
      b.className = "banner";
      b.textContent = problems.join(" ");
      b.hidden = false;
    } else if (!b.classList.contains("bad")) {
      b.hidden = true;
    }
  } catch (e) {
    showError(e);
  }
}

// Background jobs

let polling = false;

function stepItem(s) {
  const mark = { unchanged: "ok", changed: "changed", warning: "warning" }[s.status] || s.status;
  return el("li", { class: s.status }, mark + ": " + s.detail);
}

function renderFailure(f) {
  const parts = [];
  if (f.dns_conflict) {
    const c = f.dns_conflict;
    const list = el("ul", {}, ...c.records.map((r) => el("li", {}, r.type + " " + r.name + " " + r.content + (r.comment ? " (" + r.comment + ")" : ""))));
    const input = el("input", { autocomplete: "off", "aria-label": "Type the hostname to replace its records" });
    const go = el("button", {
      class: "danger",
      disabled: "",
      onclick: () => runJob("/api/resume", { run_id: f.run_id, approve_dns: [c.hostname] }),
    }, "Replace records");
    input.addEventListener("input", () => { go.disabled = input.value !== c.hostname; });
    parts.push(el("p", {}, "These existing records would be replaced. Type ", el("code", {}, c.hostname), " to approve."), list, el("div", { class: "row" }, input, go));
  }
  if (f.created.length) parts.push(el("h2", {}, "Created by this run"), el("ul", {}, ...f.created.map((c) => el("li", {}, c))));
  else parts.push(el("p", { class: "muted" }, "This run created nothing."));
  if (f.unknown.length) parts.push(el("h2", {}, "Outcome unknown, may exist"), el("ul", {}, ...f.unknown.map((c) => el("li", {}, c))));
  if (f.run_id) {
    parts.push(el("div", { class: "row" },
      el("button", { class: "primary", onclick: () => runJob("/api/resume", { run_id: f.run_id, approve_dns: [] }) }, "Resume"),
      f.created.length || f.unknown.length
        ? el("button", { class: "quiet-danger", onclick: () => confirmPlan({ kind: "rollback", run_id: f.run_id }) }, "Roll back")
        : null));
  }
  return parts;
}

function renderJob(job) {
  const panel = $("job");
  if (!job) {
    panel.hidden = true;
    return;
  }
  const tone = { running: "warn", succeeded: "good", failed: "bad" }[job.state];
  const word = { running: "Working", succeeded: "Done", failed: "Failed" }[job.state];
  const parts = [
    el("div", { class: "card-head" }, el("h2", {}, job.title), el("span", { class: "badge " + tone }, word)),
  ];
  if (job.state === "running") parts.push(el("p", { class: "muted" }, "An administrator prompt may appear for service steps."));
  if (job.steps.length) parts.push(el("ul", { class: "steps" }, ...job.steps.map(stepItem)));
  if (job.error) parts.push(el("p", {}, job.error));
  if (job.failure) parts.push(...renderFailure(job.failure));
  if (job.result && job.result.done) {
    parts.push(el("ul", { class: "steps" }, ...job.result.done.map((d) => el("li", { class: "changed" }, "done: " + d))));
    if (job.result.not_attempted && job.result.not_attempted.length) {
      parts.push(el("ul", { class: "steps" }, ...job.result.not_attempted.map((d) => el("li", { class: "warning" }, "not attempted: " + d))));
    }
  }
  if (job.state !== "running") {
    parts.push(el("div", { class: "row end" }, el("button", { onclick: () => { panel.hidden = true; } }, "Dismiss")));
  }
  panel.replaceChildren(...parts);
  panel.hidden = false;
}

async function watchJob(onLoad) {
  if (polling) return;
  polling = true;
  try {
    for (;;) {
      const job = await api("/api/job");
      // A job that already succeeded is old news after a page reload.
      if (onLoad && job && job.state === "succeeded") break;
      renderJob(job);
      if (!job || job.state !== "running") break;
      await new Promise((r) => setTimeout(r, 700));
    }
  } catch (e) {
    showError(e);
  }
  polling = false;
  refresh();
  if (!$("runs").closest("[data-panel]").hidden) loadRuns();
}

async function runJob(path, body) {
  clearError();
  try {
    await api(path, body);
    window.scrollTo(0, 0);
    watchJob();
  } catch (e) {
    showError(e);
  }
}

// Confirmed plans

let currentPlan = null;

async function confirmPlan(kind) {
  clearError();
  try {
    const plan = await api("/api/plan", kind);
    currentPlan = plan;
    $("confirm-title").textContent = plan.summary;
    $("confirm-actions").replaceChildren(...plan.descriptions.map((d) => el("li", {}, d)));
    const notes = plan.kept.map((k) => "Kept: " + k).concat(plan.warnings.map((w) => "Warning: " + w));
    $("confirm-notes").replaceChildren(...notes.map((n) => el("li", {}, n)));
    $("confirm-phrase").textContent = plan.confirm_phrase;
    $("confirm-input").value = "";
    $("confirm-go").disabled = true;
    $("confirm").showModal();
    $("confirm-input").focus();
  } catch (e) {
    showError(e);
  }
}

$("confirm-input").addEventListener("input", (e) => {
  $("confirm-go").disabled = !currentPlan || e.target.value !== currentPlan.confirm_phrase;
});
$("confirm-cancel").addEventListener("click", () => $("confirm").close());
$("confirm-go").addEventListener("click", () => {
  const plan = currentPlan;
  const answer = $("confirm-input").value;
  $("confirm").close();
  runJob("/api/apply", { kind: plan.kind, fingerprint: plan.fingerprint, confirm: answer });
});

// Forms

let routeTunnel = null;

function openRouteDialog(name) {
  routeTunnel = name;
  $("route-tunnel").textContent = name;
  $("route-form").reset();
  $("route-dialog").showModal();
}

$("route-cancel").addEventListener("click", () => $("route-dialog").close());
$("route-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  $("route-dialog").close();
  runJob("/api/route", { tunnel: routeTunnel, hostname: f.get("hostname"), target: f.get("target") });
});

$("setup-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  runJob("/api/setup", {
    tunnel: f.get("tunnel"),
    routes: [{ hostname: f.get("hostname"), service: f.get("target") }],
    install_service: f.get("service") === "on",
    zone: null,
    replace_dns: [],
  });
});

$("remote-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  clearError();
  const zone = new FormData(e.target).get("zone");
  try {
    const rows = await api("/api/tunnels?zone=" + encodeURIComponent(zone));
    const body = el("tbody", {}, ...rows.map((r) => el("tr", {},
      el("td", { class: "host" }, r.name),
      el("td", {}, r.status || "unknown"),
      el("td", {}, r.managed_here ? "Here" : "Elsewhere"),
      el("td", {}, el("button", {
        class: "quiet-danger",
        onclick: () => confirmPlan({ kind: "delete_tunnel", name: r.name, zone: zone || null, include_unmanaged_dns: false }),
      }, "Delete")))));
    $("remote").replaceChildren(rows.length
      ? el("div", { class: "table-wrap" }, el("table", {},
          el("thead", {}, el("tr", {}, el("th", {}, "Name"), el("th", {}, "Status"), el("th", {}, "Managed"), el("th", {}, ""))), body))
      : el("p", { class: "muted" }, "No tunnels."));
  } catch (err) {
    showError(err);
  }
});

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  clearError();
  const f = new FormData(e.target);
  const body = { token: f.get("token"), zone: f.get("zone") || null };
  e.target.elements.token.value = "";
  try {
    const r = await api("/api/auth/login", body);
    const items = [el("li", {}, "Token is " + r.token_status + ", stored in " + r.stored_in)];
    for (const c of (r.permissions ? r.permissions.checks : [])) {
      const denied = c.result === "denied";
      const unknown = typeof c.result === "object";
      items.push(el("li", {},
        el("span", { class: "badge " + (denied ? "bad" : unknown ? "warn" : "good") }, denied ? "Missing" : unknown ? "Unknown" : "OK"),
        c.name));
    }
    $("login-output").replaceChildren(...items);
    refresh();
  } catch (err) {
    showError(err);
  }
});

$("logout").addEventListener("click", async () => {
  clearError();
  try {
    await api("/api/auth/logout", {});
    $("login-output").replaceChildren(el("li", {}, "Stored token deleted."));
    refresh();
  } catch (e) {
    showError(e);
  }
});

$("cf-install").addEventListener("click", () => runJob("/api/cloudflared/install", { version: null }));

async function loadLogs() {
  clearError();
  const tunnel = $("log-tunnel").value;
  if (!tunnel) {
    $("log-output").textContent = "No tunnels yet.";
    return;
  }
  try {
    const lines = await api("/api/logs?lines=300&tunnel=" + encodeURIComponent(tunnel));
    const out = $("log-output");
    out.textContent = lines.length ? lines.join("\n") : "No log lines yet.";
    out.scrollTop = out.scrollHeight;
  } catch (e) {
    showError(e);
  }
}

async function loadDoctor() {
  clearError();
  const out = $("doctor-output");
  out.replaceChildren(el("li", { class: "muted" }, "Running checks..."));
  try {
    const findings = await api("/api/doctor");
    const tone = { ok: "good", info: "good", warning: "warn", error: "bad" };
    const word = { ok: "OK", info: "Info", warning: "Warning", error: "Problem" };
    out.replaceChildren(...findings.map((f) => el("li", {},
      el("span", { class: "badge " + tone[f.severity] }, word[f.severity]),
      el("div", {}, el("div", {}, f.message), f.fix ? el("div", { class: "fix" }, "Fix: " + f.fix) : null))));
  } catch (e) {
    showError(e);
  }
}

async function loadRuns() {
  clearError();
  try {
    const runs = await api("/api/runs");
    const rollbackable = (r) => (r.status === "failed" || r.status === "complete") && (r.created.length || r.unknown.length);
    $("runs").replaceChildren(...(runs.length ? runs.map((r) => el("div", { class: "card" },
      el("div", { class: "card-head" }, el("h2", {}, r.tunnel), el("code", {}, r.id),
        el("span", { class: "badge " + ({ complete: "good", failed: "bad", rolled_back: "warn", running: "warn" }[r.status]) }, r.status.replace("_", " "))),
      r.error ? el("p", {}, r.error) : null,
      r.created.length ? el("ul", {}, ...r.created.map((c) => el("li", {}, c))) : null,
      r.unknown.length ? el("ul", {}, ...r.unknown.map((c) => el("li", {}, "Unknown: " + c))) : null,
      el("div", { class: "row" },
        r.status === "failed" ? el("button", { onclick: () => runJob("/api/resume", { run_id: r.id, approve_dns: [] }) }, "Resume") : null,
        rollbackable(r) ? el("button", { class: "quiet-danger", onclick: () => confirmPlan({ kind: "rollback", run_id: r.id }) }, "Roll back") : null)))
      : [el("p", { class: "muted" }, "No runs recorded.")]));
  } catch (e) {
    showError(e);
  }
}

$("log-refresh").addEventListener("click", loadLogs);
$("log-tunnel").addEventListener("change", loadLogs);
$("doctor-run").addEventListener("click", loadDoctor);

// Tabs

function showTab(name) {
  for (const b of document.querySelectorAll("#tabs button")) {
    if (b.dataset.tab === name) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  for (const p of document.querySelectorAll("[data-panel]")) p.hidden = p.dataset.panel !== name;
  if (name === "logs") loadLogs();
  if (name === "history") loadRuns();
}

for (const b of document.querySelectorAll("#tabs button")) {
  b.addEventListener("click", () => showTab(b.dataset.tab));
}

refresh();
watchJob(true);
setInterval(refresh, 5000);
