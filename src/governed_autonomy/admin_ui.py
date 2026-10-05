"""Minimal dependency-free admin UI.

The page ships no inline script or style: everything lives in separately
served, same-origin ``app.js``/``app.css`` assets so a strict
``script-src 'self'; style-src 'self'`` CSP can be enforced (see
``AuthenticatedAPI._send_static`` in ``http_api.py``). No credential is ever
persisted by the page; the operator token and any signing key entered in the
browser are held in page memory only and vanish on reload.
"""

from __future__ import annotations


def render_admin_ui() -> bytes:
    body = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Governance Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="stylesheet" href="/admin/app.css">
</head>
<body>
<main>
<h1>Governance Admin</h1>
<p class="hint">
Paste an operator/bearer token to authenticate this browser session. Nothing you
enter here is persisted: it is held only in this page's memory and is lost on reload.
</p>
<section id="auth-panel">
<label for="token-input">Authorization token</label>
<input id="token-input" type="password" autocomplete="off" placeholder="Bearer or operator token">
<button id="token-save">Connect</button>
<span id="auth-status" class="status"></span>
</section>

<nav class="tabs">
<button data-tab="mission-control" class="tab-button active">Mission Control</button>
<button data-tab="health" class="tab-button">Health</button>
<button data-tab="policies" class="tab-button">Policies</button>
<button data-tab="proposals" class="tab-button">Policy Proposals</button>
<button data-tab="trust" class="tab-button">Trusted Keys</button>
<button data-tab="operators" class="tab-button">Operator Access</button>
<button data-tab="audit" class="tab-button">Audit</button>
<button data-tab="metrics" class="tab-button">Metrics</button>
</nav>

<section id="tab-mission-control" class="tab-panel active">
<h2>Governance Mission Control <button class="refresh" data-refresh="mission-control">Refresh</button></h2>
<p id="mission-status" class="hint">Connect to load the current governance snapshot.</p>
<div class="mission-stats">
  <span>Assets <strong id="mc-assets">—</strong></span>
  <span>Policies <strong id="mc-policies">—</strong></span>
  <span>Approvals <strong id="mc-approvals">—</strong></span>
  <span>Incidents <strong id="mc-incidents">—</strong></span>
  <span>Exec success <strong id="mc-success-rate">—</strong></span>
</div>
<div class="mission-grid">
  <section><h3>Assets &amp; policy graph</h3><table id="mission-assets"><thead><tr><th>Action</th><th>Governing policies</th></tr></thead><tbody></tbody></table></section>
  <section><h3>Approval queue</h3><table id="mission-approvals"><thead><tr><th>Policy</th><th>Proposal</th><th>Approvals</th></tr></thead><tbody></tbody></table></section>
  <section><h3>Incident center</h3><table id="mission-incidents"><thead><tr><th>Event</th><th>Detail</th></tr></thead><tbody></tbody></table></section>
  <section><h3>Analytics &amp; audit timeline</h3><p id="mission-analytics" class="hint"></p><ol id="mission-timeline"></ol></section>
</div>
</section>

<section id="tab-health" class="tab-panel">
<h2>Health</h2>
<button class="refresh" data-refresh="health">Refresh</button>
<pre id="health-output" class="output">Not loaded.</pre>
</section>

<section id="tab-policies" class="tab-panel">
<h2>Registered policies</h2>
<button class="refresh" data-refresh="policies">Refresh</button>
<table id="policies-table"><thead><tr>
<th>Policy ID</th><th>Version</th><th>Digest</th><th>Allowed actions</th>
</tr></thead><tbody></tbody></table>
</section>

<section id="tab-proposals" class="tab-panel">
<h2>Policy change proposals</h2>
<button class="refresh" data-refresh="proposals">Refresh</button>
<table id="proposals-table"><thead><tr>
<th>Proposal</th><th>Policy</th><th>Status</th><th>Proposer</th>
<th>Approvals</th><th>Actions</th>
</tr></thead><tbody></tbody></table>

<h3>Propose a policy change</h3>
<p class="hint">
Signing happens entirely in this browser tab using the Web Crypto API: your
private key is pasted below only to compute an Ed25519 signature locally and
is never sent to the server or stored anywhere.
</p>
<p class="hint">
Policy JSON supports the full <code>Policy.to_dict()</code> schema, including
mesh-governance fields (<code>required_mesh_inputs</code>,
<code>required_mesh_sources</code>, <code>mesh_required_actions</code>,
<code>mesh_required_environments</code>).
</p>
<form id="propose-form">
<label>Policy JSON (Policy.to_dict schema)
<textarea id="propose-policy" rows="8" placeholder='{"policy_id": "...", "allowed_actions": [...], "required_mesh_inputs": {"deploy": 2}, ...}'></textarea>
</label>
<label>Rationale <input id="propose-rationale" type="text"></label>
<label>Proposer key ID <input id="propose-key-id" type="text"></label>
<label>Proposer private key (base64url, raw 32 bytes) <input id="propose-private-key" type="password" autocomplete="off"></label>
<button type="submit">Sign and submit proposal</button>
</form>
<pre id="propose-output" class="output"></pre>

<h3>Approve a pending proposal</h3>
<form id="approve-form">
<label>Proposal ID <input id="approve-proposal-id" type="text"></label>
<label>Approver key ID <input id="approve-key-id" type="text"></label>
<label>Approver private key (base64url, raw 32 bytes) <input id="approve-private-key" type="password" autocomplete="off"></label>
<button type="submit">Sign and submit approval</button>
</form>
<pre id="approve-output" class="output"></pre>
</section>

<section id="tab-audit" class="tab-panel">
<h2>Audit report</h2>
<button class="refresh" data-refresh="audit">Refresh</button>
<pre id="audit-output" class="output">Not loaded.</pre>

<h3>Governance log</h3>
<p class="hint">
Durable, hash-chained history of policy, trust, and operator-key changes
(proposed, approved, activated, key added/revoked), including the authenticated
actor, recorded alongside authorization/execution events.
</p>
<table id="governance-log-table"><thead><tr>
<th>Recorded at</th><th>Event</th><th>Subject</th><th>Actor</th>
</tr></thead><tbody></tbody></table>
</section>

<section id="tab-trust" class="tab-panel">
<h2>Trusted issuer keys</h2>
<button class="refresh" data-refresh="trust">Refresh</button>
<table id="trust-table"><thead><tr>
<th>Key ID</th><th>Public key (base64url)</th><th>Status</th><th>Actions</th>
</tr></thead><tbody></tbody></table>

<h3>Add a trusted key</h3>
<p class="hint">
Trust changes take effect immediately once signed: they are not subject to the
policy-proposal approval quorum, since trust is the root of authority the
quorum itself depends on. Only a currently trusted, non-revoked key can
authorize adding or revoking another key.
</p>
<form id="trust-add-form">
<label>New key ID <input id="trust-add-key-id" type="text"></label>
<label>New public key (base64url, raw 32 bytes) <input id="trust-add-public-key" type="text"></label>
<label>Requesting (already trusted) key ID <input id="trust-add-requester-key-id" type="text"></label>
<label>Requesting private key (base64url, raw 32 bytes) <input id="trust-add-private-key" type="password" autocomplete="off"></label>
<button type="submit">Sign and add key</button>
</form>
<pre id="trust-add-output" class="output"></pre>

<h3>Revoke a trusted key</h3>
<form id="trust-revoke-form">
<label>Key ID to revoke <input id="trust-revoke-key-id" type="text"></label>
<label>Requesting (already trusted) key ID <input id="trust-revoke-requester-key-id" type="text"></label>
<label>Requesting private key (base64url, raw 32 bytes) <input id="trust-revoke-private-key" type="password" autocomplete="off"></label>
<button type="submit">Sign and revoke key</button>
</form>
<pre id="trust-revoke-output" class="output"></pre>
</section>

<section id="tab-operators" class="tab-panel">
<h2>Operator API keys</h2>
<p class="hint">
Keys are stored as hashes in the configured SQLite database and can access
only <code>/admin</code> routes. The full token is shown once when created;
copy it now and store it in your secret manager.
</p>
<button class="refresh" data-refresh="operators">Refresh</button>
<table id="operator-keys-table"><thead><tr>
<th>Operator</th><th>Key ID</th><th>Created</th><th>Status</th><th>Actions</th>
</tr></thead><tbody></tbody></table>
<h3>Create an operator key</h3>
<form id="operator-key-form">
<label>Operator ID <input id="operator-key-operator-id" type="text" maxlength="256"></label>
<button type="submit">Create operator key</button>
</form>
<pre id="operator-key-output" class="output"></pre>
</section>

<section id="tab-metrics" class="tab-panel">
<h2>Metrics</h2>
<button class="refresh" data-refresh="metrics">Refresh</button>
<pre id="metrics-output" class="output">Not loaded.</pre>
</section>
</main>
<script src="/admin/app.js"></script>
</body>
</html>"""
    return body.encode("utf-8")


def render_admin_css() -> bytes:
    body = """:root {
  color-scheme: light dark;
  --border: #8884;
  --accent: #2563eb;
}
* { box-sizing: border-box; }
body {
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  margin: 0 auto;
  max-width: 960px;
  padding: 1.5rem;
  line-height: 1.4;
}
h1 { font-size: 1.5rem; }
h2 { font-size: 1.2rem; margin-top: 0; }
.hint { font-size: 0.85rem; opacity: 0.8; }
#auth-panel {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 1rem;
  padding: 0.75rem;
  border: 1px solid var(--border);
  border-radius: 0.5rem;
}
#auth-panel input { flex: 1 1 260px; }
.status { font-size: 0.85rem; }
.status.ok { color: #16a34a; }
.status.error { color: #dc2626; }
.tabs { display: flex; gap: 0.25rem; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }
.tab-button {
  padding: 0.5rem 0.9rem;
  border: none;
  background: none;
  cursor: pointer;
  border-bottom: 2px solid transparent;
  font-size: 0.95rem;
}
.tab-button.active { border-bottom-color: var(--accent); font-weight: 600; }
.tab-panel { display: none; }
.tab-panel.active { display: block; }
.output {
  background: #0001;
  border-radius: 0.4rem;
  padding: 0.75rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 0.85rem;
}
table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; font-size: 0.9rem; }
th, td { text-align: left; padding: 0.4rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }
form { display: flex; flex-direction: column; gap: 0.6rem; max-width: 640px; margin-bottom: 1.5rem; }
form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.9rem; }
textarea, input[type="text"], input[type="password"] {
  font-family: inherit;
  font-size: 0.9rem;
  padding: 0.4rem;
  border: 1px solid var(--border);
  border-radius: 0.3rem;
}
button {
  cursor: pointer;
  padding: 0.4rem 0.8rem;
  border: 1px solid var(--accent);
  border-radius: 0.3rem;
  background: var(--accent);
  color: #fff;
  align-self: flex-start;
}
button.refresh { background: none; color: var(--accent); margin-bottom: 0.75rem; }
.mission-stats { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.8rem 0; }
.mission-stats span { background: #111827; border: 1px solid #334155; border-radius: 0.4rem; padding: 0.55rem 0.75rem; }
.mission-stats strong { margin-left: 0.3rem; color: #93c5fd; }
.mission-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0.8rem; }
.mission-grid section { min-width: 0; border: 1px solid #334155; border-radius: 0.5rem; padding: 0.75rem; }
.mission-grid h3 { margin: 0 0 0.5rem; font-size: 1rem; }
#mission-timeline { max-height: 220px; overflow: auto; font-size: 0.82rem; }
#mission-timeline li { margin: 0.35rem 0; }
body { max-width: 1440px; background: #080e19; color: #e2e8f0; }
input, textarea { background: #0f172a; color: #e2e8f0; }
button { font-weight: 600; }
button.refresh { color: #93c5fd; border-color: #334155; }
th { color: #94a3b8; font-size: 0.73rem; text-transform: uppercase; letter-spacing: 0.05em; }
td { color: #cbd5e1; font-size: 0.82rem; }
@media (max-width: 760px) {
  body { padding: 0.85rem; }
  .mission-grid { grid-template-columns: 1fr; }
}
"""
    return body.encode("utf-8")


def render_admin_js() -> bytes:
    body = r""""use strict";
(() => {
  let authToken = "";

  function b64urlEncode(bytes) {
    let binary = "";
    for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64urlDecode(value) {
    let padded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  // RFC 8410 fixed 16-byte PKCS8 prefix for a raw 32-byte Ed25519 private key.
  const PKCS8_ED25519_PREFIX = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);

  async function importEd25519PrivateKey(rawKeyB64) {
    const raw = b64urlDecode(rawKeyB64);
    if (raw.length !== 32) {
      throw new Error("private key must decode to exactly 32 raw bytes");
    }
    const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + raw.length);
    pkcs8.set(PKCS8_ED25519_PREFIX, 0);
    pkcs8.set(raw, PKCS8_ED25519_PREFIX.length);
    return crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "Ed25519" },
      false,
      ["sign"],
    );
  }

  async function signEd25519(privateKeyB64, message) {
    const key = await importEd25519PrivateKey(privateKeyB64);
    const signature = await crypto.subtle.sign(
      { name: "Ed25519" },
      key,
      new TextEncoder().encode(message),
    );
    return b64urlEncode(signature);
  }

  async function api(path, options = {}) {
    const authorization = authToken.startsWith("gasop_") ? "Bearer " + authToken : authToken;
    const headers = Object.assign({}, options.headers, { Authorization: authorization });
    if (options.body) headers["Content-Type"] = "application/json";
    const response = await fetch(path, Object.assign({}, options, { headers }));
    const text = await response.text();
    let parsed;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch (err) {
      parsed = { error: text || "invalid response" };
    }
    if (!response.ok) {
      const message = parsed && parsed.error ? parsed.error : `HTTP ${response.status}`;
      throw new Error(message);
    }
    return parsed;
  }

  function setStatus(message, ok) {
    const el = document.getElementById("auth-status");
    el.textContent = message;
    el.className = "status " + (ok ? "ok" : "error");
  }

  function showTab(name) {
    document.querySelectorAll(".tab-panel").forEach((el) => {
      el.classList.toggle("active", el.id === "tab-" + name);
    });
    document.querySelectorAll(".tab-button").forEach((el) => {
      el.classList.toggle("active", el.dataset.tab === name);
    });
  }

  function setMetric(id, value, tone) {
    const element = document.getElementById(id);
    element.textContent = value;
    element.className = tone ? tone : "";
  }

  async function loadControlRoom() {
    const error = document.getElementById("mission-error");
    error.hidden = true;
    try {
      const data = await api("/admin/control-room");
      const analytics = data.analytics || {};
      const healthy = Boolean(data.health && data.health.ok);
      setMetric("mc-health", healthy ? "OPERATIONAL" : "DEGRADED", healthy ? "good" : "bad");
      document.getElementById("mc-health-detail").textContent = healthy
        ? "Replay and governance checks passing"
        : "One or more readiness checks need attention";
      setMetric("mc-assets", analytics.asset_count ?? 0);
      setMetric("mc-policies", analytics.policy_count ?? 0);
      setMetric("mc-approvals", analytics.pending_approval_count ?? 0,
        analytics.pending_approval_count ? "warn" : "good");
      setMetric("mc-incidents", (data.incidents || []).length,
        data.incidents && data.incidents.length ? "bad" : "good");
      setMetric("mc-success-rate",
        analytics.success_rate === null ? "—" : analytics.success_rate + "%",
        analytics.success_rate === null ? "" : analytics.success_rate >= 95 ? "good" : "warn");
      document.getElementById("mc-execution-count").textContent =
        `${analytics.execution_count || 0} executions · ${analytics.failure_count || 0} failed`;

      renderPolicyGraph(data.graph || {});
      renderIncidents(data.incidents || []);
      renderApprovals(data.proposals || {});
      renderAssets(data.assets || []);
      renderAnalytics(analytics, data.health || {});
      renderTimeline(data.timeline || []);
    } catch (err) {
      error.textContent = "Mission control could not load: " + err.message;
      error.hidden = false;
      ["policy-graph", "incident-list", "approval-list", "analytics-chart"].forEach((id) => {
        document.getElementById(id).innerHTML =
          '<p class="empty-state">Snapshot unavailable. Refresh after resolving the connection.</p>';
      });
    }
  }

  function renderPolicyGraph(graph) {
    const container = document.getElementById("policy-graph");
    const policies = new Map((graph.nodes || [])
      .filter((node) => node.kind === "policy")
      .map((node) => [node.id, []]));
    for (const edge of graph.edges || []) {
      if (policies.has(edge.from)) policies.get(edge.from).push(edge.to);
    }
    if (!policies.size) {
      container.innerHTML = '<p class="empty-state">No policies are registered.</p>';
      return;
    }
    container.innerHTML = [...policies.entries()].map(([policyId, actions]) =>
      '<div class="graph-row"><div class="graph-policy"><strong>' + escapeHtml(policyId) +
      '</strong><br><small>policy</small></div><div class="graph-arrow" aria-hidden="true">→</div>' +
      '<div>' + (actions.length
        ? actions.sort().map((action) => '<span class="graph-action">' + escapeHtml(action) + '</span>').join("")
        : '<span class="empty-state">No linked action</span>') +
      '</div></div>'
    ).join("");
  }

  function renderIncidents(incidents) {
    const container = document.getElementById("incident-list");
    if (!incidents.length) {
      container.innerHTML = '<p class="empty-state">No denied requests or failed executions in the replay ledger.</p>';
      return;
    }
    container.innerHTML = incidents.slice(0, 12).map((incident) =>
      '<article class="incident-item ' + escapeHtml(incident.severity) + '">' +
      '<strong>' + escapeHtml(incident.summary) + '</strong>' +
      '<p>' + escapeHtml(incident.detail || "No additional details recorded.") + '</p>' +
      '<p>' + escapeHtml(incident.action || incident.policy_id || incident.frame_id) +
      ' · frame ' + escapeHtml(String(incident.sequence)) + '</p></article>'
    ).join("");
  }

  function renderApprovals(proposalData) {
    const container = document.getElementById("approval-list");
    const pending = (proposalData.proposals || []).filter((proposal) => proposal.status === "pending");
    if (!pending.length) {
      container.innerHTML = '<p class="empty-state">No policy changes are waiting for approval.</p>';
      return;
    }
    const required = proposalData.required_approvals;
    container.innerHTML = pending.map((proposal) => {
      const count = Number(proposal.approval_count || 0);
      const quorum = Number(required || 0);
      return '<article class="approval-item"><strong>' + escapeHtml(proposal.policy_id) +
        '</strong><p>' + escapeHtml(proposal.proposal_id) + '</p><p>Approvals: ' +
        escapeHtml(String(count)) + (quorum ? ' / ' + escapeHtml(String(quorum)) : '') +
        ' · proposer ' + escapeHtml(proposal.proposed_by_key_id) + '</p></article>';
    }).join("");
  }

  function renderAssets(assets) {
    const tbody = document.querySelector("#asset-table tbody");
    if (!assets.length) {
      tbody.innerHTML = '<tr><td colspan="3">No executable action handlers are registered.</td></tr>';
      return;
    }
    tbody.innerHTML = assets.map((asset) =>
      '<tr><td>' + escapeHtml(asset.asset_id) + '</td><td><span class="status-pill ' +
      escapeHtml(asset.status) + '">' + escapeHtml(asset.status) + '</span></td><td>' +
      escapeHtml((asset.policies || []).join(", ") || "No policy mapping") + '</td></tr>'
    ).join("");
  }

  function renderAnalytics(metrics, health) {
    const container = document.getElementById("analytics-chart");
    const values = [
      ["Authorizations", Number(metrics.authorization_count || 0), ""],
      ["Executions", Number(metrics.execution_count || 0), ""],
      ["Successful", Number(metrics.success_count || 0), "success"],
      ["Failed", Number(metrics.failure_count || 0), "failure"],
    ];
    const maximum = Math.max(1, ...values.map((value) => value[1]));
    container.innerHTML = values.map(([label, value, kind]) => {
      const width = Math.round(value / maximum * 100);
      return '<div class="analytics-row"><span>' + escapeHtml(label) + '</span><svg class="analytics-track" ' +
        'viewBox="0 0 100 10" preserveAspectRatio="none" role="img" aria-label="' +
        escapeHtml(label + ": " + value) + '"><rect class="analytics-bar ' + kind +
        '" x="0" y="0" width="' + width + '" height="10" rx="5"></rect></svg><strong>' +
        escapeHtml(String(value)) + '</strong></div>';
    }).join("");
    const replay = health.checks && health.checks.replay_chain;
    document.getElementById("analytics-integrity").textContent = replay
      ? `Replay integrity ${replay.ok ? "verified" : "failed"} · ${replay.frames} frames · ` +
        `${metrics.trusted_key_count || 0} trusted keys · ${metrics.revoked_key_count || 0} revoked`
      : "Replay integrity status unavailable.";
  }

  function renderTimeline(events) {
    const tbody = document.querySelector("#timeline-table tbody");
    const shown = events.slice(0, 30);
    document.getElementById("timeline-count").textContent = `${events.length} recent frames`;
    if (!shown.length) {
      tbody.innerHTML = '<tr><td colspan="6">No audit frames have been recorded.</td></tr>';
      return;
    }
    tbody.innerHTML = shown.map((event) => {
      const detail = event.action || event.policy_id || "—";
      const actorNonce = event.actor_id !== "system" && event.actor_id
        ? event.actor_id : event.nonce || "—";
      const when = event.recorded_at || ("Frame " + event.sequence);
      return '<tr><td>' + escapeHtml(when) + '</td><td>' + escapeHtml(event.event) +
        '</td><td>' + escapeHtml(event.type) + '</td><td>' + escapeHtml(detail) +
        '</td><td>' + escapeHtml(actorNonce) + '</td><td><code>' +
        escapeHtml(String(event.frame_hash || "").slice(0, 12)) + '</code></td></tr>';
    }).join("");
  }

  async function loadHealth() {
    const output = document.getElementById("health-output");
    try {
      output.textContent = JSON.stringify(await api("/health"), null, 2);
    } catch (err) {
      output.textContent = "Error: " + err.message;
    }
  }

  async function loadAudit() {
    const output = document.getElementById("audit-output");
    try {
      output.textContent = JSON.stringify(await api("/audit"), null, 2);
    } catch (err) {
      output.textContent = "Error: " + err.message;
    }
    await loadGovernanceLog();
  }

  async function loadGovernanceLog() {
    const tbody = document.querySelector("#governance-log-table tbody");
    tbody.innerHTML = "";
    try {
      const data = await api("/admin/governance-log");
      const events = [...(data.events || [])].reverse();
      for (const event of events) {
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td>" + escapeHtml(event.recorded_at || "") + "</td>" +
          "<td>" + escapeHtml(event.event || "") + "</td>" +
          "<td>" + escapeHtml(event.subject_id || "") + "</td>" +
          "<td>" + escapeHtml(event.actor_id || "system") + "</td>";
        tbody.appendChild(tr);
      }
    } catch (err) {
      const tr = document.createElement("tr");
      tr.innerHTML = "<td colspan=\"4\">Error: " + escapeHtml(err.message) + "</td>";
      tbody.appendChild(tr);
    }
  }

  async function loadMetrics() {
    const output = document.getElementById("metrics-output");
    try {
      output.textContent = JSON.stringify(await api("/admin/metrics"), null, 2);
    } catch (err) {
      output.textContent = "Error: " + err.message;
    }
  }

  async function loadPolicies() {
    const tbody = document.querySelector("#policies-table tbody");
    tbody.innerHTML = "";
    try {
      const data = await api("/admin/policies");
      for (const entry of data.policies.policies || []) {
        const policy = entry.policy || entry;
        const version = entry.version || entry.manifest_version || "-";
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td>" + escapeHtml(policy.policy_id) + "</td>" +
          "<td>" + escapeHtml(String(version)) + "</td>" +
          "<td>" + escapeHtml((policy.policy_id || "") + "") + "</td>" +
          "<td>" + escapeHtml((policy.allowed_actions || []).join(", ")) + "</td>";
        tbody.appendChild(tr);
      }
    } catch (err) {
      tbody.innerHTML = "<tr><td colspan=4>Error: " + escapeHtml(err.message) + "</td></tr>";
    }
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (ch) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]
    ));
  }

  async function loadProposals() {
    const tbody = document.querySelector("#proposals-table tbody");
    tbody.innerHTML = "";
    try {
      const data = await api("/admin/proposals");
      const required = data.required_approvals;
      for (const proposal of data.proposals || []) {
        const tr = document.createElement("tr");
        const approvalsText = proposal.approval_count + (required ? "/" + required : "");
        const canActivate = proposal.status === "pending" && required && proposal.approval_count >= required;
        tr.innerHTML =
          "<td>" + escapeHtml(proposal.proposal_id) + "</td>" +
          "<td>" + escapeHtml(proposal.policy_id) + "</td>" +
          "<td>" + escapeHtml(proposal.status) + "</td>" +
          "<td>" + escapeHtml(proposal.proposed_by_key_id) + "</td>" +
          "<td>" + escapeHtml(approvalsText) + "</td>" +
          "<td>" + (canActivate
            ? '<button data-activate="' + escapeHtml(proposal.proposal_id) + '">Activate</button>'
            : "") + "</td>";
        tbody.appendChild(tr);
      }
      tbody.querySelectorAll("[data-activate]").forEach((button) => {
        button.addEventListener("click", async () => {
          try {
            await api("/admin/proposals/" + encodeURIComponent(button.dataset.activate) + "/activate", {
              method: "POST",
            });
            await loadProposals();
          } catch (err) {
            alert("Activation failed: " + err.message);
          }
        });
      });
    } catch (err) {
      tbody.innerHTML = "<tr><td colspan=6>Error: " + escapeHtml(err.message) + "</td></tr>";
    }
  }

  function wireProposeForm() {
    document.getElementById("propose-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const output = document.getElementById("propose-output");
      output.textContent = "Signing...";
      try {
        const policy = JSON.parse(document.getElementById("propose-policy").value);
        const rationale = document.getElementById("propose-rationale").value;
        const proposerKeyId = document.getElementById("propose-key-id").value;
        const privateKey = document.getElementById("propose-private-key").value;
        const prepared = await api("/admin/proposals/prepare", {
          method: "POST",
          body: JSON.stringify({ policy, rationale, proposer_key_id: proposerKeyId }),
        });
        const signature = await signEd25519(privateKey, prepared.unsigned_payload);
        const result = await api("/admin/proposals", {
          method: "POST",
          body: JSON.stringify({
            policy,
            rationale,
            proposal_id: prepared.proposal_id,
            proposer_key_id: proposerKeyId,
            signature,
          }),
        });
        output.textContent = "Submitted:\n" + JSON.stringify(result, null, 2);
        document.getElementById("propose-private-key").value = "";
        await loadProposals();
      } catch (err) {
        output.textContent = "Error: " + err.message;
      }
    });
  }

  function wireApproveForm() {
    document.getElementById("approve-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const output = document.getElementById("approve-output");
      output.textContent = "Signing...";
      try {
        const proposalId = document.getElementById("approve-proposal-id").value;
        const approverKeyId = document.getElementById("approve-key-id").value;
        const privateKey = document.getElementById("approve-private-key").value;
        const encodedId = encodeURIComponent(proposalId);
        const prepared = await api("/admin/proposals/" + encodedId + "/prepare-approval", {
          method: "POST",
          body: JSON.stringify({ approver_key_id: approverKeyId }),
        });
        const signature = await signEd25519(privateKey, prepared.unsigned_payload);
        const result = await api("/admin/proposals/" + encodedId + "/approve", {
          method: "POST",
          body: JSON.stringify({ approver_key_id: approverKeyId, signature }),
        });
        output.textContent = "Approved:\n" + JSON.stringify(result, null, 2);
        document.getElementById("approve-private-key").value = "";
        await loadProposals();
      } catch (err) {
        output.textContent = "Error: " + err.message;
      }
    });
  }

  async function loadTrust() {
    const tbody = document.querySelector("#trust-table tbody");
    tbody.innerHTML = "";
    try {
      const data = await api("/admin/trust");
      const revoked = new Set(data.revoked || []);
      for (const [keyId, publicKey] of Object.entries(data.keys || {})) {
        const tr = document.createElement("tr");
        const isRevoked = revoked.has(keyId);
        tr.innerHTML =
          "<td>" + escapeHtml(keyId) + "</td>" +
          "<td>" + escapeHtml(publicKey) + "</td>" +
          "<td>" + (isRevoked ? "revoked" : "trusted") + "</td>" +
          "<td>" + (isRevoked
            ? ""
            : '<button data-prefill-revoke="' + escapeHtml(keyId) + '">Revoke\u2026</button>') +
          "</td>";
        tbody.appendChild(tr);
      }
      tbody.querySelectorAll("[data-prefill-revoke]").forEach((button) => {
        button.addEventListener("click", () => {
          document.getElementById("trust-revoke-key-id").value = button.dataset.prefillRevoke;
        });
      });
    } catch (err) {
      tbody.innerHTML = "<tr><td colspan=4>Error: " + escapeHtml(err.message) + "</td></tr>";
    }
  }

  function wireTrustAddForm() {
    document.getElementById("trust-add-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const output = document.getElementById("trust-add-output");
      output.textContent = "Signing...";
      try {
        const keyId = document.getElementById("trust-add-key-id").value;
        const publicKeyB64 = document.getElementById("trust-add-public-key").value;
        const requesterKeyId = document.getElementById("trust-add-requester-key-id").value;
        const privateKey = document.getElementById("trust-add-private-key").value;
        const prepared = await api("/admin/trust/keys/prepare", {
          method: "POST",
          body: JSON.stringify({
            key_id: keyId,
            public_key_b64: publicKeyB64,
            requested_by_key_id: requesterKeyId,
          }),
        });
        const signature = await signEd25519(privateKey, prepared.unsigned_payload);
        const result = await api("/admin/trust/keys", {
          method: "POST",
          body: JSON.stringify({
            key_id: keyId,
            public_key_b64: publicKeyB64,
            requested_by_key_id: requesterKeyId,
            signature,
          }),
        });
        output.textContent = "Added:\n" + JSON.stringify(result, null, 2);
        document.getElementById("trust-add-private-key").value = "";
        await loadTrust();
      } catch (err) {
        output.textContent = "Error: " + err.message;
      }
    });
  }

  function wireTrustRevokeForm() {
    document.getElementById("trust-revoke-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const output = document.getElementById("trust-revoke-output");
      output.textContent = "Signing...";
      try {
        const keyId = document.getElementById("trust-revoke-key-id").value;
        const requesterKeyId = document.getElementById("trust-revoke-requester-key-id").value;
        const privateKey = document.getElementById("trust-revoke-private-key").value;
        const encodedId = encodeURIComponent(keyId);
        const prepared = await api("/admin/trust/keys/" + encodedId + "/revoke/prepare", {
          method: "POST",
          body: JSON.stringify({ requested_by_key_id: requesterKeyId }),
        });
        const signature = await signEd25519(privateKey, prepared.unsigned_payload);
        const result = await api("/admin/trust/keys/" + encodedId + "/revoke", {
          method: "POST",
          body: JSON.stringify({ requested_by_key_id: requesterKeyId, signature }),
        });
        output.textContent = "Revoked:\n" + JSON.stringify(result, null, 2);
        document.getElementById("trust-revoke-private-key").value = "";
        await loadTrust();
      } catch (err) {
        output.textContent = "Error: " + err.message;
      }
    });
  }

  async function loadOperatorKeys() {
    const tbody = document.querySelector("#operator-keys-table tbody");
    tbody.innerHTML = "";
    try {
      const data = await api("/admin/operator-keys");
      for (const key of data.keys || []) {
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td>" + escapeHtml(key.operator_id) + "</td>" +
          "<td>" + escapeHtml(key.key_id) + "</td>" +
          "<td>" + escapeHtml(key.created_at) + "</td>" +
          "<td>" + (key.revoked ? "Revoked" : "Active") + "</td>" +
          "<td>" + (key.revoked ? "" :
            "<button type=\"button\" data-revoke-operator-key=\"" +
            escapeHtml(key.key_id) + "\">Revoke</button>") + "</td>";
        tbody.appendChild(tr);
      }
    } catch (err) {
      const tr = document.createElement("tr");
      tr.innerHTML = "<td colspan=\"5\">Error: " + escapeHtml(err.message) + "</td>";
      tbody.appendChild(tr);
    }
  }

  function wireOperatorKeyForm() {
    document.getElementById("operator-key-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const output = document.getElementById("operator-key-output");
      output.textContent = "Creating key...";
      try {
        const operatorId = document.getElementById("operator-key-operator-id").value.trim();
        const created = await api("/admin/operator-keys", {
          method: "POST",
          body: JSON.stringify({ operator_id: operatorId }),
        });
        output.textContent =
          "Copy and securely store this token now; it will not be shown again:\n" +
          created.token + "\n\nOperator: " + created.operator_id +
          "\nKey ID: " + created.key_id;
        document.getElementById("operator-key-operator-id").value = "";
        await loadOperatorKeys();
      } catch (err) {
        output.textContent = "Error: " + err.message;
      }
    });
    document.querySelector("#operator-keys-table tbody").addEventListener("click", async (event) => {
      const button = event.target.closest("[data-revoke-operator-key]");
      if (!button) return;
      const keyId = button.dataset.revokeOperatorKey;
      if (!window.confirm("Revoke this operator key? Requests using it will fail immediately.")) {
        return;
      }
      const output = document.getElementById("operator-key-output");
      try {
        await api("/admin/operator-keys/" + encodeURIComponent(keyId) + "/revoke", {
          method: "POST",
        });
        output.textContent = "Operator key revoked: " + keyId;
        await loadOperatorKeys();
      } catch (err) {
        output.textContent = "Error: " + err.message;
      }
    });
  }

  const loaders = {
    "mission-control": loadControlRoom,
    health: loadHealth,
    policies: loadPolicies,
    proposals: loadProposals,
    trust: loadTrust,
    operators: loadOperatorKeys,
    audit: loadAudit,
    metrics: loadMetrics,
  };

  function connect() {
    authToken = document.getElementById("token-input").value.trim();
    if (!authToken) {
      setStatus("Enter a token first.", false);
      return;
    }
    setStatus("Connected (token held in memory only).", true);
    loaders["mission-control"]();
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("token-save").addEventListener("click", connect);
    document.getElementById("token-input").addEventListener("keydown", (event) => {
      if (event.key === "Enter") connect();
    });
    document.querySelectorAll(".tab-button").forEach((button) => {
      button.addEventListener("click", () => {
        showTab(button.dataset.tab);
        const loader = loaders[button.dataset.tab];
        if (loader) loader();
      });
    });
    document.querySelectorAll("[data-refresh]").forEach((button) => {
      button.addEventListener("click", () => loaders[button.dataset.refresh]());
    });
    wireProposeForm();
    wireApproveForm();
    wireTrustAddForm();
    wireTrustRevokeForm();
    wireOperatorKeyForm();
  });
})();
"""
    return body.encode("utf-8")
