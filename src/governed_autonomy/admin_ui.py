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
<button data-tab="health" class="tab-button active">Health</button>
<button data-tab="policies" class="tab-button">Policies</button>
<button data-tab="proposals" class="tab-button">Policy Proposals</button>
<button data-tab="audit" class="tab-button">Audit</button>
<button data-tab="metrics" class="tab-button">Metrics</button>
</nav>

<section id="tab-health" class="tab-panel active">
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
    const headers = Object.assign({}, options.headers, { Authorization: authToken });
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

  const loaders = {
    health: loadHealth,
    policies: loadPolicies,
    proposals: loadProposals,
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
    loaders.health();
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
  });
})();
"""
    return body.encode("utf-8")
