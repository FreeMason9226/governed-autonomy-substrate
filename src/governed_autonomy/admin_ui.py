"""Minimal dependency-free admin UI.

The page deliberately contains no inline script or secrets.  It is a set of
links to authenticated, read-only JSON resources, which keeps the CSP strict
and leaves session/SSO concerns to the deployment edge.
"""
from __future__ import annotations

def render_admin_ui() -> bytes:
    body = """<!doctype html><html><head><meta charset="utf-8"><title>Governance Admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1"></head><body>
<main><h1>Governance Admin</h1>
<p>Use the authenticated JSON resources below. No credentials are stored in this page.</p>
<ul><li><a href="/health">Health</a></li><li><a href="/audit">Audit</a></li>
<li><a href="/admin/policies">Policies</a></li><li><a href="/admin/proposals">Proposals</a></li>
<li><a href="/admin/metrics">Metrics</a></li></ul></main></body></html>"""
    return body.encode("utf-8")
