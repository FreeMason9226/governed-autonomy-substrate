"""Simulated AI agent that opens a pull request, plus live-mode approval lookup.

Dry-run (default) makes no network calls and needs no credentials.
Live mode (--live) uses these environment variables:
  GAA_DEMO_REPO         owner/name of the target repository (required)
  GAA_DEMO_TOKEN        token with contents:write and pull-requests:write (required; never printed)
  GAA_DEMO_BASE_BRANCH  base branch (default: main)
  GAA_DEMO_API_URL      API root (default: https://api.github.com)
This script never approves or merges a pull request.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any

BOT_LOGIN = "ai-agent-bot"
AI_LABEL = "ai-authored"
CHANGE_PATH = "src/governed_autonomy/_demo_ai_change.py"
CHANGE_BODY = '"""Simulated AI-authored change for the governed-autonomy demo."""\n\nDEMO_VALUE = 1\n'
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class Github:
    def __init__(self, repo: str, token: str, api_url: str) -> None:
        if not REPO_RE.match(repo):
            raise SystemExit("GAA_DEMO_REPO must look like owner/name")
        if not api_url.startswith("https://"):
            raise SystemExit("GAA_DEMO_API_URL must use https")
        self.repo, self.token, self.api_url = repo, token, api_url.rstrip("/")

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        request = urllib.request.Request(
            f"{self.api_url}/repos/{self.repo}{path}",
            method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 (https enforced)
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"GitHub API {method} {path} failed: HTTP {exc.code}") from None


def env_settings() -> tuple[str, str, str, str]:
    repo, token = os.environ.get("GAA_DEMO_REPO"), os.environ.get("GAA_DEMO_TOKEN")
    if not repo or not token:
        raise SystemExit("live mode requires GAA_DEMO_REPO and GAA_DEMO_TOKEN")
    return (repo, token, os.environ.get("GAA_DEMO_BASE_BRANCH", "main"),
            os.environ.get("GAA_DEMO_API_URL", "https://api.github.com"))


def dry_run_pr() -> dict[str, Any]:
    """Return the deterministic PR a live run would open (mirrors the fixture)."""
    return {
        "number": 1,
        "title": "AI: widen default rate limit",
        "user": {"login": BOT_LOGIN},
        "head": {"sha": "0123456789abcdef0123456789abcdef01234567"},
        "base": {"ref": "main"},
        "labels": [{"name": AI_LABEL}],
        "simulated": True,
    }


def open_live_pr(suffix: str) -> dict[str, Any]:
    repo, token, base, api_url = env_settings()
    gh = Github(repo, token, api_url)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", suffix):
        raise SystemExit("--branch-suffix must match [A-Za-z0-9._-]{1,40}")
    branch = f"ai/demo-{suffix}"
    base_sha = gh.call("GET", f"/git/ref/heads/{base}")["object"]["sha"]
    gh.call("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": base_sha})
    gh.call("PUT", f"/contents/{CHANGE_PATH}", {
        "message": "AI: simulated demo change",
        "content": base64.b64encode(CHANGE_BODY.encode()).decode(),
        "branch": branch,
    })
    pr = gh.call("POST", "/pulls", {
        "title": "AI: simulated governed-autonomy demo change",
        "head": branch,
        "base": base,
        "body": "Simulated AI-authored change. Requires explicit human approval before merge.",
    })
    try:
        gh.call("POST", f"/issues/{pr['number']}/labels", {"labels": [AI_LABEL]})
    except SystemExit:
        print(f"warning: could not add '{AI_LABEL}' label; add it manually", file=sys.stderr)
    return {"number": pr["number"], "html_url": pr["html_url"], "head_sha": pr["head"]["sha"]}


def real_approvers(reviews: list[dict[str, Any]], head_sha: str, author: str) -> list[str]:
    """Logins whose latest review is APPROVED on the current head commit (author excluded)."""
    latest: dict[str, dict[str, Any]] = {}
    for review in reviews:
        if review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            latest[review["user"]["login"]] = review
    return sorted(
        login for login, review in latest.items()
        if review["state"] == "APPROVED" and review.get("commit_id") == head_sha and login != author
    )


def fetch_approvers(number: int) -> list[str]:
    repo, token, _base, api_url = env_settings()
    gh = Github(repo, token, api_url)
    pr = gh.call("GET", f"/pulls/{number}")
    reviews = gh.call("GET", f"/pulls/{number}/reviews?per_page=100")
    return real_approvers(reviews, pr["head"]["sha"], pr["user"]["login"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    op = sub.add_parser("open-pr", help="open (or simulate) the AI-authored PR")
    op.add_argument("--live", action="store_true", help="really call the GitHub API (default: dry run)")
    op.add_argument("--branch-suffix", default="run1")
    ap = sub.add_parser("approvals", help="live: list real human approvers of a PR's current head")
    ap.add_argument("--pr", type=int, required=True)
    args = parser.parse_args(argv)
    if args.cmd == "open-pr":
        out = open_live_pr(args.branch_suffix) if args.live else {"dry_run": True, "pull_request": dry_run_pr()}
    else:
        out = {"pr": args.pr, "approvers": fetch_approvers(args.pr)}
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
