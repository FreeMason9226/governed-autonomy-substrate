# Governed-autonomy PR demo

Lifecycle: **AI opens PR -> policy flags it -> human explicitly approves -> signed GAA (Governed Autonomy Attestation) generated and verified -> merge-ready event -> hash-chained audit JSON.**

The tooling never approves or merges a PR. In simulation the human approval is *modeled* and every record is marked `simulated: true`; in live mode the approval is read from real GitHub reviews.

## Prerequisites

- Python 3.11+ and `pip install -e .` (provides `cryptography`; no other dependencies).
- Live mode only: a GitHub repository you can write to, and a token.

## 1. Run the full simulation locally (no secrets)

```bash
python -m demo.simulate --out demo-out
```

Expected output:

```json
{
  "audit_chain_valid": true,
  "audit_events": ["pr_opened", "policy_evaluated", "human_approved", "gaa_signed", "gaa_verified", "merge_ready"],
  "gaa_valid": true,
  "merge_ready": true,
  "policy_status": "flag_requires_human_approval"
}
```

(`audit_events` is printed one per line.) Files written to `demo-out/`: `policy-result.json`, `gaa.json`, `audit.json`. The simulation is deterministic (fixed clock, fixed public demo key) so repeated runs are byte-identical.

Self-check: `python -m pytest tests/test_demo_gaa_pr.py`.

## 2. Observe the policy flag and the human step

```bash
python -m demo.simulate --out demo-out --no-approval   # stops at the flag; no GAA is issued
python -m demo.pr_policy --event demo/fixtures/ai_change.json
```

`status` is `pass` or `flag_requires_human_approval` (see `demo/schemas/policy_result.schema.json`). The fixture is AI-authored and touches `src/`, so it is flagged. The check always exits 0: a flag is a result, not a tool failure. The human step is a normal GitHub review: a reviewer other than the author clicks **Approve** on the PR's current head commit.

## 3. Optionally open the PR in live mode

| Variable | Meaning |
|---|---|
| `GAA_DEMO_REPO` | `owner/name` (required) |
| `GAA_DEMO_TOKEN` | token with contents:write + pull-requests:write (required, never printed) |
| `GAA_DEMO_BASE_BRANCH` | base branch, default `main` |
| `GAA_DEMO_API_URL` | default `https://api.github.com` (https only) |
| `GAA_DEMO_SIGNING_KEY` | base64 of a 32-byte Ed25519 seed, for live signing |

```bash
python -m demo.bot open-pr                              # dry run, no network
export GAA_DEMO_REPO=you/your-fork GAA_DEMO_TOKEN=...   # use a fine-grained token on a throwaway repo
python -m demo.bot open-pr --live --branch-suffix run1
```

Then have a human approve the PR on GitHub and confirm the real approval:

```bash
python -m demo.bot approvals --pr 123
```

Only approvals from non-authors on the current head commit are listed (later changes-requested or stale approvals are ignored).

## 4. Generate and verify the signed GAA

```bash
python -m demo.attest sign --policy-result demo-out/policy-result.json \
  --approver simulated-human-reviewer --issued-at 2026-01-01T00:00:03Z --output demo-out/gaa.json
python -m demo.attest verify demo-out/gaa.json            # prints "valid", exit 0
python -m demo.attest verify-audit demo-out/audit.json    # checks the hash chain
```

For a real approval add `--live` (uses `GAA_DEMO_SIGNING_KEY`), pass the approver login from `demo.bot approvals`, and verify with `--trusted-public-key <base64 key you published>`. Without a trusted key, `verify` only proves the record is internally consistent. Generate a key seed with `python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"` and keep it secret.

Tamper check: edit `claims.approved_by` in `gaa.json`; `verify` prints `INVALID` and exits 1.

## 5. Policy workflow and artifact

`demo/workflow.yml` is the inspectable workflow; `.github/workflows/demo-policy.yml` is its identical mirror (GitHub only runs workflows from `.github/workflows/`). It runs on `pull_request_target` for relevant paths with `contents: read` and `pull-requests: read`. It checks out only the trusted default branch, reads the PR purely as API data, and never executes PR code or interpolates PR text into shell. It uploads `policy-result` (`policy-result.json`).

Download the artifact (token needs `actions:read`):

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://api.github.com/repos/OWNER/REPO/actions/runs?event=pull_request_target&per_page=1"
curl -s -H "Authorization: Bearer $TOKEN" "https://api.github.com/repos/OWNER/REPO/actions/runs/RUN_ID/artifacts"
curl -sL -H "Authorization: Bearer $TOKEN" -o policy-result.zip "https://api.github.com/repos/OWNER/REPO/actions/artifacts/ARTIFACT_ID/zip"
unzip policy-result.zip && cat policy-result.json
```

Or use `gh run download RUN_ID -n policy-result`. Fetch a stored audit/GAA file the same way, e.g. from a repository path:
`curl -s -H "Accept: application/vnd.github.raw" -H "Authorization: Bearer $TOKEN" https://api.github.com/repos/OWNER/REPO/contents/PATH/audit.json`.
Then run `python -m demo.attest verify-audit audit.json`.

## Security caveats

- The simulation signing key is derived from a public constant: simulated GAAs prove nothing and are labeled `approval_simulated: true`.
- The audit file is "immutable-style": a hash chain detects edits but the file is not write-protected; store it in append-only/WORM storage for real use. A rewritten chain can only be detected against an externally held head hash.
- Never commit tokens or `GAA_DEMO_SIGNING_KEY`; the scripts never print them.
- `pull_request_target` has access to repository secrets context; do not add steps that check out or run PR head code.
- Live mode creates a branch, a file under `src/governed_autonomy/`, and a PR on the target repo; use a throwaway repository.
