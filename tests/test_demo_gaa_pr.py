import json

from demo import attest, bot, pr_policy, simulate


def test_policy_flags_ai_change_and_passes_docs_only() -> None:
    pr = bot.dry_run_pr()
    flagged = pr_policy.evaluate(pr, [{"filename": "src/x.py", "additions": 1, "deletions": 0}])
    assert flagged["status"] == "flag_requires_human_approval"
    assert flagged == pr_policy.evaluate(pr, [{"filename": "src/x.py", "additions": 1, "deletions": 0}])
    ok = pr_policy.evaluate(pr, [{"filename": "docs/a.md", "additions": 1, "deletions": 0}])
    assert ok["status"] == "pass" and not ok["requires_human_approval"]


def test_simulation_lifecycle_and_tamper_detection(tmp_path) -> None:
    summary = simulate.run(str(tmp_path))
    assert summary["merge_ready"] and summary["gaa_valid"] and summary["audit_chain_valid"]
    gaa = json.loads((tmp_path / "gaa.json").read_text())
    assert attest.verify_gaa(gaa)
    gaa["claims"]["approved_by"] = "someone-else"
    assert not attest.verify_gaa(gaa)
    records = json.loads((tmp_path / "audit.json").read_text())["records"]
    records[1]["data"]["status"] = "pass"
    assert not attest.AuditLog.verify(records)


def test_no_approval_means_no_gaa(tmp_path) -> None:
    summary = simulate.run(str(tmp_path), approve=False)
    assert not summary["merge_ready"] and not (tmp_path / "gaa.json").exists()


def test_real_approvers_requires_current_head_and_excludes_author() -> None:
    reviews = [
        {"user": {"login": "a"}, "state": "APPROVED", "commit_id": "h"},
        {"user": {"login": "b"}, "state": "APPROVED", "commit_id": "old"},
        {"user": {"login": "bot"}, "state": "APPROVED", "commit_id": "h"},
        {"user": {"login": "c"}, "state": "APPROVED", "commit_id": "h"},
        {"user": {"login": "c"}, "state": "CHANGES_REQUESTED", "commit_id": "h"},
    ]
    assert bot.real_approvers(reviews, "h", "bot") == ["a"]
