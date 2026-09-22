from governed_autonomy import build_demo_service


def test_service_audit_report_includes_action_policy_and_history():
    service, _, _ = build_demo_service()
    artifact = service.authorize(
        {
            "action": "write_file",
            "path": "out.txt",
            "content": "audit",
        },
        "demo-files-v1",
    )
    service.execute(artifact)

    report = service.audit_report()

    assert report["actions"] == ["write_file"]
    assert report["policy_ids"] == ["demo-files-v1"]
    assert report["audit_summary"]["authorization_count"] == 1
    assert report["audit_summary"]["execution_count"] == 1
    assert report["health"]["ok"] is True
