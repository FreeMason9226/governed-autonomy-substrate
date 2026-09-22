from governed_autonomy import build_demo_service, health_report


def test_bootstrap_wires_complete_governed_service():
    service, _, replay_log = build_demo_service()
    artifact = service.authorize(
        {"action": "write_file", "path": "out.txt", "content": "bootstrapped"},
        "demo-files-v1",
    )

    assert service.execute_json(artifact.to_json()) == "bootstrapped"
    assert health_report(replay_log=replay_log)["ok"] is True
