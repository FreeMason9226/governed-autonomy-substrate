from governed_autonomy import build_demo_service, health_report


def test_bootstrap_wires_complete_governed_service():
    service, _, replay_log = build_demo_service()
    artifact = service.authorize(
        {"action": "write_file", "path": "out.txt", "content": "bootstrapped"},
        "demo-files-v1",
    )

    assert service.execute_json(artifact.to_json()) == "bootstrapped"
    assert health_report(replay_log=replay_log)["ok"] is True


def test_bootstrap_authorizes_job_specs_for_the_worker():
    service, _, _ = build_demo_service()
    artifact = service.authorize(
        {
            "action": "run_job",
            "image": "gas-ci:test",
            "command": ["python", "-c", "print(4242)"],
        },
        "demo-jobs-v1",
    )

    assert service.execute_json(artifact.to_json()) == {
        "image": "gas-ci:test",
        "command": ["python", "-c", "print(4242)"],
    }
