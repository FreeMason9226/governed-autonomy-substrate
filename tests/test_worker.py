from governed_autonomy import InMemoryControlPlaneRepository, create_app
from governed_autonomy.bootstrap import build_platform_demo
from governed_autonomy.worker import WorkerService


def test_worker_executes_authorized_artifacts_and_marks_dead_letter_on_retries():
    platform, service, _, _ = build_platform_demo()
    control_plane = InMemoryControlPlaneRepository()
    for policy in service.policies.policies():
        control_plane.save_policy(policy, published=True)
    app = create_app(platform=platform, control_plane=control_plane, bearer_token="test-token")
    _ = app

    authorized = control_plane.create_authorization(
        policy_id="demo-files-v1",
        request_payload={"action": "write_file", "path": "out.txt", "content": "worker"},
        context={},
        mesh_inputs=[],
        request_digest="digest-1",
        idempotency_key=None,
        ttl_seconds=300,
        required_approvals=0,
        max_attempts=2,
    )
    artifact = platform.authorize(
        {"action": "write_file", "path": "out.txt", "content": "worker"},
        "demo-files-v1",
        context={"request_id": "worker-req-1"},
    )
    control_plane.update_authorization(
        authorized.authorization_id,
        status="authorized",
        artifact_payload=artifact.to_dict(),
        expires_at=artifact.expires_at,
    )

    worker = WorkerService(control_plane=control_plane, platform=platform)
    result = worker.run_once()
    assert result is not None
    assert result.status == "executed"
    assert control_plane.get_authorization(authorized.authorization_id).result_payload == "worker"

    failing_platform, _, _, _ = build_platform_demo()
    failing_platform.service.actions["write_file"] = lambda request: (_ for _ in ()).throw(RuntimeError("boom"))
    retry_record = control_plane.create_authorization(
        policy_id="demo-files-v1",
        request_payload={"action": "write_file", "path": "out.txt", "content": "fail"},
        context={},
        mesh_inputs=[],
        request_digest="digest-2",
        idempotency_key=None,
        ttl_seconds=300,
        required_approvals=0,
        max_attempts=1,
    )
    retry_artifact = failing_platform.authorize(
        {"action": "write_file", "path": "out.txt", "content": "fail"},
        "demo-files-v1",
        context={"request_id": "worker-req-2"},
    )
    control_plane.update_authorization(
        retry_record.authorization_id,
        status="authorized",
        artifact_payload=retry_artifact.to_dict(),
        expires_at=retry_artifact.expires_at,
    )
    failing_worker = WorkerService(control_plane=control_plane, platform=failing_platform, retry_delay_seconds=0)
    failed = failing_worker.run_once()
    assert failed is not None
    assert failed.status == "dead_letter"
