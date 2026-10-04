import json
import subprocess
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from governed_autonomy import (
    AuthorizationError,
    AuthorizationIssuer,
    ExecutionBoundary,
    GovernedService,
    KeyPair,
    Policy,
    ReplayLog,
    SQLiteJobStore,
)
from governed_autonomy.canonical import b64decode
from governed_autonomy.key_lifecycle import ACTIVE, REVOKED, ROTATED, KeyLifecycleManager
from governed_autonomy.kms_backends import AwsKmsBackend, KMSBackendError
from governed_autonomy.signing import KMSSigner
from governed_autonomy.trust import TrustStore
from governed_autonomy.worker import ContainerSandbox, WorkerRuntime


class FakeKMS:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.calls = []

    def sign(self, **kw):
        self.calls.append(kw)
        return {"Signature": self.key.sign(kw["Message"])}

    def get_public_key(self, **kw):
        der = self.key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return {"PublicKey": der}


def test_aws_kms_backend_signs_with_kms_signer_and_verifies():
    fake = FakeKMS()
    signer = KMSSigner("k1", AwsKmsBackend(fake))
    sig = signer.sign(b"payload")
    fake.key.public_key().verify(b64decode(sig), b"payload")
    assert fake.calls[0]["MessageType"] == "RAW"
    assert signer.public_key_bytes() == fake.key.public_key().public_bytes_raw()


def test_aws_kms_backend_fails_closed():
    class Boom:
        def sign(self, **kw):
            raise RuntimeError("secret detail")

        def get_public_key(self, **kw):
            return {}

    backend = AwsKmsBackend(Boom())
    with pytest.raises(KMSBackendError) as err:
        backend.sign("k", b"x")
    assert "secret detail" not in str(err.value)
    with pytest.raises(KMSBackendError):
        backend.public_key_bytes("k")


def test_key_lifecycle_rotation_and_revocation():
    trust = TrustStore()
    mgr = KeyLifecycleManager(trust)
    a, b = KeyPair.generate(), KeyPair.generate()
    mgr.register("a", "aws", a.public_key.public_bytes_raw())
    mgr.rotate("a", "b", "aws", b.public_key.public_bytes_raw())
    assert mgr.get("a").status == ROTATED and mgr.get("b").status == ACTIVE
    assert trust.resolve("a") is not None and mgr.active_key().key_id == "b"
    with pytest.raises(ValueError):
        mgr.rotate("a", "c", "aws", b"x" * 32)
    mgr.revoke("a")
    assert mgr.get("a").status == REVOKED and trust.resolve("a") is None
    assert [k.key_id for k in mgr.trust_list()] == ["b"]
    with pytest.raises(KeyError):
        mgr.revoke("missing")


def _sandbox(runner, images=("alpine:3.20",)):
    return ContainerSandbox(images, runner=runner)


def test_sandbox_hardening_allowlist_and_secret_handling():
    seen = {}

    def runner(argv, **kw):
        seen.update(argv=argv, env=kw["env"])
        return SimpleNamespace(returncode=0, stdout=b"token=s3cr3t ok", stderr=b"")

    box = _sandbox(runner)
    result = box.execute("alpine:3.20", ["echo", "hi; rm -rf /"], {"API_KEY": "s3cr3t"})
    argv = seen["argv"]
    assert "--network=none" in argv and "--read-only" in argv and "--cap-drop=ALL" in argv
    assert "s3cr3t" not in " ".join(argv) and seen["env"]["API_KEY"] == "s3cr3t"
    assert "s3cr3t" not in result.output and result.ok
    with pytest.raises(ValueError):
        box.build_command("evil:latest", ["x"], [])
    with pytest.raises(ValueError):
        box.build_command("alpine:3.20", ["x"], ["BAD NAME"])


def test_sandbox_timeout_maps_to_timeout_error():
    def runner(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 1)

    with pytest.raises(TimeoutError):
        _sandbox(runner).execute("alpine:3.20", ["x"], {})


class StaticSecrets:
    def fetch(self, policy_id, keys):
        return {k: "v-" + k for k in keys}


def _service():
    issuer = KeyPair.generate()
    log = ReplayLog()
    return GovernedService(
        issuer=AuthorizationIssuer(issuer=issuer, replay_log=log),
        boundary=ExecutionBoundary(replay_log=log, issuer_keys={issuer.key_id: issuer.public_key}),
        policies={
            "jobs-v1": Policy(
                "jobs-v1",
                ("run_job",),
                {"run_job": ("image", "command")},
                {"run_job": {}},
            )
        },
        actions={"run_job": lambda request: dict(request)},
    )


def test_e2e_authorized_job_runs_in_sandbox_and_replay_is_one_shot():
    service = _service()
    calls = []

    def runner(argv, **kw):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=b"done", stderr=b"")

    store = SQLiteJobStore()
    artifact = service.authorize(
        {"action": "run_job", "image": "alpine:3.20", "command": ["echo", "hi"]}, "jobs-v1"
    )
    store.enqueue(
        # unsigned queue fields must be ignored in favour of the signed request
        {"artifact": artifact.to_json(), "image": "evil:latest", "command": ["rm"]},
        idempotency_key="j1",
        max_attempts=1,
    )
    worker = WorkerRuntime(
        store,
        authorizer=lambda p: service.execute_json(p["artifact"]),
        secrets=StaticSecrets(),
        sandbox=_sandbox(runner),
        retry_delay=0,
    )
    job = worker.process_once()
    assert job is not None and job.status == "succeeded"
    assert calls[0][-2:] == ["echo", "hi"] and "evil:latest" not in calls[0]

    # replaying the same artifact is rejected by the barrier -> dead letter, no execution
    store.enqueue({"artifact": artifact.to_json()}, idempotency_key="j2", max_attempts=1)
    assert worker.process_once().status == "dead_letter"
    assert len(calls) == 1
    with pytest.raises(AuthorizationError):
        service.execute_json(artifact.to_json())


def test_worker_denies_unauthorized_job_without_running():
    store = SQLiteJobStore()
    store.enqueue({"image": "alpine:3.20", "command": ["x"]}, idempotency_key="u", max_attempts=1)

    def deny(_):
        raise AuthorizationError("no")

    def runner(*a, **kw):
        raise AssertionError("must not run")

    worker = WorkerRuntime(
        store, authorizer=deny, secrets=StaticSecrets(), sandbox=_sandbox(runner), retry_delay=0
    )
    assert worker.process_once().status == "dead_letter"


def test_cli_login_and_replay_verify(tmp_path, monkeypatch, capsys):
    from governed_autonomy import cli

    monkeypatch.setenv("GAS_HOME", str(tmp_path))
    monkeypatch.delenv("GOVERNED_AUTONOMY_OPERATOR_TOKEN", raising=False)
    assert cli.main(["auth", "login", "--api-url", "http://x:1", "--token", "tok"]) == 0
    assert json.loads((tmp_path / "credentials.json").read_text())["token"] == "tok"
    assert cli.main(["auth", "login"]) == 1

    log_path = tmp_path / "replay.jsonl"
    log = ReplayLog(log_path)
    log.append("f1", {"type": "x"})
    capsys.readouterr()
    assert cli.main(["replay", "verify", str(log_path)]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    log_path.write_text(log_path.read_text().replace('"x"', '"y"'))
    assert cli.main(["replay", "verify", str(log_path)]) == 1


def test_cli_http_commands_use_bearer_token(tmp_path, monkeypatch, capsys):
    from governed_autonomy import cli

    monkeypatch.setenv("GAS_HOME", str(tmp_path))
    cli.save_credentials("http://api:1", "tok")
    captured = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"keys": []}'

    def fake_urlopen(request, timeout):
        captured["url"], captured["auth"] = request.full_url, request.get_header("Authorization")
        return Resp()

    monkeypatch.setattr(cli, "urlopen", fake_urlopen)
    assert cli.main(["operator-key", "list"]) == 0
    assert captured == {"url": "http://api:1/admin/operator-keys", "auth": "Bearer tok"}


def test_cli_job_submit_and_status(tmp_path, monkeypatch, capsys):
    import json

    from governed_autonomy import cli

    calls = []
    monkeypatch.setattr(
        cli, "_request", lambda method, path, body=None: calls.append((method, path, body)) or {"ok": 1}
    )
    artifact = tmp_path / "gaa.json"
    artifact.write_text('{"b": 2, "a": 1}')
    assert cli.main(["job", "submit", str(artifact), "--max-attempts", "5"]) == 0
    method, path, body = calls[0]
    assert (method, path) == ("POST", "/admin/jobs")
    assert body["artifact"] == {"a": 1, "b": 2} and body["max_attempts"] == 5
    assert len(body["idempotency_key"]) == 64
    assert cli.main(["job", "submit", str(artifact), "--idempotency-key", "k1"]) == 0
    assert calls[1][2]["idempotency_key"] == "k1"
    assert cli.main(["job", "status", "a/b"]) == 0
    assert calls[2][:2] == ("GET", "/admin/jobs/a%2Fb")
    artifact.write_text("[1]")
    assert cli.main(["job", "submit", str(artifact)]) == 1
    assert json.loads(capsys.readouterr().out.split("}")[0] + "}") == {"ok": 1}
