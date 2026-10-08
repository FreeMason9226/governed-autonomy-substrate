from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governed_autonomy import (
    ComplianceAuditor,
    InMemoryTraceRecorder,
    JSONLAuditAnchorSink,
    KeyPair,
    PolicyRegistry,
    ReplayLog,
    TraceContext,
    TrustStore,
)
from governed_autonomy.audit import sign_audit_anchor
from governed_autonomy.signing import LocalEd25519Signer


def test_independent_anchor_detects_rewritten_replay_history(tmp_path):
    replay = ReplayLog()
    replay.append("one", {"type": "authorization", "nonce": "nonce-1"})
    signer = LocalEd25519Signer("audit-key")
    sink = JSONLAuditAnchorSink(tmp_path / "independent" / "anchors.jsonl")

    anchor = replay.anchor(signer, sink)

    assert sink.anchors() == (anchor,)
    assert anchor.verify(Ed25519PublicKey.from_public_bytes(signer.public_key_bytes()))
    rewritten = ReplayLog()
    rewritten.append("one", {"type": "authorization", "nonce": "nonce-2"})
    replacement = sign_audit_anchor(rewritten.verify_integrity(), signer)
    assert replacement.head_hash != anchor.head_hash


def test_compliance_evidence_includes_soc2_and_iso_control_evidence():
    issuer = KeyPair.generate("evidence-issuer")
    trust = TrustStore()
    trust.add(issuer.key_id, issuer.public_key)
    replay = ReplayLog()
    replay.append("one", {"type": "authorization", "nonce": "nonce-1"})

    bundle = ComplianceAuditor(
        replay_log=replay,
        trust_store=trust,
        policy_registry=PolicyRegistry(trust_store=trust),
    ).evidence_bundle()

    assert bundle["replay_integrity"]["ok"] is True
    assert {(item["framework"], item["control_id"]) for item in bundle["controls"]} >= {
        ("SOC 2", "CC7.2"),
        ("ISO/IEC 27001:2022", "A.8.15"),
    }


def test_trace_context_is_strict_and_records_no_sensitive_request_data():
    context = TraceContext.from_traceparent(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    )
    recorder = InMemoryTraceRecorder()
    assert context is not None

    recorder.record("gas.http.response", {"http.response.status_code": 200}, context)

    assert TraceContext.from_traceparent("00-not-valid-00f067aa0ba902b7-01") is None
    assert recorder.events == [
        {
            "name": "gas.http.response",
            "attributes": {"http.response.status_code": 200},
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        }
    ]
