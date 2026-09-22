import time
import uuid

from .crypto import KeyPair
from .engine import ExecutionBoundary
from .models import GovernanceAuthorizationArtifact
from .replay import ReplayLog


def main() -> None:
    issuer = KeyPair.generate()
    log = ReplayLog("replay.jsonl")
    request = {"action": "send_email", "recipient": "user@example.com", "body": "Hello"}
    decision = {"allow": True, "allowed_actions": ["send_email"], "policy": "demo-v1"}
    nonce = uuid.uuid4().hex
    unsigned = GovernanceAuthorizationArtifact(
        request,
        decision,
        int(time.time()) + 300,
        nonce,
        f"authorization:{nonce}",
        issuer.key_id,
        "",
    )
    frame = log.append(
        f"authorization:{nonce}",
        {
            "type": "authorization",
            "nonce": nonce,
            "artifact_payload": unsigned.unsigned_payload().decode("utf-8"),
        },
    )
    artifact = GovernanceAuthorizationArtifact.issue(
        action_request=request,
        decision=decision,
        expires_at=unsigned.expires_at,
        nonce=nonce,
        replay_frame_ref=frame.frame_id,
        issuer=issuer,
    )
    boundary = ExecutionBoundary(
        replay_log=log, issuer_keys={issuer.key_id: issuer.public_key}
    )
    print(boundary.execute(artifact, lambda action: f"executed {action['action']}"))


if __name__ == "__main__":
    main()
