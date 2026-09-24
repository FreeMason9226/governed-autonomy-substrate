"""Run the local governance bottleneck and replay verification walkthrough."""

from governed_autonomy import AuthorizationError, AuthorizationIssuer, ExecutionBoundary, KeyPair, Policy, ReplayLog


def main() -> None:
    key = KeyPair.generate("demo-governance")
    replay = ReplayLog()
    policy = Policy("demo-read-v1", ("read",), {"read": ()}, {})
    issuer = AuthorizationIssuer(issuer=key, replay_log=replay, nonce_factory=lambda: "demo-nonce")
    boundary = ExecutionBoundary(replay_log=replay, issuer_keys={key.key_id: key.public_key})
    try:
        boundary.execute(None, lambda _: "forbidden")
    except AuthorizationError as error:
        print(f"without GAA: denied ({error})")
    artifact = issuer.authorize({"action": "read"}, policy)
    print(f"with GAA: {boundary.execute(artifact, lambda _: 'success')}")
    print(f"replay chain valid: {replay.verify_chain()}")


if __name__ == "__main__":
    main()