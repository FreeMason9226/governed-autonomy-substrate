import json

from governed_autonomy import KeyPair, ReplayLog
from governed_autonomy.canonical import b64encode
from governed_autonomy.cli import main


def test_replay_certify_cli_verifies_an_independently_retained_anchor(tmp_path, capsys):
    replay_path = tmp_path / "replay.jsonl"
    anchor_path = tmp_path / "anchor.json"
    signer = KeyPair.generate("anchor-signer")
    replay = ReplayLog(replay_path)
    replay.append("frame-1", {"type": "authorization", "nonce": "nonce-1"})
    anchor = replay.create_anchor(signer)
    anchor_path.write_text(json.dumps(anchor.to_dict()), encoding="utf-8")
    public_key = b64encode(signer.public_key_bytes())

    assert (
        main(
            [
                "replay",
                "certify",
                str(replay_path),
                "--anchor",
                str(anchor_path),
                "--public-key",
                public_key,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["certified"] is True

    replay.append("frame-2", {"type": "execution", "nonce": "nonce-1", "status": "completed"})
    assert (
        main(
            [
                "replay",
                "certify",
                str(replay_path),
                "--anchor",
                str(anchor_path),
                "--public-key",
                public_key,
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["certified"] is False
