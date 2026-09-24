import json
from pathlib import Path

from governed_autonomy.verify_replay import verify_replay


def test_independent_verify_replay_accepts_published_vector():
    vector = json.loads(Path("replay/tests/anchoring_vectors.json").read_text(encoding="utf-8"))
    verify_replay(vector["record"], vector["frame"], vector["selection"])