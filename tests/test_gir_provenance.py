import hashlib
import json
from pathlib import Path


def test_gir_smoke_checkpoint_hash_matches_manifest():
    root = Path("gir/train")
    manifest = json.loads((root / "checkpoint_manifest.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256((root / "checkpoint_smoke.json").read_bytes()).hexdigest()
    assert manifest["checkpoint_sha256"] == digest