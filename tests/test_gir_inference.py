import json
from pathlib import Path

from training.gir_inference import extract_obligations


def test_gir_inference_regression_fixtures_are_deterministic():
    fixture_path = Path("training/inference_regression.jsonl")
    for line in fixture_path.read_text(encoding="utf-8").splitlines():
        fixture = json.loads(line)
        assert extract_obligations(fixture["text"]) == fixture["expected_obligations"]