"""Split the combined anchoring vector into CLI input files."""

import json
from pathlib import Path


def main() -> None:
    source = Path("replay/tests/anchoring_vectors.json")
    vector = json.loads(source.read_text(encoding="utf-8"))
    target = Path("evidence/anchor-sample")
    target.mkdir(parents=True, exist_ok=True)
    (target / "record.json").write_text(json.dumps(vector["record"], indent=2) + "\n", encoding="utf-8")
    (target / "frame.json").write_text(json.dumps(vector["frame"], indent=2) + "\n", encoding="utf-8")
    (target / "selection.json").write_text(json.dumps(vector["selection"], indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()