"""Repository-facing entry point for the independent replay verifier."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from governed_autonomy.verify_replay import main


if __name__ == "__main__":
    raise SystemExit(main())
