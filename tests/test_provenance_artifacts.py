import json
from pathlib import Path


def test_browser_context_and_patent_support_are_present():
    context = json.loads(Path("tools/browser_context.json").read_text(encoding="utf-8"))
    assert context["edge_all_open_tabs"]
    assert "traceability" in context["note"]
    assert Path("PATENT_SUPPORT.md").stat().st_size > 0