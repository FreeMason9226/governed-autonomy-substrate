import json

from demo.document_access.run import run_demo


def test_demo_output_does_not_include_fixture_document_contents() -> None:
    _runtime, result = run_demo()

    output = json.dumps(result)

    assert "final_fixture_state" not in result
    assert "Restricted secret fixture" not in output
    assert "Confidential planning fixture" not in output
