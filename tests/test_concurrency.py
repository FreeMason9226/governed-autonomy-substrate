from concurrent.futures import ThreadPoolExecutor

from test_authorization import setup_artifact


def test_concurrent_delivery_invokes_action_once():
    artifact, boundary, log = setup_artifact()
    calls = []

    def action(_):
        calls.append("called")
        return "ok"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: _execute(boundary, artifact, action), range(8)))

    assert results.count("ok") == 1
    assert len(calls) == 1
    assert len(log.events("execution")) == 1


def _execute(boundary, artifact, action):
    try:
        return boundary.execute(artifact, action)
    except Exception:
        return None
