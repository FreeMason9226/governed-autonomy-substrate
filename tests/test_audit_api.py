import pytest

from governed_autonomy import ReplayLog


def test_audit_events_can_be_filtered_without_private_storage():
    log = ReplayLog()
    log.append("authorization:n1", {"type": "authorization", "nonce": "n1"})
    log.append(
        "execution:n1",
        {"type": "execution", "nonce": "n1", "status": "completed"},
    )

    assert len(log.events()) == 2
    assert log.events("authorization")[0]["nonce"] == "n1"
    assert log.events("execution")[0]["status"] == "completed"
    assert log.events_for_nonce("n1") == log.events()


def test_audit_event_filter_rejects_empty_type():
    with pytest.raises(ValueError, match="event_type"):
        ReplayLog().events("")


def test_audit_nonce_query_rejects_empty_nonce():
    with pytest.raises(ValueError, match="nonce"):
        ReplayLog().events_for_nonce("")
