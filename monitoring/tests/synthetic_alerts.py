from pathlib import Path

from governed_autonomy.observability import RuntimeMetrics


def test_synthetic_integrity_alert_counters():
    metrics = RuntimeMetrics("synthetic")
    metrics.record_risk(0.95)
    metrics.record_drift_alert()
    metrics.record_replay_verification_failure()
    metrics.record_failed_anchor()
    metrics.record_unauthorized_signing_attempt()
    values = metrics.to_dict()
    assert values["agency_risk_index"] > 0.9
    assert values["drift_alerts"] == 1
    assert values["replay_verification_failures"] == 1
    assert values["failed_anchors"] == 1
    assert values["unauthorized_signing_attempts"] == 1


def test_alert_rules_name_all_required_conditions():
    rules = Path("deploy/observability/alerts.yaml").read_text(encoding="utf-8")
    for alert in ("GASReplayVerificationMismatch", "GASFailedAnchoring", "GASUnauthorizedSigningAttempt"):
        assert alert in rules