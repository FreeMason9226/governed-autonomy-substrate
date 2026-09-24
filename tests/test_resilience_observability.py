import pytest

from governed_autonomy import ResilienceController, ResilienceMode
from governed_autonomy.observability import RuntimeMetrics


def test_resilience_modes_fail_closed_until_recovery():
    controller = ResilienceController()
    assert controller.permits_execution()
    controller.transition(ResilienceMode.DEGRADED, "anchor timeout")
    assert not controller.permits_execution()
    controller.transition(ResilienceMode.SAFE, "replay mismatch")
    controller.transition(ResilienceMode.RECOVERY, "operator approved recovery")
    controller.transition(ResilienceMode.NORMAL, "integrity checks passed")
    assert controller.permits_execution()
    with pytest.raises(ValueError, match="invalid resilience"):
        controller.transition(ResilienceMode.RECOVERY, "illegal direct recovery")


def test_cam_ari_and_ats_metrics_are_exported():
    metrics = RuntimeMetrics("gas")
    metrics.record_risk(0.7)
    metrics.record_drift_alert()
    metrics.set_ats_score(0.9)
    metrics.record_replay_verification_failure()
    metrics.record_failed_anchor()
    metrics.record_unauthorized_signing_attempt()
    exported = metrics.to_dict()
    assert exported["agency_risk_index"] == 0.7
    assert exported["drift_alerts"] == 1
    assert exported["ats_score"] == 0.9
    assert exported["replay_verification_failures"] == 1
    assert exported["failed_anchors"] == 1
    assert exported["unauthorized_signing_attempts"] == 1