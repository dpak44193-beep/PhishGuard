"""Tests for the deterministic decision engine."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.models.scan import ScanMode
from app.models.threat import RiskLevel
from app.services.decision_engine import DecisionEngine, DEFAULT_DECISION_THRESHOLDS
from cti.base import CTIResponse, CTIStatus


def make_cti(
    source: str,
    status: CTIStatus,
    score: float | None = 0.0,
    hit: bool | None = False,
) -> CTIResponse:
    return CTIResponse(source=source, status=status, hit=hit, score=score, details={})


class TestScoreComputation:
    def test_all_zero_gives_no_threat_detected(self):
        result = DecisionEngine.decide(0.0, [])
        assert result.risk_score == 0.0
        assert result.verdict == RiskLevel.NO_THREAT_DETECTED
        assert any("limited" in entry for entry in result.explanation)

    def test_pure_ml_score(self):
        result = DecisionEngine.decide(1.0, [])
        assert result.risk_score == 0.79
        assert result.verdict == RiskLevel.SUSPICIOUS

    def test_score_capped_at_one(self):
        result = DecisionEngine.decide(2.0, [])
        assert result.risk_score <= 1.0

    def test_score_is_rounded_to_4dp(self):
        result = DecisionEngine.decide(0.33333, [])
        assert result.risk_score == round(result.risk_score, 4)


class TestThresholds:
    def test_no_threat_detected_below_suspicious_threshold(self):
        result = DecisionEngine.decide(0.0, [])
        assert result.verdict == RiskLevel.NO_THREAT_DETECTED

    def test_suspicious_between_thresholds(self):
        score = (DEFAULT_DECISION_THRESHOLDS["suspicious"] + DEFAULT_DECISION_THRESHOLDS["malicious"]) / 2
        result = DecisionEngine.decide(score, [])
        assert result.verdict == RiskLevel.SUSPICIOUS

    def test_live_cti_hit_forces_malicious(self):
        ctis = [make_cti("virustotal", CTIStatus.LIVE, 1.0, hit=True)]
        result = DecisionEngine.decide(DEFAULT_DECISION_THRESHOLDS["suspicious"] + 0.05, ctis)
        assert result.verdict == RiskLevel.MALICIOUS
        assert result.risk_score >= 0.97

    def test_high_confidence_ml_without_live_cti_stays_suspicious(self):
        result = DecisionEngine.decide(0.96, [])
        assert result.verdict == RiskLevel.SUSPICIOUS

    def test_mock_hits_do_not_override_to_malicious(self):
        ctis = [make_cti("virustotal", CTIStatus.MOCK, 1.0, hit=True)]
        result = DecisionEngine.decide(0.2, ctis)
        assert result.verdict == RiskLevel.NO_THREAT_DETECTED


class TestExplanation:
    def test_no_explanation_when_all_clear(self):
        result = DecisionEngine.decide(0.0, [])
        assert any("limited" in entry for entry in result.explanation)

    def test_ml_explanation_above_50pct(self):
        result = DecisionEngine.decide(0.8, [])
        assert any("ML" in e for e in result.explanation)

    def test_vt_explanation_on_hit(self):
        ctis = [make_cti("virustotal", CTIStatus.LIVE, 0.5, hit=True)]
        result = DecisionEngine.decide(0.0, ctis)
        assert any("VirusTotal" in e for e in result.explanation)

    def test_urlhaus_explanation_on_hit(self):
        ctis = [make_cti("urlhaus", CTIStatus.LIVE, 1.0, hit=True)]
        result = DecisionEngine.decide(0.0, ctis)
        assert any("URLhaus" in e for e in result.explanation)

    def test_whois_explanation_on_hit(self):
        ctis = [CTIResponse(
            source="whois", status=CTIStatus.LIVE, hit=True, score=0.8,
            details={"domain_age_days": 3}
        )]
        result = DecisionEngine.decide(0.0, ctis)
        assert any("3 days" in e for e in result.explanation)

    def test_provider_status_explanation_when_unavailable(self):
        ctis = [make_cti("virustotal", CTIStatus.ERROR, None, None)]
        result = DecisionEngine.decide(0.0, ctis)
        assert any("status" in e for e in result.explanation)


class TestScanModes:
    def test_full_mode_when_all_providers_live(self):
        ctis = [
            make_cti("virustotal", CTIStatus.LIVE),
            make_cti("urlhaus", CTIStatus.LIVE),
            make_cti("whois", CTIStatus.LIVE),
        ]
        result = DecisionEngine.decide(0.2, ctis)
        assert result.scan_mode == ScanMode.FULL

    def test_ml_only_mode_when_cti_unavailable(self):
        ctis = [
            make_cti("virustotal", CTIStatus.UNKNOWN, None, None),
            make_cti("urlhaus", CTIStatus.ERROR, None, None),
            make_cti("whois", CTIStatus.TIMEOUT, None, None),
        ]
        result = DecisionEngine.decide(0.2, ctis)
        assert result.scan_mode == ScanMode.ML_ONLY

    def test_degraded_mode_when_mixed_provider_statuses(self):
        ctis = [
            make_cti("virustotal", CTIStatus.LIVE),
            make_cti("urlhaus", CTIStatus.ERROR, None, None),
            make_cti("whois", CTIStatus.MOCK),
        ]
        result = DecisionEngine.decide(0.2, ctis)
        assert result.scan_mode == ScanMode.DEGRADED
