import asyncio
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from app.config import settings
from app.models.scan import ScanMode
from app.services.decision_engine import DecisionEngine
from app.services.ml_service import MLService
from cti.base import CTIResponse, CTIStatus
from cti.mock_adapters import MockVirusTotalAdapter
from cti import urlhaus, virustotal, whois_lookup
from ml.features.extractor import FEATURE_ORDER, FEATURE_SCHEMA_VERSION


class FixedModel:
    n_features_in_ = len(FEATURE_ORDER)

    def predict_proba(self, values):
        return np.tile([0.8, 0.2], (len(values), 1))


def make_bundle():
    return {
        "base_model": FixedModel(),
        "feature_order": list(FEATURE_ORDER),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "version": "test-model-v1",
        "training_data": {"kind": "verified_test_data"},
        "model_metadata": {
            "artifact_version": "test-model-v1",
            "training_date_utc": "2026-10-10T00:00:00+00:00",
            "dataset_sources": {"source_url": "https://example.org/data"},
            "feature_schema": {
                "version": FEATURE_SCHEMA_VERSION,
                "names": list(FEATURE_ORDER),
                "pipeline_steps": [],
            },
            "test_metrics": {"f1": 0.9},
        },
    }


def test_model_loader_checks_schema_and_exposes_training_metadata(monkeypatch, tmp_path):
    model_path = tmp_path / "model.joblib"
    model_path.touch()
    monkeypatch.setattr(MLService, "_bundle", None)
    monkeypatch.setattr(settings, "ml_model_path", str(model_path))
    monkeypatch.setattr("app.services.ml_service.joblib.load", lambda _: make_bundle())

    MLService.load()

    assert MLService.predict(np.zeros(len(FEATURE_ORDER))) == 0.2
    assert MLService.metadata()["dataset_sources"]["source_url"] == "https://example.org/data"


def test_model_loader_rejects_schema_mismatch_without_caching(monkeypatch, tmp_path):
    model_path = tmp_path / "model.joblib"
    model_path.touch()
    bundle = make_bundle()
    bundle["feature_order"] = list(reversed(FEATURE_ORDER))
    monkeypatch.setattr(MLService, "_bundle", None)
    monkeypatch.setattr(settings, "ml_model_path", str(model_path))
    monkeypatch.setattr("app.services.ml_service.joblib.load", lambda _: bundle)

    with pytest.raises(ValueError, match="feature order"):
        MLService.load()
    assert MLService._bundle is None


def test_model_loader_fails_when_artifact_is_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(MLService, "_bundle", None)
    monkeypatch.setattr(settings, "ml_model_path", str(tmp_path / "missing-model.joblib"))

    with pytest.raises(FileNotFoundError, match="Model not found"):
        MLService.load()

    assert MLService._bundle is None


def test_inference_rejects_wrong_feature_vector_shape(monkeypatch, tmp_path):
    model_path = tmp_path / "model.joblib"
    model_path.touch()
    monkeypatch.setattr(MLService, "_bundle", None)
    monkeypatch.setattr(settings, "ml_model_path", str(model_path))
    monkeypatch.setattr("app.services.ml_service.joblib.load", lambda _: make_bundle())
    MLService.load()

    with pytest.raises(ValueError, match="ordered features"):
        MLService.predict(np.zeros(len(FEATURE_ORDER) - 1))


def test_inference_rejects_non_finite_features(monkeypatch, tmp_path):
    model_path = tmp_path / "model.joblib"
    model_path.touch()
    monkeypatch.setattr(MLService, "_bundle", None)
    monkeypatch.setattr(settings, "ml_model_path", str(model_path))
    monkeypatch.setattr("app.services.ml_service.joblib.load", lambda _: make_bundle())
    MLService.load()

    features = np.zeros(len(FEATURE_ORDER))
    features[0] = np.nan
    with pytest.raises(ValueError, match="non-finite"):
        MLService.predict(features)


def test_optional_virustotal_does_not_degrade_live_configured_providers():
    results = [
        CTIResponse(
            source="virustotal",
            status=CTIStatus.NOT_CONFIGURED,
            hit=None,
            score=None,
        ),
        CTIResponse(source="urlhaus", status=CTIStatus.LIVE, hit=False, score=0.0),
        CTIResponse(source="whois", status=CTIStatus.LIVE, hit=False, score=0.0),
    ]

    result = DecisionEngine.decide(0.1, results)

    assert result.scan_mode == ScanMode.FULL
    assert any("not proof" in explanation for explanation in result.explanation)
    assert not any("VirusTotal status" in explanation for explanation in result.explanation)


def test_provider_errors_remain_distinct_from_no_match():
    results = [
        CTIResponse(
            source="virustotal",
            status=CTIStatus.NOT_CONFIGURED,
            hit=None,
            score=None,
        ),
        CTIResponse(
            source="urlhaus",
            status=CTIStatus.ERROR,
            hit=None,
            score=None,
            error="request failed",
        ),
        CTIResponse(source="whois", status=CTIStatus.LIVE, hit=False, score=0.0),
    ]

    result = DecisionEngine.decide(0.1, results)

    assert result.scan_mode == ScanMode.DEGRADED
    assert any("URLhaus status: error" in explanation for explanation in result.explanation)
    assert any("not proof" in explanation for explanation in result.explanation)


def test_mock_provider_placeholder_does_not_fabricate_a_match():
    response = asyncio.run(MockVirusTotalAdapter().lookup("https://example.invalid/"))

    assert response.status == CTIStatus.MOCK
    assert response.hit is None
    assert response.score is None
    assert response.details["provider_request_performed"] is False


def test_virustotal_without_api_key_is_explicitly_not_configured(monkeypatch):
    async def stub_urlhaus_lookup(self, url):
        return CTIResponse(
            source="urlhaus",
            status=CTIStatus.LIVE,
            hit=False,
            score=0.0,
        )

    async def stub_whois_lookup(self, url):
        return CTIResponse(
            source="whois",
            status=CTIStatus.LIVE,
            hit=False,
            score=0.0,
        )

    monkeypatch.setattr(settings, "cti_mock", False)
    monkeypatch.setattr(settings, "virustotal_api_key", "")
    monkeypatch.setattr(urlhaus.URLhausAdapter, "lookup", stub_urlhaus_lookup)
    monkeypatch.setattr(whois_lookup.WHOISAdapter, "lookup", stub_whois_lookup)

    from app.services.cti_service import enrich

    responses = asyncio.run(enrich("https://example.invalid/"))

    virustotal_result = next(item for item in responses if item.source == "virustotal")
    assert virustotal_result.status == CTIStatus.NOT_CONFIGURED
    assert virustotal_result.hit is None
    assert virustotal_result.score is None
    assert virustotal_result.error is None


def test_virustotal_not_found_does_not_submit_url(monkeypatch):
    calls = {"get": 0, "post": 0}

    class Response:
        status_code = 404

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, *args, **kwargs):
            calls["get"] += 1
            return Response()

        async def post(self, *args, **kwargs):
            calls["post"] += 1
            raise AssertionError("URL must not be submitted for analysis")

    monkeypatch.setattr(virustotal, "_VT_MIN_GAP", 0)
    monkeypatch.setattr(virustotal.httpx, "AsyncClient", lambda **kwargs: Client())

    result = asyncio.run(
        virustotal.VirusTotalAdapter("test-key").lookup("https://example.invalid/")
    )

    assert result.status == CTIStatus.LIVE
    assert result.hit is False
    assert result.details["submitted_for_analysis"] is False
    assert calls == {"get": 1, "post": 0}


def test_cti_service_converts_provider_exception_to_explicit_error(monkeypatch):
    class FailingAdapter:
        async def lookup(self, url):
            raise RuntimeError("provider unavailable")

    class LiveAdapter:
        async def lookup(self, url):
            return CTIResponse(
                source="whois",
                status=CTIStatus.LIVE,
                hit=False,
                score=0.0,
            )

    monkeypatch.setattr(
        "app.services.cti_service._build_provider_plan",
        lambda: {
            "virustotal": None,
            "urlhaus": FailingAdapter(),
            "whois": LiveAdapter(),
        },
    )

    from app.services.cti_service import enrich

    responses = asyncio.run(enrich("https://example.invalid/"))
    by_source = {response.source: response for response in responses}

    assert by_source["virustotal"].status == CTIStatus.NOT_CONFIGURED
    assert by_source["virustotal"].hit is None
    assert by_source["urlhaus"].status == CTIStatus.ERROR
    assert by_source["urlhaus"].hit is None
    assert by_source["urlhaus"].score is None
    assert by_source["urlhaus"].error == "provider unavailable"
    assert by_source["whois"].status == CTIStatus.LIVE


def test_missing_cti_evidence_is_not_reported_as_enriched():
    from app.services.scan_orchestrator import _build_cti_result

    result = _build_cti_result([])

    assert result.virustotal is None
    assert result.urlhaus is None
    assert result.whois is None
    assert result.enriched is False
