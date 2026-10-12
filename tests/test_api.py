"""FastAPI integration tests — runs against in-process ASGI app with a temp SQLite DB."""
import os
import sys
import pytest
import pytest_asyncio
from pathlib import Path
from httpx import AsyncClient, ASGITransport

# Point at a throw-away database so tests never touch the dev DB
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_phishguard.db")
os.environ.setdefault("CTI_MOCK", "true")
os.environ.setdefault("ML_MODEL_PATH", str(
    Path(__file__).resolve().parents[1] / "ml/models/artifacts/phishguard_model.joblib"
))

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.main import app  # noqa: E402
from app.config import settings  # noqa: E402
from app.services.ml_service import MLService  # noqa: E402
from ml.features.extractor import FEATURE_ORDER  # noqa: E402


@pytest_asyncio.fixture
async def client(monkeypatch):
    from app.db.database import init_db
    monkeypatch.setattr(settings, "cti_mock", True)

    def predict_for_api_contract(vector):
        return 0.99 if vector[FEATURE_ORDER.index("suspicious_keywords")] else 0.1

    monkeypatch.setattr(MLService, "predict", predict_for_api_contract)
    monkeypatch.setattr(MLService, "version", lambda: "test-model-v1")
    monkeypatch.setattr(
        MLService,
        "metadata",
        lambda: {
            "artifact_version": "test-model-v1",
            "training_date_utc": "2026-10-10T00:00:00+00:00",
            "dataset_sources": {"source_url": "https://example.org/data"},
            "feature_schema": {
                "version": "test-feature-schema-v1",
                "names": list(FEATURE_ORDER),
                "pipeline_steps": ["scaler", "model"],
            },
            "test_metrics": {"accuracy": 1.0},
        },
    )
    monkeypatch.setattr(
        MLService,
        "decision_thresholds",
        lambda: {"suspicious": 0.6, "malicious": 0.9},
    )
    await init_db()  # create tables; lifespan doesn't fire with ASGITransport
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


# ── Health ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "timestamp" in data


# ── Scan ───────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_legit_url(client):
    resp = await client.post("/api/scan", json={"url": "https://google.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["url"] == "https://google.com"
    assert data["level"] in ("no_threat_detected", "suspicious", "malicious")
    assert data["verdict"] == data["level"]
    assert data["scan_mode"] in ("full", "degraded", "ml_only", "failed")
    assert 0.0 <= data["score"] <= 1.0
    assert data["risk_score"] == data["score"]
    assert 0.0 <= data["ml_probability"] <= 1.0
    assert isinstance(data["indicators"], list)
    assert isinstance(data["explanation"], list)
    assert data["evidence"]["ml"]["score"] == data["ml_probability"]
    ml_evidence = data["evidence"]["ml"]
    assert ml_evidence["model_version"] == "test-model-v1"
    assert ml_evidence["model_metadata"]["artifact_version"] == "test-model-v1"
    assert ml_evidence["model_metadata"]["training_date_utc"]
    assert ml_evidence["model_metadata"]["dataset_sources"]["source_url"]
    assert ml_evidence["model_metadata"]["feature_schema"]["names"] == FEATURE_ORDER
    assert ml_evidence["model_metadata"]["test_metrics"]["accuracy"] == 1.0
    assert data["cti"]["virustotal"]["status"] == "mock"
    assert data["cti"]["urlhaus"]["status"] == "mock"
    assert data["cti"]["whois"]["status"] == "mock"
    assert data["cti"]["virustotal"]["hit"] is None
    assert data["cti"]["virustotal"]["score"] is None
    assert data["cti"]["enriched"] is False


@pytest.mark.asyncio
async def test_scan_stores_id(client):
    resp = await client.post("/api/scan", json={"url": "https://example.com"})
    assert resp.status_code == 200
    assert resp.json()["id"] is not None


@pytest.mark.asyncio
async def test_scan_source_recorded(client):
    resp = await client.post(
        "/api/scan",
        json={"url": "https://example.com", "source": "extension"},
    )
    assert resp.json()["source"] == "extension"


@pytest.mark.asyncio
async def test_scan_features_returned(client):
    resp = await client.post("/api/scan", json={"url": "https://example.com/path?q=1"})
    feats = resp.json()["features"]
    assert feats is not None
    assert feats["uses_https"] is True
    assert feats["url_length"] > 0


@pytest.mark.asyncio
async def test_scan_normalizes_url(client):
    resp = await client.post("/api/scan", json={"url": " HTTPS://Example.COM:443/login "})
    assert resp.status_code == 200
    assert resp.json()["url"] == "https://example.com/login"


@pytest.mark.asyncio
async def test_scan_rejects_non_http_url(client):
    resp = await client.post("/api/scan", json={"url": "ftp://example.com"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_scan_suspicious_url_has_indicators(client):
    resp = await client.post(
        "/api/scan",
        json={"url": "http://paypal-verify-login.xyz/secure?account=true"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["indicators"]) > 0
    assert "scan_mode" in data


# ── History ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_history_returns_list(client):
    # Seed one scan first
    await client.post("/api/scan", json={"url": "https://history-test.com"})
    resp = await client.get("/api/history")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_history_limit_respected(client):
    for i in range(5):
        await client.post("/api/scan", json={"url": f"https://limit-test-{i}.com"})
    resp = await client.get("/api/history?limit=3")
    assert resp.status_code == 200
    assert len(resp.json()) <= 3


@pytest.mark.asyncio
async def test_history_contains_scanned_url(client):
    target = "https://history-check-unique.com"
    created = await client.post(
        "/api/scan",
        json={"url": target, "source": "extension"},
    )
    assert created.status_code == 200
    resp = await client.get("/api/history?limit=50")
    stored = next(record for record in resp.json() if record["url"] == target)
    assert stored["id"] == created.json()["id"]
    assert stored["source"] == "extension"


@pytest.mark.asyncio
async def test_scan_api_failure_for_invalid_scheme(client):
    response = await client.post(
        "/api/scan",
        json={"url": "ftp://example.com/resource"},
    )

    assert response.status_code == 422


# ── Export ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_csv(client):
    await client.post("/api/scan", json={"url": "https://export-test.com"})
    resp = await client.get("/api/export/csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    text = resp.text
    assert "id,url,score" in text


@pytest.mark.asyncio
async def test_export_json(client):
    await client.post("/api/scan", json={"url": "https://export-json-test.com"})
    resp = await client.get("/api/export/json")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "url" in data[0]


@pytest.mark.asyncio
async def test_export_invalid_format(client):
    resp = await client.get("/api/export/xml")
    assert resp.status_code == 400
