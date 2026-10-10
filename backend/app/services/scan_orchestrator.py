"""Coordinates feature extraction, calibrated scoring, CTI enrichment, and persistence."""
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from app.models.scan import ScanRequest, ScanResult, CTIResult
from app.models.scan import MLEvidence, ProviderEvidence, ProviderStatus, ScanEvidence
from app.models.threat import RiskLevel, ThreatIndicator
from app.services.decision_engine import DecisionEngine
from app.services.feature_service import extract
from app.services.ml_service import MLService
from app.services.cti_service import enrich
from app.services.db_service import DBService
from app.services.url_normalizer import normalize_url
from cti.base import CTIStatus  # noqa: E402


async def orchestrate_scan(request: ScanRequest, session: AsyncSession) -> ScanResult:
    url = normalize_url(request.url)

    # 1. Feature extraction
    features, vector = extract(url)

    # 2. ML inference
    ml_prob = MLService.predict(vector)

    # 3. Parallel CTI enrichment
    cti_responses = await enrich(url)

    # 4. Deterministic decision layer
    decision = DecisionEngine.decide(
        ml_prob,
        cti_responses,
        thresholds=MLService.decision_thresholds(),
    )

    # 5. Build explanatory indicators only
    indicators = _build_indicators(ml_prob, cti_responses)

    # 6. Build CTI result dict
    cti_result = _build_cti_result(cti_responses)
    evidence = ScanEvidence(
        ml=MLEvidence(
            score=ml_prob,
            model_version=MLService.version(),
            thresholds=MLService.decision_thresholds(),
        ),
        cti=cti_result,
    )

    result = ScanResult(
        id=str(uuid.uuid4()),
        url=url,
        score=decision.risk_score,
        risk_score=decision.risk_score,
        level=decision.verdict,
        verdict=decision.verdict,
        scan_mode=decision.scan_mode,
        ml_probability=ml_prob,
        features=features,
        cti=cti_result,
        evidence=evidence,
        indicators=indicators,
        explanation=decision.explanation,
        scanned_at=datetime.now(timezone.utc),
        source=request.source,
    )

    db = DBService(session)
    return await db.save_scan(result)


def _build_indicators(ml_prob, cti_responses) -> list[ThreatIndicator]:
    indicators = []
    thresholds = MLService.decision_thresholds()

    if ml_prob >= thresholds["malicious"]:
        indicators.append(ThreatIndicator(
            type="ml_high_confidence",
            severity="high",
            description=f"ML classifier: {ml_prob:.1%} phishing probability",
            source="ml",
        ))
    elif ml_prob >= thresholds["suspicious"]:
        indicators.append(ThreatIndicator(
            type="ml_flag",
            severity="medium",
            description=f"ML classifier flagged URL ({ml_prob:.1%} probability)",
            source="ml",
        ))

    for cti in cti_responses:
        if cti.status == CTIStatus.LIVE and cti.hit:
            sev = "critical" if cti.source == "urlhaus" else "high"
            indicators.append(ThreatIndicator(
                type=f"{cti.source}_hit",
                severity=sev,
                description=f"URL flagged by {cti.source} (score: {cti.score:.0%})",
                source=cti.source,
            ))
        elif cti.status in {CTIStatus.ERROR, CTIStatus.TIMEOUT, CTIStatus.UNKNOWN}:
            indicators.append(ThreatIndicator(
                type=f"{cti.source}_status",
                severity="low",
                description=f"{cti.source} status: {cti.status.value}",
                source=cti.source,
            ))

    return indicators


def _build_cti_result(cti_responses) -> CTIResult:
    provider_map = {
        response.source: ProviderEvidence(
            provider=response.source,
            status=ProviderStatus(response.status.value),
            hit=response.hit,
            score=response.score,
            details=response.details,
            error=response.error,
            latency_ms=response.latency_ms,
        )
        for response in cti_responses
    }

    return CTIResult(
        virustotal=provider_map.get("virustotal"),
        urlhaus=provider_map.get("urlhaus"),
        whois=provider_map.get("whois"),
        enriched=any(
            evidence is not None and evidence.status in {ProviderStatus.LIVE, ProviderStatus.MOCK}
            for evidence in provider_map.values()
        ),
    )
