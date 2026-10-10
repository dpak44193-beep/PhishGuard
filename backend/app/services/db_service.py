import json
import uuid
from datetime import datetime, timezone
from typing import List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import ScanRecord
from app.models.scan import CTIResult, MLEvidence, ProviderEvidence, ProviderStatus, ScanEvidence, ScanMode, ScanResult
from app.models.threat import RiskLevel


class DBService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def save_scan(self, result: ScanResult) -> ScanResult:
        record = ScanRecord(
            id=result.id or str(uuid.uuid4()),
            url=result.url,
            score=result.score,
            level=result.level.value if isinstance(result.level, RiskLevel) else result.level,
            ml_probability=result.ml_probability,
            indicators_json=json.dumps([i.model_dump() for i in result.indicators]),
            explanation_json=json.dumps(result.explanation),
            cti_json=json.dumps(result.cti.model_dump() if result.cti else {}),
            features_json=json.dumps(result.features.model_dump() if result.features else {}),
            source=result.source,
            scanned_at=result.scanned_at or datetime.now(timezone.utc),
        )
        self.session.add(record)
        await self.session.commit()
        await self.session.refresh(record)
        result.id = record.id
        return result

    async def get_history(self, limit: int = 50, offset: int = 0) -> List[ScanResult]:
        stmt = (
            select(ScanRecord)
            .order_by(ScanRecord.scanned_at.desc())
            .limit(limit)
            .offset(offset)
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        return [_record_to_result(r) for r in rows]


def _record_to_result(r: ScanRecord) -> ScanResult:
    from app.models.scan import URLFeatures
    from app.models.threat import ThreatIndicator

    indicators = [ThreatIndicator(**i) for i in json.loads(r.indicators_json or "[]")]
    features_data = json.loads(r.features_json or "{}")
    features = URLFeatures(**features_data) if features_data else None
    cti_data = json.loads(r.cti_json or "{}")
    cti = _coerce_cti_result(cti_data) if cti_data else None
    level = _normalize_level(r.level)
    evidence = ScanEvidence(
        ml=MLEvidence(score=r.ml_probability),
        cti=cti,
    ) if cti else None

    return ScanResult(
        id=r.id,
        url=r.url,
        score=r.score,
        risk_score=r.score,
        level=level,
        verdict=level,
        scan_mode=_infer_scan_mode(cti),
        ml_probability=r.ml_probability,
        features=features,
        cti=cti,
        evidence=evidence,
        indicators=indicators,
        explanation=json.loads(r.explanation_json or "[]"),
        scanned_at=r.scanned_at,
        source=r.source,
    )


def _coerce_cti_result(cti_data: dict) -> CTIResult:
    return CTIResult(
        virustotal=_coerce_provider_evidence("virustotal", cti_data.get("virustotal")),
        urlhaus=_coerce_provider_evidence("urlhaus", cti_data.get("urlhaus")),
        whois=_coerce_provider_evidence("whois", cti_data.get("whois")),
        enriched=bool(cti_data.get("enriched")),
    )


def _coerce_provider_evidence(provider: str, raw) -> ProviderEvidence | None:
    if raw is None:
        return None
    if isinstance(raw, dict) and "provider" in raw and "status" in raw:
        return ProviderEvidence(**raw)
    details = raw if isinstance(raw, dict) else {"value": raw}
    return ProviderEvidence(
        provider=provider,
        status=ProviderStatus.UNKNOWN,
        hit=None,
        score=None,
        details=details,
    )


def _normalize_level(raw_level: str) -> RiskLevel:
    if raw_level == RiskLevel.SAFE.value:
        return RiskLevel.NO_THREAT_DETECTED
    return RiskLevel(raw_level)


def _infer_scan_mode(cti: CTIResult | None) -> ScanMode:
    if cti is None:
        return ScanMode.ML_ONLY

    statuses = [
        provider.status
        for provider in (cti.virustotal, cti.urlhaus, cti.whois)
        if provider is not None
    ]
    if not statuses:
        return ScanMode.ML_ONLY
    if all(status == ProviderStatus.LIVE for status in statuses):
        return ScanMode.FULL
    if all(status in {ProviderStatus.UNKNOWN, ProviderStatus.ERROR, ProviderStatus.TIMEOUT} for status in statuses):
        return ScanMode.ML_ONLY
    return ScanMode.DEGRADED
