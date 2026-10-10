from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_session
from app.models.scan import ScanRequest, ScanResult
from app.services.scan_orchestrator import orchestrate_scan

router = APIRouter()


@router.post("/scan", response_model=ScanResult)
async def scan_url(
    request: ScanRequest,
    session: AsyncSession = Depends(get_session),
) -> ScanResult:
    url = request.url.strip()
    if not url.startswith(("http://", "https://", "HTTP://", "HTTPS://")):
        raise HTTPException(status_code=422, detail="URL must start with http:// or https://")
    return await orchestrate_scan(request.model_copy(update={"url": url}), session)
