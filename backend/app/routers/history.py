from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from app.db.database import get_session
from app.models.scan import ScanResult
from app.services.db_service import DBService

router = APIRouter()


@router.get("/history", response_model=List[ScanResult])
async def get_history(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> List[ScanResult]:
    svc = DBService(session)
    return await svc.get_history(limit=limit, offset=offset)
