import csv
import io
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_session
from app.services.db_service import DBService

router = APIRouter()


@router.get("/export/{fmt}")
async def export_report(
    fmt: str,
    session: AsyncSession = Depends(get_session),
):
    if fmt not in ("csv", "json"):
        raise HTTPException(status_code=400, detail="Format must be 'csv' or 'json'")

    svc = DBService(session)
    records = await svc.get_history(limit=5000, offset=0)

    if fmt == "json":
        payload = json.dumps([r.model_dump(mode="json") for r in records], indent=2)
        return StreamingResponse(
            io.StringIO(payload),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=phishguard-report.json"},
        )

    # CSV
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "url", "score", "level", "ml_probability", "scanned_at", "source"])
    for r in records:
        writer.writerow([r.id, r.url, r.score, r.level, r.ml_probability, r.scanned_at, r.source])
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard-report.csv"},
    )
