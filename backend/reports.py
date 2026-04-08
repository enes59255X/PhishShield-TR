from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from db import get_all_analyses
import csv
import io
from datetime import datetime
import json

router = APIRouter()

@router.get("/csv")
def export_csv(limit: int = Query(100, ge=1, le=1000)):
    """Tüm analizleri CSV olarak export et."""
    analyses = get_all_analyses(limit)
    
    if not analyses:
        raise HTTPException(status_code=404, detail="Analiz verisi bulunamadı.")
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow(["ID", "URL", "Score", "Risk Level", "Threat Type", "Findings", "Recommendations", "Created At"])
    
    for a in analyses:
        writer.writerow([
            a.get("id", ""),
            a.get("url", ""),
            a.get("score", ""),
            a.get("risk_level", ""),
            a.get("threat_type", ""),
            a.get("findings", "").replace("\n", "; "),
            a.get("recommendations", "").replace("\n", "; "),
            a.get("created_at", ""),
        ])
    
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishshield_analyses.csv"}
    )

@router.get("/json")
def export_json(limit: int = Query(100, ge=1, le=1000)):
    """Tüm analizleri JSON olarak export et."""
    analyses = get_all_analyses(limit)
    return {
        "exported_at": datetime.now().isoformat(),
        "count": len(analyses),
        "analyses": analyses
    }