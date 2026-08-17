"""Reports API."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from bbp_schemas.core import Report

from app.services.database import get_store

router = APIRouter(tags=["reports"])


@router.post("/reports")
async def create_report(scan_id: str):
    scans = get_store("scans")
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    findings = [f for f in get_store("findings").values() if f.scan_id == scan_id]
    report = Report(
        scan_id=scan_id,
        content=f"# Security Report\n\nScan: {scan_id}\nFindings: {len(findings)}",
    )
    get_store("reports")[report.id] = report
    return report


@router.get("/reports")
async def list_reports():
    return list(get_store("reports").values())


@router.get("/reports/{report_id}")
async def get_report(report_id: str):
    reports = get_store("reports")
    if report_id not in reports:
        raise HTTPException(404, "Report not found")
    return reports[report_id]
