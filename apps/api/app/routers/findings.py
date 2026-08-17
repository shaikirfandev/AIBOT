"""Findings API."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from bbp_schemas.core import Finding, FindingStatus
from bbp_scope import create_finding_fingerprint

from app.services.database import get_store

router = APIRouter(tags=["findings"])


@router.get("/findings")
async def list_findings():
    return list(get_store("findings").values())


@router.get("/findings/{finding_id}", response_model=Finding)
async def get_finding(finding_id: str):
    findings = get_store("findings")
    if finding_id not in findings:
        raise HTTPException(404, "Finding not found")
    return findings[finding_id]


@router.post("/findings/{finding_id}/validate")
async def validate_finding(finding_id: str):
    findings = get_store("findings")
    if finding_id not in findings:
        raise HTTPException(404, "Finding not found")
    finding = findings[finding_id]
    finding.status = FindingStatus.VALIDATING
    # In production: trigger evidence validation agent
    return {"status": "validating", "finding_id": finding_id}


@router.post("/findings/{finding_id}/regression")
async def create_regression_from_finding(finding_id: str):
    findings = get_store("findings")
    if finding_id not in findings:
        raise HTTPException(404, "Finding not found")
    from bbp_schemas.core import RegressionTest
    finding = findings[finding_id]
    rt = RegressionTest(
        finding_id=finding_id,
        expected_behavior=f"Verify fix for: {finding.title}",
        baseline_evidence=finding.evidence,
    )
    get_store("regression_tests")[rt.id] = rt
    return rt
