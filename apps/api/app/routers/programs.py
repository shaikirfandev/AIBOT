"""Programs & Scope API."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from bbp_schemas.core import Organization, OrganizationCreate, Program, ProgramCreate, ScopeRule

from app.services.database import get_store

router = APIRouter(tags=["programs"])


@router.post("/organizations", response_model=Organization)
async def create_organization(body: OrganizationCreate):
    org = Organization(**body.model_dump())
    get_store("organizations")[org.id] = org
    return org


@router.get("/organizations")
async def list_organizations():
    return list(get_store("organizations").values())


@router.post("/programs", response_model=Program)
async def create_program(body: ProgramCreate):
    org_store = get_store("organizations")
    if body.organization_id not in org_store:
        raise HTTPException(404, "Organization not found")
    program = Program(**body.model_dump())
    get_store("programs")[program.id] = program
    return program


@router.get("/programs")
async def list_programs():
    return list(get_store("programs").values())


@router.get("/programs/{program_id}", response_model=Program)
async def get_program(program_id: str):
    programs = get_store("programs")
    if program_id not in programs:
        raise HTTPException(404, "Program not found")
    return programs[program_id]


@router.put("/programs/{program_id}/scope")
async def update_scope(program_id: str, scope: ScopeRule):
    programs = get_store("programs")
    if program_id not in programs:
        raise HTTPException(404, "Program not found")
    program = programs[program_id]
    program.scope = scope
    return {"status": "updated", "program_id": program_id}
