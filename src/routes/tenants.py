import json
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from xcore.kernel.api import AuthPayload, get_current_user
from xcore.sdk import require_permission

from ..models.tenant import Tenant
from ..repositories.tenant import TenantRepository
from ..repositories.user import TenantMemberRepository
from ..schemas.tenant import (
    MemberResponse,
    TenantCreate,
    TenantResponse,
    TenantUpdate,
)


def tenants_router(db: Any) -> APIRouter:
    router = APIRouter(prefix="/tenants", tags=["tenants"])

    @router.post(
        "/",
        response_model=TenantResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def create_tenant(
        body: TenantCreate,
        _: AuthPayload = Depends(require_permission("tenants:write")),
    ) -> Any:
        async with db.session() as session:
            repo = TenantRepository(session)
            existing = await repo.get_by_slug(body.slug)
            if existing:
                raise HTTPException(status_code=409, detail="Slug already taken")
            tenant = Tenant(
                name=body.name,
                slug=body.slug,
                settings=json.dumps(body.settings) if body.settings else None,
            )
            result = await repo.save(tenant)
            await session.commit()
            return result

    @router.get("/", response_model=List[TenantResponse])
    async def list_tenants(
        _: AuthPayload = Depends(require_permission("tenants:read")),
    ) -> Any:
        async with db.session() as session:
            repo = TenantRepository(session)
            return await repo.all()

    @router.get("/{tenant_id}", response_model=TenantResponse)
    async def get_tenant(
        tenant_id: str,
        _: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            repo = TenantRepository(session)
            tenant = await repo.get(tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found")
            return tenant

    @router.patch("/{tenant_id}", response_model=TenantResponse)
    async def update_tenant(
        tenant_id: str,
        body: TenantUpdate,
        _: AuthPayload = Depends(require_permission("tenants:write")),
    ) -> Any:
        async with db.session() as session:
            repo = TenantRepository(session)
            tenant = await repo.get(tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found")
            if body.name is not None:
                tenant.name = body.name
            if body.settings is not None:
                tenant.settings = json.dumps(body.settings)
            await session.flush()
            await session.commit()
            await session.refresh(tenant)
            return tenant

    @router.delete("/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_tenant(
        tenant_id: str,
        _: AuthPayload = Depends(require_permission("tenants:delete")),
    ) -> None:
        async with db.session() as session:
            repo = TenantRepository(session)
            tenant = await repo.get(tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found")
            await repo.delete(tenant)
            await session.commit()

    @router.get("/{tenant_id}/members", response_model=List[MemberResponse])
    async def list_members(
        tenant_id: str,
        _: AuthPayload = Depends(require_permission("tenants:read")),
    ) -> Any:
        async with db.session() as session:
            repo = TenantMemberRepository(session)
            return await repo.get_members_of_tenant(tenant_id)

    return router
