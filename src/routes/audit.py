from typing import Any, List

from fastapi import APIRouter, Depends, Query
from xcore.kernel.api import AuthPayload
from xcore.sdk import require_permission

from ..scope import PlatformScope, ensure_platform_admin, ensure_tenant_access
from ..services.audit import AuditService
from ..schemas.audit import AuditLogResponse


def audit_router(db: Any, scope: PlatformScope) -> APIRouter:
    router = APIRouter(prefix="/audit", tags=["audit"])

    @router.get("/tenants/{tenant_id}", response_model=List[AuditLogResponse])
    async def list_tenant_audit(
        tenant_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        user: AuthPayload = Depends(require_permission("audit:read")),
    ) -> Any:
        ensure_tenant_access(user, tenant_id, scope)
        async with db.session() as session:
            svc = AuditService(session)
            return await svc.list_for_tenant(tenant_id, limit=limit, offset=offset)

    @router.get("/users/{user_id}", response_model=List[AuditLogResponse])
    async def list_user_audit(
        user_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        user: AuthPayload = Depends(require_permission("audit:read")),
    ) -> Any:
        # Le journal d'un utilisateur couvre tous ses espaces : lui-même ou l'instance.
        if user.get("sub") != user_id:
            ensure_platform_admin(user, scope)
        async with db.session() as session:
            svc = AuditService(session)
            return await svc.list_for_user(user_id, limit=limit, offset=offset)

    return router
