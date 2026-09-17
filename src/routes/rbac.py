from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from xcore.kernel.api import AuthPayload
from xcore.sdk import require_permission

from ..models.rbac import Role
from ..schemas.rbac import (
    AssignPermissionRequest,
    AssignRoleRequest,
    PermissionCreate,
    PermissionResponse,
    RoleCreate,
    RoleResponse,
)
from ..scope import PlatformScope, ensure_platform_admin, ensure_tenant_access, is_platform_admin, token_tenant
from ..services.rbac import RBACService
from ..services.seed import TENANT_ASSIGNABLE_PERMISSIONS


def rbac_router(db: Any, scope: PlatformScope, cache: Any = None) -> APIRouter:
    """Rôles et permissions.

    - Rôles GLOBAUX (tenant_id nul : admin, owner, user…) et catalogue de
      permissions : administration de l'instance. Un rôle global est partagé
      par tous les espaces ; le modifier depuis un espace toucherait les autres.
    - Rôles d'un espace : son responsable, avec des permissions limitées à
      TENANT_ASSIGNABLE_PERMISSIONS.
    - Attribution d'un rôle à un membre : dans l'espace du jeton, jamais le
      rôle admin global.
    """
    router = APIRouter(prefix="/rbac", tags=["rbac"])

    def _svc(session) -> RBACService:
        return RBACService(session, cache=cache)

    async def _manageable_role(session, role_id: str, user: AuthPayload) -> Role:
        role = await _svc(session).get_role(role_id)
        if role is None:
            raise HTTPException(status_code=404, detail="Role not found")
        if role.tenant_id is None:
            ensure_platform_admin(user, scope)
        else:
            ensure_tenant_access(user, role.tenant_id, scope)
        return role

    @router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
    async def create_role(
        body: RoleCreate,
        user: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        if body.tenant_id is None:
            ensure_platform_admin(user, scope)
        else:
            ensure_tenant_access(user, body.tenant_id, scope)
        async with db.session() as session:
            role = await _svc(session).create_role(name=body.name, tenant_id=body.tenant_id, description=body.description)
            await session.commit()
            # Relation chargée explicitement : un chargement paresseux hors contexte
            # asynchrone échouait à la sérialisation de la réponse.
            await session.refresh(role, attribute_names=["permissions"])
            return role

    @router.get("/roles", response_model=List[RoleResponse])
    async def list_roles(
        tenant_id: str | None = None,
        user: AuthPayload = Depends(require_permission("rbac:read")),
    ) -> Any:
        if tenant_id is not None:
            ensure_tenant_access(user, tenant_id, scope)
        async with db.session() as session:
            return await _svc(session).list_roles(tenant_id=tenant_id)

    @router.get("/roles/{role_id}", response_model=RoleResponse)
    async def get_role(
        role_id: str,
        user: AuthPayload = Depends(require_permission("rbac:read")),
    ) -> Any:
        async with db.session() as session:
            role = await _svc(session).get_role(role_id)
            if role is None:
                raise HTTPException(status_code=404, detail="Role not found")
            if role.tenant_id is not None:
                ensure_tenant_access(user, role.tenant_id, scope)
            return role

    @router.post("/roles/{role_id}/permissions", response_model=RoleResponse)
    async def assign_permission(
        role_id: str,
        body: AssignPermissionRequest,
        user: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        async with db.session() as session:
            await _manageable_role(session, role_id, user)
            perm = await _svc(session).get_permission(body.permission_id)
            if perm is None:
                raise HTTPException(status_code=404, detail="Permission not found")
            if not is_platform_admin(user, scope) and perm.name not in TENANT_ASSIGNABLE_PERMISSIONS:
                raise HTTPException(status_code=403, detail="Permission réservée à l'administration de l'instance")
            try:
                role = await _svc(session).assign_permission_to_role(role_id, body.permission_id)
            except ValueError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
            await session.commit()
            # Relation chargée explicitement : un chargement paresseux hors contexte
            # asynchrone échouait à la sérialisation de la réponse.
            await session.refresh(role, attribute_names=["permissions"])
            return role

    @router.delete("/roles/{role_id}/permissions/{permission_id}", response_model=RoleResponse)
    async def remove_permission(
        role_id: str,
        permission_id: str,
        user: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        async with db.session() as session:
            await _manageable_role(session, role_id, user)
            try:
                role = await _svc(session).remove_permission_from_role(role_id, permission_id)
            except ValueError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
            await session.commit()
            # Relation chargée explicitement : un chargement paresseux hors contexte
            # asynchrone échouait à la sérialisation de la réponse.
            await session.refresh(role, attribute_names=["permissions"])
            return role

    @router.post("/tenants/{tenant_id}/members/{user_id}/role", response_model=dict)
    async def assign_role_to_member(
        tenant_id: str,
        user_id: str,
        body: AssignRoleRequest,
        user: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        ensure_tenant_access(user, tenant_id, scope)
        async with db.session() as session:
            role = await _svc(session).get_role(body.role_id)
            if role is None or (role.tenant_id is not None and role.tenant_id != tenant_id):
                raise HTTPException(status_code=404, detail="Role not found")
            if role.id == scope.admin_role_id and not is_platform_admin(user, scope):
                raise HTTPException(status_code=403, detail="Rôle réservé à l'administration de l'instance")
            if user.get("sub") == user_id and token_tenant(user) == tenant_id and not is_platform_admin(user, scope):
                # Un responsable ne modifie pas son propre rôle (ni élévation, ni perte d'accès involontaire).
                raise HTTPException(status_code=400, detail="Impossible de modifier son propre rôle")
            try:
                await _svc(session).assign_role_to_member(user_id, tenant_id, body.role_id)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            await session.commit()
            return {"success": True, "role_id": body.role_id}

    @router.post("/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
    async def create_permission(
        body: PermissionCreate,
        user: AuthPayload = Depends(require_permission("rbac:write")),
    ) -> Any:
        ensure_platform_admin(user, scope)
        async with db.session() as session:
            perm = await _svc(session).create_permission(name=body.name, description=body.description)
            await session.commit()
            await session.refresh(perm)
            return perm

    @router.get("/permissions", response_model=List[PermissionResponse])
    async def list_permissions(
        _: AuthPayload = Depends(require_permission("rbac:read")),
    ) -> Any:
        async with db.session() as session:
            return await _svc(session).list_permissions()

    @router.get("/users/{user_id}/tenants/{tenant_id}/permissions", response_model=List[str])
    async def get_user_permissions(
        user_id: str,
        tenant_id: str,
        user: AuthPayload = Depends(require_permission("rbac:read")),
    ) -> Any:
        ensure_tenant_access(user, tenant_id, scope)
        async with db.session() as session:
            return await _svc(session).get_permissions_for_user(user_id, tenant_id)

    return router
