from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from xcore.kernel.api import AuthPayload, get_current_user
from xcore.sdk import require_permission

from ..repositories.rbac import RoleRepository
from ..repositories.tenant import TenantRepository
from ..repositories.user import UserRepository
from ..schemas.invite import AcceptInviteRequest, InviteCreate, InvitePreview, InviteResponse
from ..scope import PlatformScope, ensure_tenant_access, is_platform_admin
from ..services.email import AuthEmailService
from ..services.events import XAuthEvents
from ..services.invite import InviteService


def invites_router(
    db: Any,
    email_service: AuthEmailService,
    events: XAuthEvents | None = None,
    scope: PlatformScope | None = None,
) -> APIRouter:
    """Invitations dans un espace : créées et listées par le responsable de
    l'espace du jeton, acceptées par le seul destinataire (adresse email)."""
    scope = scope or PlatformScope()
    router = APIRouter(prefix="/invites", tags=["invites"])

    @router.post("/", response_model=InviteResponse, status_code=status.HTTP_201_CREATED)
    async def create_invite(
        body: InviteCreate,
        user: AuthPayload = Depends(require_permission("invites:write")),
    ) -> Any:
        ensure_tenant_access(user, body.tenant_id, scope)
        async with db.session() as session:
            tenant = await TenantRepository(session).get(body.tenant_id)
            if tenant is None:
                raise HTTPException(status_code=404, detail="Tenant not found")
            if body.role_id is not None:
                role = await RoleRepository(session).get(body.role_id)
                if role is None or (role.tenant_id is not None and role.tenant_id != body.tenant_id):
                    raise HTTPException(status_code=404, detail="Role not found")
                if role.id == scope.admin_role_id and not is_platform_admin(user, scope):
                    raise HTTPException(status_code=403, detail="Rôle réservé à l'administration de l'instance")
            inviter = await UserRepository(session).get(user["sub"])

            svc = InviteService(session, events)
            try:
                invite = await svc.create_invite(
                    tenant_id=body.tenant_id,
                    invited_by=user["sub"],
                    email=body.email,
                    role_id=body.role_id,
                    expires_hours=body.expires_hours,
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            await session.commit()
            await session.refresh(invite)

        await email_service.invite.send_invitation(
            to=invite.email,
            invite_token=invite.token,
            tenant_name=tenant.name,
            invited_by=inviter.email if inviter else "",
            expires_hours=body.expires_hours,
        )
        return invite

    @router.get("/{tenant_id}", response_model=List[InviteResponse])
    async def list_invites(
        tenant_id: str,
        user: AuthPayload = Depends(require_permission("invites:read")),
    ) -> Any:
        ensure_tenant_access(user, tenant_id, scope)
        async with db.session() as session:
            return await InviteService(session).list_invites(tenant_id)

    @router.get("/token/{token}", response_model=InvitePreview)
    async def get_invite(token: str) -> Any:
        """Public — l'invité voit l'espace et l'adresse concernée avant d'accepter."""
        async with db.session() as session:
            invite = await InviteService(session).get_invite_by_token(token)
            if invite is None:
                raise HTTPException(status_code=404, detail="Invite not found")
            tenant = await TenantRepository(session).get(invite.tenant_id)
            expires = invite.expires_at if invite.expires_at.tzinfo else invite.expires_at.replace(tzinfo=timezone.utc)
            return InvitePreview(
                tenant_name=tenant.name if tenant else "",
                email=invite.email,
                expires_at=expires,
                valid=invite.is_active and invite.used_at is None and expires > datetime.now(tz=timezone.utc),
            )

    @router.post("/accept", response_model=dict)
    async def accept_invite(
        body: AcceptInviteRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """L'utilisateur est celui du jeton ; l'invitation doit lui être adressée."""
        async with db.session() as session:
            svc = InviteService(session, events)
            try:
                membership = await svc.accept_invite(token=body.token, user_id=user["sub"])
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            await session.commit()
            return {
                "success": True,
                "tenant_id": membership.tenant_id,
                "user_id": membership.user_id,
                "role_id": membership.role_id,
            }

    return router
