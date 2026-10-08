from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..models.rbac import Role, Permission
from .base import BaseRepository


class RoleRepository(BaseRepository[Role]):
    model = Role

    async def get_with_permissions(self, role_id: str) -> Optional[Role]:
        result = await self.session.execute(
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.id == role_id)
        )
        return result.scalar_one_or_none()

    async def list_for_tenant(self, tenant_id: Optional[str]) -> list[Role]:
        # `permissions` chargée ICI : la route sérialise la réponse (RoleResponse) après la fermeture de la session,
        # un chargement paresseux à ce moment-là lève DetachedInstanceError (500) — sur toute base.
        query = select(Role).options(selectinload(Role.permissions))
        if tenant_id is None:
            result = await self.session.execute(query.where(Role.tenant_id.is_(None)))
        else:
            result = await self.session.execute(
                query.where((Role.tenant_id == tenant_id) | Role.tenant_id.is_(None))
            )
        return list(result.scalars().all())


class PermissionRepository(BaseRepository[Permission]):
    model = Permission

    async def get_by_name(self, name: str) -> Optional[Permission]:
        result = await self.session.execute(
            select(Permission).where(Permission.name == name)
        )
        return result.scalar_one_or_none()
