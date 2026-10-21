"""Portée des opérations d'administration xauth.

Deux niveaux distincts :
- administrateur DE L'INSTANCE : admin:* dans l'espace initial (seed, slug
  ADMIN_TENANT_SLUG). Seul habilité aux opérations transverses (tous les
  utilisateurs, tous les espaces, rôles et permissions globaux).
- responsable D'UN ESPACE : rôle « owner » attribué au créateur de l'espace.
  Ses permissions (tenants:*, rbac:*, audit:read, invites:*) ne valent que
  pour l'espace de son jeton.

Une permission ne suffit donc jamais seule : l'espace visé par la requête doit
être celui du jeton, sauf pour l'administrateur de l'instance.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import HTTPException
from xcore.kernel.api import AuthPayload

ADMIN_PERMISSION = "admin:*"


@dataclass
class PlatformScope:
    """Renseigné par le seed au démarrage (espace initial, rôle admin global)."""

    tenant_id: str | None = None
    admin_role_id: str | None = None


def token_tenant(user: AuthPayload) -> str | None:
    tenant_id = user.get("tenant_id") or (user.get("user") or {}).get("tenant_id")
    return tenant_id if tenant_id else None


def granted(user: AuthPayload) -> set[str]:
    return set(user.get("permissions") or []) | set(user.get("roles") or [])


def is_platform_admin(user: AuthPayload, scope: PlatformScope) -> bool:
    return bool(scope.tenant_id) and token_tenant(user) == scope.tenant_id and ADMIN_PERMISSION in granted(user)


def ensure_platform_admin(user: AuthPayload, scope: PlatformScope) -> None:
    if not is_platform_admin(user, scope):
        raise HTTPException(status_code=403, detail="Réservé à l'administration de l'instance")


def ensure_tenant_access(user: AuthPayload, tenant_id: str | None, scope: PlatformScope) -> None:
    """L'espace visé doit être celui du jeton (ou appelant administrateur de l'instance)."""
    if is_platform_admin(user, scope):
        return
    if not tenant_id or token_tenant(user) != tenant_id:
        # 404 plutôt que 403 : ne pas confirmer l'existence d'un espace tiers.
        raise HTTPException(status_code=404, detail="Tenant not found")
