from __future__ import annotations

from typing import TypedDict

from xcore.sdk import AutoDispatchMixin, action, error, ok, validate_payload

# ---------- Payload schemas ----------

VERIFY_TOKEN_SCHEMA: TypedDict = { # type: ignore
    "token": (str, ...),
} # type: ignore

HAS_PERMISSION_SCHEMA: TypedDict = {# type: ignore
    "user_id": (str, ...),
    "tenant_id": (str, ...),
    "permission": (str, ...),
    "tennand_id": (str, ...),
}

GET_USER_SCHEMA: TypedDict = {# type: ignore
    "user_id": (str, ...),
}

GET_TENANT_SCHEMA: TypedDict = {# type: ignore
    "tenant_id": (str, ...),
}

LIST_MEMBERS_SCHEMA: TypedDict = {# type: ignore
    "tenant_id": (str, ...),
}

IS_MEMBER_SCHEMA: TypedDict = {# type: ignore
    "tenant_id": (str, ...),
    "user_id": (str, None),
    "email": (str, None),
}

CREATE_INVITE_SCHEMA: TypedDict = {# type: ignore
    "tenant_id": (str, ...),
    "invited_by": (str, ...),
    "email": (str, ...),
    "role_id": (str, None),
    "expires_hours": (int, 72),
}

GET_OAUTH_TOKEN_SCHEMA: TypedDict = {# type: ignore
    "user_id": (str, ...),
    "provider": (str, "google"),
}

LOG_EVENT_SCHEMA: TypedDict = {# type: ignore
    "action": (str, ...),
    "tenant_id": (str, None),
    "user_id": (str, None),
    "resource": (str, None),
    "resource_id": (str, None),
    "ip_address": (str, None),
    "user_agent": (str, None),
    "metadata": (dict, None),
}


# ---------- IPC command mixin ----------


class IPCCommands(AutoDispatchMixin):
    """
    IPC actions for the xauth plugin.
    Inheriting class must provide self._db and self._cache attributes
    plus self._token_service as a TokenService instance.
    """

    @action("xauth.verify_token")
    @validate_payload(VERIFY_TOKEN_SCHEMA, type_response="model", unset=False) # type: ignore
    async def _ipc_verify_token(self, payload) -> dict:
        try:
            claims = self._token_service.verify_access_token(payload.token) # # type: ignore
            # Fetch permissions for the user in their tenant
            tenant_id = claims.get("tenant_id")
            user_id = claims["sub"]
            permissions: list[str] = []
            if tenant_id:
                async with self._db.session() as session:# # type: ignore
                    from .services.rbac import RBACService

                    svc = RBACService(session, cache=self._cache) # # type: ignore
                    permissions = await svc.get_permissions_for_user(user_id, tenant_id)
            return ok(
                user_id=user_id,
                tenant_id=tenant_id,
                permissions=permissions,
                jti=claims.get("jti"),
            )
        except ValueError as exc:
            return error(str(exc), code="invalid_token")
        except Exception as exc:
            return error(f"Token verification failed: {exc}", code="error")

    @action("xauth.has_permission")
    @validate_payload(HAS_PERMISSION_SCHEMA, type_response="model", unset=False) # type: ignore
    async def _ipc_has_permission(self, payload) -> dict:
        try:
            async with self._db.session() as session: # type: ignore
                from .services.rbac import RBACService

                svc = RBACService(session, cache=self._cache) # # type: ignore
                result = await svc.has_permission(
                    payload.user_id, payload.tenant_id, payload.permission
                )
            return ok(has_permission=result)
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.get_user")
    @validate_payload(GET_USER_SCHEMA, type_response="model", unset=False) # type: ignore
    async def _ipc_get_user(self, payload) -> dict:
        try:
            async with self._db.session() as session: # type: ignore
                from .repositories.user import UserRepository

                repo = UserRepository(session)
                user = await repo.get(payload.user_id)
                if user is None:
                    return error("User not found", code="not_found")
                return ok(
                    user={
                        "id": user.id,
                        "email": user.email,
                        "is_active": user.is_active,
                        "mfa_enabled": user.mfa_enabled,
                    }
                )
        except Exception as exc:
            return error(str(exc), code="error")

    # Défense en profondeur : le seul appelant (usage_routes.py, /usage/tenant*) exige déjà require_tenant_admin
    # (owner du tenant, `tenants:write`, OU admin plateforme, `admin:*`) côté HTTP, avec le bon contrôle de portée
    # (le tenant visé doit être celui du jeton). ActionPermissionMiddleware revérifie ici en OU — plus grossier
    # (pas de contrôle du tenant du jeton, comme pour xauth.get_tenant ci-dessous) mais un deuxième filet
    # indépendant plutôt qu'aucun. `permission_groups` (OU de ET) évite de refuser à tort un admin plateforme qui
    # n'est pas owner de CE tenant précis — un simple `permissions=["tenants:write"]` l'aurait fait.
    @action("xauth.list_members", permission_groups=[["tenants:write"], ["admin:*"]])
    @validate_payload(LIST_MEMBERS_SCHEMA, type_response="model", unset=False) # type: ignore
    async def _ipc_list_members(self, payload) -> dict:
        """Membres d'UN espace (celui que l'appelant désigne — le plugin chat l'impose depuis le jeton de la requête, jamais
        depuis une entrée de l'utilisateur) : identifiant, email, propriétaire, actif. Aucun secret ; plafonné."""
        try:
            async with self._db.session() as session: # type: ignore
                from .repositories.user import TenantMemberRepository

                members = await TenantMemberRepository(session).get_members_of_tenant(payload.tenant_id)
                return ok(
                    members=[
                        {
                            "user_id": member.user_id,
                            "email": member.user.email if member.user else None,
                            "is_owner": bool(member.is_owner),
                            "is_active": bool(member.user.is_active) if member.user else False,
                        }
                        for member in members[:500]
                    ]
                )
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.is_member")
    @validate_payload(IS_MEMBER_SCHEMA, type_response="model", unset=False) # type: ignore
    async def _ipc_is_member(self, payload) -> dict:
        """UN booléen : ce compte (par `user_id`) ou cette adresse (par `email`) est-il membre de CET espace ? Rien d'autre n'est renvoyé — ni
        identifiant, ni rôle, ni liste. Sert à inviter dans un projet seulement quelqu'un de l'espace, et à nettoyer les appartenances de
        projet d'un compte qui a quitté l'espace. Volontairement SANS exigence de permission : un propriétaire de projet (pas
        forcément responsable de l'espace) doit pouvoir poser la question ; le tenant est imposé par l'appelant (le plugin chat le lit
        dans le jeton), jamais choisi par un utilisateur."""
        try:
            from sqlalchemy import func, select

            from .models.user import TenantMember, User

            user_id = getattr(payload, "user_id", None)
            email = (getattr(payload, "email", None) or "").strip().lower()
            if not user_id and not email:
                return error("user_id ou email requis", code="invalid")
            async with self._db.session() as session: # type: ignore
                query = (
                    select(User.is_active)
                    .join(TenantMember, TenantMember.user_id == User.id)
                    .where(TenantMember.tenant_id == payload.tenant_id)
                )
                query = query.where(User.id == user_id) if user_id else query.where(func.lower(User.email) == email)
                row = (await session.execute(query)).first()
            return ok(member=row is not None, active=bool(row[0]) if row is not None else False)
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.get_tenant", permissions=["admin:*"])
    @validate_payload(GET_TENANT_SCHEMA, type_response="model", unset=False) # # type: ignore
    async def _ipc_get_tenant(self, payload) -> dict:
        # Défense en profondeur : le seul appelant (usage_routes.py, /usage/platform) exige déjà
        # require_platform_admin (admin:* dans le tenant plateforme) côté HTTP. ActionPermissionMiddleware
        # (xcoreruntime >= 2.8.1) revérifie admin:* ici — plus grossier que require_platform_admin (pas de
        # contrôle du tenant du jeton), mais un deuxième filet indépendant plutôt qu'aucun.
        try:
            async with self._db.session() as session: # # type: ignore
                from .repositories.tenant import TenantRepository

                repo = TenantRepository(session)
                tenant = await repo.get(payload.tenant_id)
                if tenant is None:
                    return error("Tenant not found", code="not_found")
                return ok(
                    tenant={
                        "id": tenant.id,
                        "name": tenant.name,
                        "slug": tenant.slug,
                    }
                )
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.create_invite")
    @validate_payload(CREATE_INVITE_SCHEMA, type_response="model", unset=False) # # type: ignore
    async def _ipc_create_invite(self, payload) -> dict:
        try:
            async with self._db.session() as session: # type: ignore
                from .services.invite import InviteService

                svc = InviteService(session)
                invite = await svc.create_invite(
                    tenant_id=payload.tenant_id,
                    invited_by=payload.invited_by,
                    email=payload.email,
                    role_id=getattr(payload, "role_id", None),
                    expires_hours=getattr(payload, "expires_hours", 72),
                )
                await session.commit()
                return ok(
                    invite={
                        "id": invite.id,
                        "token": invite.token,
                        "email": invite.email,
                        "tenant_id": invite.tenant_id,
                        "expires_at": invite.expires_at.isoformat(),
                    }
                )
        except Exception as exc:
            return error(str(exc), code="error")

    @action("xauth.get_oauth_token")
    @validate_payload(GET_OAUTH_TOKEN_SCHEMA, type_response="model", unset=False) # type: ignore
    async def _ipc_get_oauth_token(self, payload) -> dict:
        """Résout un jeton API tiers valide (Gmail/Calendar...) pour un
        utilisateur ayant lié ce provider — rafraîchi automatiquement si
        expiré. Seul ce plugin possède les jetons chiffrés ; les autres
        passent par ici plutôt que d'y accéder directement."""
        try:
            from .services.oauth import OAuthService

            async with self._db.session() as session: # type: ignore
                svc = OAuthService(
                    session,
                    self._token_service, # type: ignore
                    self._cache, # type: ignore
                    self._oauth_providers, # type: ignore
                    cipher=self._token_cipher, # type: ignore
                )
                access_token, scopes = await svc.get_valid_access_token(
                    payload.user_id, payload.provider
                )
                await session.commit()
            return ok(access_token=access_token, scopes=scopes)
        except ValueError as exc:
            return error(str(exc), code="token_unavailable")
        except Exception as exc:
            return error(f"Résolution du jeton échouée : {exc}", code="error")

    @action("xauth.log_event")
    @validate_payload(LOG_EVENT_SCHEMA, type_response="model", unset=False) # type: ignore
    async def _ipc_log_event(self, payload) -> dict:
        try:
            async with self._db.session() as session: # # type: ignore
                from .services.audit import AuditService

                svc = AuditService(session)
                entry = await svc.log_event(
                    action=payload.action,
                    tenant_id=getattr(payload, "tenant_id", None),
                    user_id=getattr(payload, "user_id", None),
                    resource=getattr(payload, "resource", None),
                    resource_id=getattr(payload, "resource_id", None),
                    ip_address=getattr(payload, "ip_address", None),
                    user_agent=getattr(payload, "user_agent", None),
                    metadata=getattr(payload, "metadata", None),
                )
                await session.commit()
                return ok(audit_log_id=entry.id)
        except Exception as exc:
            return error(str(exc), code="error")
