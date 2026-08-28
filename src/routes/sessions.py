from __future__ import annotations

from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from xcore.kernel.api import AuthPayload, get_current_user

from ..repositories.session import SessionRepository
from ..services.token import TokenService


class SessionResponse(BaseModel):
    id: str
    tenant_id: str | None
    ip_address: str | None
    device_fingerprint: str | None
    last_seen: str
    expires_at: str
    is_current: bool = False

    model_config = {"from_attributes": True}


def sessions_router(db: Any, token_service: TokenService, cache: Any = None) -> APIRouter:
    router = APIRouter(tags=["sessions"])

    # L'ancien POST /auth/verify-mfa (→ AuthService.verify_mfa_and_issue_token)
    # a été retiré : il prenait le refresh_token lui-même comme jeton de
    # corrélation MFA, alors que login() l'émet AVANT toute vérification —
    # ce refresh_token était donc utilisable tel quel via /auth/refresh
    # (qui ne vérifie jamais MFA) pour contourner MFA entièrement. Remplacé
    # par POST /auth/mfa/verify-login (main.py::_auth_router_with_db), qui
    # corrèle via un mfa_token dédié à usage unique — voir AuthService.
    # _finalize_login / verify_mfa_login.

    @router.get("/auth/sessions", response_model=List[SessionResponse])
    async def list_sessions(
        current_user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """Liste toutes les sessions actives de l'utilisateur connecté."""
        async with db.session() as session:
            repo = SessionRepository(session)
            sessions = await repo.get_active_sessions_for_user(current_user["sub"])
            return [
                {
                    "id": s.id,
                    "tenant_id": s.tenant_id,
                    "ip_address": s.ip_address,
                    "device_fingerprint": s.device_fingerprint,
                    "last_seen": s.last_seen.isoformat(),
                    "expires_at": s.expires_at.isoformat(),
                }
                for s in sessions
            ]

    @router.delete("/auth/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_session(
        session_id: str,
        current_user: AuthPayload = Depends(get_current_user),
    ) -> None:
        """Révoque une session spécifique (déconnexion d'un appareil)."""
        async with db.session() as session:
            repo = SessionRepository(session)
            target = await repo.get(session_id)
            if target is None or target.user_id != current_user["sub"]:
                raise HTTPException(status_code=404, detail="Session not found")
            if target.is_revoked:
                raise HTTPException(status_code=400, detail="Session already revoked")

            # Blacklister le JTI si présent
            if cache and target.last_jti:
                ttl = token_service._access_expire * 60 + 30
                await cache.set(f"xauth:jti_bl:{target.last_jti}", "1", ttl=ttl)

            target.is_revoked = True
            await session.commit()

    @router.delete("/auth/sessions", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_all_sessions(
        current_user: AuthPayload = Depends(get_current_user),
    ) -> None:
        """Révoque toutes les sessions actives (logout de tous les appareils)."""
        async with db.session() as session:
            repo = SessionRepository(session)
            sessions = await repo.get_active_sessions_for_user(current_user["sub"])

            for s in sessions:
                if cache and s.last_jti:
                    ttl = token_service._access_expire * 60 + 30
                    await cache.set(f"xauth:jti_bl:{s.last_jti}", "1", ttl=ttl)

            await repo.revoke_all_for_user(current_user["sub"])
            await session.commit()

    return router
