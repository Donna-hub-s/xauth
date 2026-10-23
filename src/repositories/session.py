from __future__ import annotations

from typing import Optional

from sqlalchemy import select

from ..models.session import Session
from .base import BaseRepository


class SessionRepository(BaseRepository[Session]):
    model = Session

    async def get_by_refresh_token(self, hashed_token: str) -> Optional[Session]:
        result = await self.session.execute(
            select(Session)
            .where(Session.refresh_token == hashed_token)
            .where(Session.is_revoked == False)  # noqa: E712
        )
        return result.scalar_one_or_none()

    async def get_active_sessions_for_user(self, user_id: str) -> list[Session]:
        result = await self.session.execute(
            select(Session)
            .where(Session.user_id == user_id)
            .where(Session.is_revoked == False)  # noqa: E712
        )
        return list(result.scalars().all())

    async def device_is_known(self, user_id: str, device_id: str) -> bool:
        """Cet utilisateur s'est-il déjà connecté depuis cet appareil ?

        Les sessions révoquées et expirées comptent : se déconnecter d'un appareil n'en fait pas
        un appareil inconnu, sinon chaque reconnexion déclencherait une alerte.

        Le filtre sur `user_id` est une règle de sécurité, pas une optimisation : sans lui,
        présenter l'identifiant d'autrui révélerait s'il existe, donc permettrait de sonder les
        appareils d'un autre compte.
        """
        result = await self.session.execute(
            select(Session.id)
            .where(Session.user_id == user_id)
            .where(Session.device_fingerprint == device_id)
            .limit(1)
        )
        return result.scalar_one_or_none() is not None

    async def has_any_session(self, user_id: str) -> bool:
        """L'utilisateur a-t-il déjà ouvert une session ? Sert à ne pas alerter sur la toute
        première connexion du compte : un « nouvel appareil » y est la normalité, pas un signal."""
        result = await self.session.execute(
            select(Session.id).where(Session.user_id == user_id).limit(1)
        )
        return result.scalar_one_or_none() is not None

    async def revoke_all_for_user(self, user_id: str) -> None:
        sessions = await self.get_active_sessions_for_user(user_id)
        for s in sessions:
            s.is_revoked = True
        await self.session.flush()
