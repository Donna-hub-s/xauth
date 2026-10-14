from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from xcore.kernel.api import AuthPayload, get_current_user


def ws_ticket_router(websocket_service: Any) -> APIRouter:
    """Émission d'un ticket WS à usage unique — le jeton d'accès reste
    httpOnly (jamais lu par le JS du navigateur), le navigateur échange ce
    ticket courte durée contre une connexion sur /ws/user (voir
    extensions/xwebsocket/main.py::issue_ticket/_redeem_ticket)."""
    router = APIRouter(prefix="/ws", tags=["auth", "websocket"])

    @router.post("/ticket", summary="Émettre un ticket de connexion WebSocket")
    async def issue_ws_ticket(current_user: AuthPayload = Depends(get_current_user)) -> dict:
        tenant_id = (current_user.get("user") or {}).get("tenant_id")
        if not tenant_id:
            raise HTTPException(403, "Aucun espace de travail sélectionné.")
        if websocket_service is None:
            raise HTTPException(503, "Notifications temps réel indisponibles")
        ticket = websocket_service.issue_ticket(
            user_id=current_user["sub"],
            tenant_id=tenant_id,
            permissions=current_user.get("permissions"),
            roles=current_user.get("roles"),
            channel="user",
        )
        return {"ticket": ticket, "expires_in": 30}

    return router
