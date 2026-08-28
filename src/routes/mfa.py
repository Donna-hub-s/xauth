from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from xcore.kernel.api import AuthPayload, get_current_user

from ..services.mfa import MFAService


class VerifyMFARequest(BaseModel):
    code: str


class EnableMFARequest(BaseModel):
    code: str


def mfa_router(db: Any) -> APIRouter:
    router = APIRouter(prefix="/mfa", tags=["mfa"])

    @router.post("/setup")
    async def setup_totp(
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            svc = MFAService(session)
            try:
                result = await svc.setup_totp(user["sub"])
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
            except RuntimeError as exc:
                raise HTTPException(status_code=500, detail=str(exc))

    @router.post("/enable")
    async def enable_mfa(
        body: EnableMFARequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            svc = MFAService(session)
            success = await svc.enable_mfa(user["sub"], body.code)
            if not success:
                raise HTTPException(status_code=400, detail="Invalid TOTP code")
            await session.commit()
            return {"mfa_enabled": True}

    @router.post("/verify")
    async def verify_totp(
        body: VerifyMFARequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            svc = MFAService(session)
            valid = await svc.verify_totp(user["sub"], body.code)
            return {"valid": valid}

    @router.delete("/", status_code=status.HTTP_204_NO_CONTENT)
    async def disable_mfa(
        user: AuthPayload = Depends(get_current_user),
    ) -> None:
        async with db.session() as session:
            svc = MFAService(session)
            await svc.disable_mfa(user["sub"])
            await session.commit()

    @router.post("/backup-codes/regenerate")
    async def regenerate_backup_codes(
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """Régénère les backup codes (invalide les anciens). Affichés une seule fois."""
        async with db.session() as session:
            svc = MFAService(session)
            try:
                codes = await svc.regenerate_backup_codes(user["sub"])
                await session.commit()
                return {"backup_codes": codes}
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    return router
