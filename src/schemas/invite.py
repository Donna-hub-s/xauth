from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class InviteCreate(BaseModel):
    tenant_id: str
    email: EmailStr
    role_id: Optional[str] = None
    expires_hours: int = Field(default=72, ge=1, le=24 * 14)


class AcceptInviteRequest(BaseModel):
    token: str
    # Ignoré : l'utilisateur est celui du jeton. Conservé pour compatibilité.
    user_id: Optional[str] = None


class InvitePreview(BaseModel):
    """Aperçu public d'une invitation (page d'acceptation) : ni jeton, ni identifiants internes."""
    tenant_name: str
    email: str
    expires_at: datetime
    valid: bool


class InviteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    email: str
    token: str
    role_id: Optional[str]
    expires_at: datetime
    used_at: Optional[datetime]
    is_active: bool
    invited_by: str
