from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class TenantCreate(BaseModel):
    name: str
    slug: str
    settings: Optional[dict] = None


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    settings: Optional[dict] = None


class TenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    created_at: datetime


class MemberResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    tenant_id: str
    role_id: Optional[str]
    joined_at: datetime
    is_owner: bool
