from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserRootSchemas(BaseModel):

    ADMIN_EMAIL: str
    ADMIN_PASSWORD: str
    ADMIN_TENANT_SLUG: str
    ADMIN_TENANT_NAME: str
    ADMIN_ROLE_NAME: str
    USER_ROLE_NAME: str



class TenantInfo(BaseModel):
    id: str
    name: Optional[str] = None
    slug: Optional[str] = None
    role_id: Optional[str] = None
    is_owner: bool = False

class SelectTenantRequest(BaseModel):
    refresh_token: str
    tenant_id: str

class VerifyMfaLoginRequest(BaseModel):
    mfa_token: str
    code: str

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_id: Optional[str] = None
    # Identité de l'appareil déjà connue du navigateur (voir services/devices.py). Donnée NON
    # FIABLE : elle n'est reconnue que si elle figure dans une session de CE compte, et elle
    # n'authentifie rien. Absente à la première connexion depuis un appareil — le serveur en
    # émet alors une et la renvoie dans `TokenResponse.device_id`.
    device_id: Optional[str] = Field(default=None, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class SetupCreateRequest(BaseModel):
    refresh_token: str
    name: str
    slug: str


class SetupJoinRequest(BaseModel):
    refresh_token: str
    invite_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    mfa_required: bool = False
    # Jeton court (5 min), à usage unique, distinct du refresh_token — présent
    # uniquement si mfa_required=true. Corrèle l'appel à /auth/mfa/verify-login
    # sans jamais faire circuler un refresh_token utilisable (donc exploitable
    # via /auth/refresh) avant que le code TOTP ne soit vérifié.
    mfa_token: Optional[str] = None
    # Identité de l'appareil émise (ou reconnue) par le serveur, à conserver côté navigateur et
    # à renvoyer aux connexions suivantes. Absente quand aucun jeton n'est émis (étape MFA).
    device_id: Optional[str] = None
    needs_tenant_setup: bool = False  # ← true si l'user n'appartient à aucun tenant
    tenants: Optional[list[TenantInfo]] = None  # ← présent uniquement si multi-tenant


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    is_active: bool
    mfa_enabled: bool
    # Jamais le hash lui-même — juste de quoi choisir entre "changer" et
    # "définir" un mot de passe côté interface (comptes créés par OAuth).
    has_password: bool
