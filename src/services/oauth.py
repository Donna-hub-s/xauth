from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

_logger = logging.getLogger(__name__)

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.oauth import OAuthAccount
from ..models.session import Session
from ..models.user import User
from ..providers.base import OAuthProvider, OAuthUserInfo
from ..repositories.oauth import OAuthAccountRepository
from ..repositories.session import SessionRepository
from ..repositories.user import UserRepository
from .crypto import TokenCipher
from .token import TokenService

# TTL du state CSRF en secondes
_STATE_TTL = 600
_STATE_KEY_PREFIX = "xauth:oauth:state:"


class OAuthError(ValueError):
    """ValueError qui porte en plus un `code` stable. Le message reste destiné
    aux logs et à la réponse JSON des routes API ; c'est le code (et lui seul)
    que le callback met dans l'URL de retour vers le navigateur — le frontend
    le traduit (voir frontend/lib/oauth-feedback.ts). Avant, c'était le texte
    de l'exception, parfois suivi de la réponse brute du provider."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# Codes renvoyés au navigateur — une liste fermée, que le frontend connaît.
STATE_INVALID = "state_invalid"
PROVIDER_UNKNOWN = "provider_unknown"
PROVIDER_ERROR = "provider_error"
ACCOUNT_DISABLED = "account_disabled"
ALREADY_LINKED = "already_linked"
ACCESS_DENIED = "access_denied"  # l'utilisateur a refusé (ou annulé) le consentement chez le provider


def error_code(exc: BaseException) -> str:
    """Code à exposer au navigateur pour une erreur du flux OAuth."""
    return exc.code if isinstance(exc, OAuthError) else PROVIDER_ERROR


class OAuthService:
    """
    Gère le flow OAuth2 complet : génération d'URL, callback, find-or-create user.
    Le state CSRF est stocké en cache Redis (TTL 10min).
    """

    def __init__(
        self,
        session: AsyncSession,
        token_service: TokenService,
        cache: Any,
        providers: dict[str, OAuthProvider],
        cipher: TokenCipher | None = None,
    ) -> None:
        self._session = session
        self._token = token_service
        self._cache = cache
        self._providers = providers
        self._cipher = cipher

    # ── Providers registry ────────────────────────────────────────────────────

    def get_provider(self, name: str) -> OAuthProvider:
        provider = self._providers.get(name)
        if provider is None:
            available = ", ".join(self._providers.keys()) or "aucun"
            raise OAuthError(PROVIDER_UNKNOWN, f"Provider '{name}' inconnu. Disponibles : {available}")
        return provider

    def list_providers(self) -> list[str]:
        return list(self._providers.keys())

    # ── Step 1 : générer l'URL d'autorisation ────────────────────────────────

    async def get_auth_url(
        self,
        provider_name: str,
        tenant_id: Optional[str] = None,
        post_login_redirect: Optional[str] = None,
        link_for_user_id: Optional[str] = None,
    ) -> str:
        provider = self.get_provider(provider_name)

        state = secrets.token_urlsafe(32)
        state_data = {
            "provider": provider_name,
            "tenant_id": tenant_id,
            "redirect": post_login_redirect,
            # Présent uniquement pour un /authorize appelé par un utilisateur
            # déjà authentifié qui veut lier ce provider à SON compte (voir
            # routes/oauth.py::authorize) — handle_callback lie alors à ce
            # user_id explicitement, sans passer par _find_or_create_user
            # (qui matche par email : un email Google différent créerait et
            # connecterait silencieusement un tout autre compte, vide).
            "link_for_user_id": link_for_user_id,
        }
        # Le backend cache (RedisCacheBackend/MemoryBackend, voir
        # xcore.services.cache.backends) fait déjà la sérialisation JSON en
        # interne (.set accepte un dict tel quel) — json.dumps ici avant
        # .set() encodait un dict en str, que RedisCacheBackend.set()
        # stockait alors tel quel (déjà une str), MAIS son .get() tente
        # TOUJOURS un json.loads() sur ce qu'il lit de Redis et réussit
        # (c'était du JSON valide) → renvoie un dict, pas la str attendue.
        # handle_callback() ci-dessous refaisait alors json.loads(dict),
        # qui lève TypeError (pas ValueError) à CHAQUE callback OAuth,
        # sans exception côté /authorize — 100% reproductible, constaté en
        # conditions réelles (connexion GitHub systématiquement "annulée ou
        # échouée" malgré un flow authorize→callback par ailleurs correct).
        await self._cache.set(
            f"{_STATE_KEY_PREFIX}{state}",
            state_data,
            ttl=_STATE_TTL,
        )
        # Liaison depuis un compte connecté = geste explicite « reconnecter » :
        # on redemande le consentement. Une simple connexion ne le redemande pas.
        return provider.get_auth_url(state, reconsent=link_for_user_id is not None)

    # ── Step 2 : callback — échange le code, trouve ou crée le user ──────────

    async def _take_state(self, provider_name: str, state: str | None) -> dict[str, Any]:
        """Vérifie et CONSOMME le state CSRF (usage unique) ; renvoie ce qu'il porte."""
        state_data = await self._cache.get(f"{_STATE_KEY_PREFIX}{state}") if state else None
        if state_data is None:
            raise OAuthError(STATE_INVALID, "State OAuth invalide ou expiré.")
        await self._cache.delete(f"{_STATE_KEY_PREFIX}{state}")
        if state_data.get("provider") != provider_name:
            raise OAuthError(STATE_INVALID, "State OAuth : provider mismatch.")
        return state_data

    async def handle_denied(self, provider_name: str, state: str | None, reason: str | None = None) -> dict[str, Any]:
        """Le provider revient SANS code : l'utilisateur a annulé ou refusé le consentement (`?error=access_denied`), ou le
        provider a échoué. Rien n'est créé ni modifié.

        Liaison depuis un compte connecté : on renvoie `link_error` et la page d'où l'on venait — pas la page de connexion.
        Connexion : on lève, et la route renvoie sur /auth avec le code."""
        state_data = await self._take_state(provider_name, state)
        # « access_denied » est le mot que Google, GitHub, Discord et Microsoft envoient tous quand on refuse ; tout autre retour
        # sans code (serveur en panne, scope invalide, appel sans paramètre) est une défaillance du provider, pas un refus.
        code = ACCESS_DENIED if reason == "access_denied" else PROVIDER_ERROR
        _logger.info("[oauth] %s : retour sans code (%s)", provider_name, reason)
        if state_data.get("link_for_user_id"):
            return {"link_error": code, "post_login_redirect": state_data.get("redirect")}
        raise OAuthError(code, f"Retour du provider sans code : {reason or 'refus'}")

    async def handle_callback(
        self,
        provider_name: str,
        code: str,
        state: str,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        state_data = await self._take_state(provider_name, state)
        provider = self.get_provider(provider_name)

        # Échanger le code contre un jeton, puis lire le profil. Si le provider ou le réseau échoue, une LIAISON revient sur la
        # page d'où elle est partie (avec le code d'erreur) : avant, tout échec renvoyait vers /login, même un utilisateur
        # déjà connecté qui reliait Google depuis ses réglages.
        try:
            token_data = await provider.exchange_code(code)
            access_token = token_data.get("access_token")
            if not access_token:
                raise OAuthError(PROVIDER_ERROR, f"Le provider n'a pas retourné d'access_token : {token_data}")
            user_info = await provider.get_user_info(access_token)
        except Exception as exc:
            # Trace complète pour une défaillance imprévue (réseau, réponse illisible) : la route la journalisait avant, avec sa pile.
            _logger.warning("[oauth] %s : échange avec le provider échoué : %s", provider_name, exc, exc_info=not isinstance(exc, OAuthError))
            if state_data.get("link_for_user_id"):
                return {"link_error": error_code(exc), "post_login_redirect": state_data.get("redirect")}
            if isinstance(exc, OAuthError):
                raise
            raise OAuthError(PROVIDER_ERROR, "Échange avec le provider échoué.") from exc

        link_for_user_id: Optional[str] = state_data.get("link_for_user_id")
        if link_for_user_id:
            # Liaison depuis un compte déjà authentifié (voir Settings) — pas
            # de find-or-create par email : ValueError attendue si ce compte
            # provider appartient déjà à quelqu'un d'autre, retournée comme
            # résultat plutôt que levée pour ne pas retomber sur la
            # redirection générique de connexion (voir routes/oauth.py::callback).
            try:
                await self._link_account(link_for_user_id, provider_name, token_data, user_info)
            except ValueError as exc:
                return {
                    "link_error": error_code(exc),
                    "post_login_redirect": state_data.get("redirect"),
                }
            return {
                "linked": provider_name,
                "post_login_redirect": state_data.get("redirect"),
            }

        # Find-or-create
        user = await self._find_or_create_user(user_info)
        await self._store_provider_tokens(provider_name, user_info.provider_user_id, token_data)

        if not user.is_active:
            raise OAuthError(ACCOUNT_DISABLED, "Compte désactivé.")

        # Même parcours que la connexion par mot de passe (AuthService._finalize_login) :
        # MFA avant tout jeton, puis espace unique, choix ou création d'espace.
        # Auparavant la connexion OAuth ignorait la MFA et émettait les jetons directement.
        from ..repositories.user import TenantMemberRepository
        from .auth import AuthService

        # tenant_id imposé dans le state (ex. lien d'invitation) : seulement si
        # l'utilisateur en est membre. Sinon, jeton scopé sur l'espace d'un tiers.
        forced_tenant_id: Optional[str] = state_data.get("tenant_id")
        if forced_tenant_id:
            membership = await TenantMemberRepository(self._session).get_membership(user.id, forced_tenant_id)
            if membership is None:
                _logger.warning("[oauth] tenant_id imposé ignoré : %s n'est pas membre", user.id)
                forced_tenant_id = None

        auth = AuthService(self._session, self._token, cache=self._cache)
        result = await auth._finalize_login(user, forced_tenant_id, ip_address)
        result.update(
            provider=provider_name,
            is_new_user=getattr(user, "_is_new", False),
            post_login_redirect=state_data.get("redirect"),
        )
        return result

    # ── Lier un provider à un user déjà authentifié ──────────────────────────

    async def link_provider(
        self,
        user_id: str,
        provider_name: str,
        code: str,
        state: str,
    ) -> OAuthAccount:
        # Vérifier le state
        state_key = f"{_STATE_KEY_PREFIX}{state}"
        raw = await self._cache.get(state_key)
        if raw is None:
            raise OAuthError(STATE_INVALID, "State OAuth invalide ou expiré.")
        await self._cache.delete(state_key)

        provider = self.get_provider(provider_name)
        token_data = await provider.exchange_code(code)
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError("Échange de code échoué.")

        user_info = await provider.get_user_info(access_token)
        return await self._link_account(user_id, provider_name, token_data, user_info)

    async def _link_account(
        self,
        user_id: str,
        provider_name: str,
        token_data: dict[str, Any],
        user_info: OAuthUserInfo,
    ) -> OAuthAccount:
        """Cœur partagé de link_provider (POST /oauth/{provider}/link) et de la
        branche liaison de handle_callback — voir son docstring pour pourquoi
        deux appelants distincts existent."""
        oauth_repo = OAuthAccountRepository(self._session)

        # Vérifier que ce compte provider n'est pas déjà lié à un autre user
        existing = await oauth_repo.get_by_provider(provider_name, user_info.provider_user_id)
        if existing and existing.user_id != user_id:
            raise OAuthError(
                ALREADY_LINKED,
                f"Ce compte {provider_name} est déjà lié à un autre utilisateur.",
            )

        if existing:
            # Compte déjà lié — re-lier (ex: pour obtenir des scopes plus
            # larges, Gmail/Calendar) doit mettre à jour ses jetons, pas les
            # ignorer : sans ça, relier à nouveau pour élargir les scopes ne
            # servait à rien, le jeton fraîchement consenti était jeté.
            account = existing
        else:
            account = OAuthAccount(
                user_id=user_id,
                provider=provider_name,
                provider_user_id=user_info.provider_user_id,
                provider_email=user_info.email,
                provider_name=user_info.name,
                provider_avatar=user_info.avatar_url,
            )
            await oauth_repo.save(account)

        await self._store_provider_tokens(provider_name, user_info.provider_user_id, token_data)
        return account

    # ── Délier un provider ────────────────────────────────────────────────────

    async def unlink_provider(self, user_id: str, provider_name: str) -> None:
        oauth_repo = OAuthAccountRepository(self._session)
        account = await oauth_repo.get_by_user_and_provider(user_id, provider_name)
        if account is None:
            raise ValueError(f"Aucun compte {provider_name} lié à cet utilisateur.")

        # Empêcher de délier si c'est le seul moyen de connexion (pas de password)
        user_repo = UserRepository(self._session)
        user = await user_repo.get(user_id)
        if user and not user.hashed_password:
            all_accounts = await oauth_repo.list_for_user(user_id)
            if len(all_accounts) <= 1:
                raise ValueError(
                    "Impossible de délier : ce compte n'a pas de mot de passe. "
                    "Définissez un mot de passe avant de délier ce provider."
                )

        await self._session.delete(account)
        await self._session.flush()

    # ── Jeton API valide (Gmail/Calendar...) pour un provider lié ────────────

    async def get_valid_access_token(
        self, user_id: str, provider_name: str
    ) -> tuple[str, list[str]]:
        """Retourne (access_token, granted_scopes) prêt à l'emploi contre
        l'API du provider — rafraîchit automatiquement si expiré. Lève
        ValueError avec un message explicite (non lié, chiffrement
        indisponible, refresh échoué...) plutôt que de renvoyer un jeton
        invalide en silence."""
        if self._cipher is None:
            raise ValueError("Chiffrement des jetons non configuré côté serveur.")

        oauth_repo = OAuthAccountRepository(self._session)
        account = await oauth_repo.get_by_user_and_provider(user_id, provider_name)
        if account is None or not account.access_token_encrypted:
            raise ValueError(f"Aucun compte {provider_name} lié (avec jeton API) pour cet utilisateur.")

        scopes = (account.granted_scopes or "").split()

        now = datetime.now(timezone.utc)
        expires_at = account.token_expires_at
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at is None or now < expires_at:
            return self._cipher.decrypt(account.access_token_encrypted), scopes

        # Expiré — refresh nécessaire.
        if not account.refresh_token_encrypted:
            raise ValueError(
                f"Jeton {provider_name} expiré et aucun refresh_token disponible — "
                "l'utilisateur doit relier son compte à nouveau."
            )

        provider = self.get_provider(provider_name)
        refresh_token = self._cipher.decrypt(account.refresh_token_encrypted)
        try:
            token_data = await provider.refresh_access_token(refresh_token)
        except Exception as exc:
            raise ValueError(f"Rafraîchissement du jeton {provider_name} échoué : {exc}") from exc

        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError(f"Rafraîchissement du jeton {provider_name} : réponse sans access_token.")

        account.access_token_encrypted = self._cipher.encrypt(access_token)
        expires_in = int(token_data.get("expires_in", 3600))
        account.token_expires_at = now + timedelta(seconds=expires_in)
        # Google ne renvoie pas toujours un nouveau refresh_token au refresh
        # (normal, le même reste valide) — on ne remplace que s'il y en a un.
        if token_data.get("refresh_token"):
            account.refresh_token_encrypted = self._cipher.encrypt(token_data["refresh_token"])
        await self._session.flush()

        return access_token, scopes

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _store_provider_tokens(
        self, provider_name: str, provider_user_id: str, token_data: dict[str, Any]
    ) -> None:
        """Chiffre et persiste les jetons API (distincts des jetons de
        session xauth) sur l'OAuthAccount correspondant — no-op silencieux si
        le chiffrement n'est pas configuré ou si le provider n'a renvoyé
        aucun access_token (providers identité-seule)."""
        access_token = token_data.get("access_token")
        if self._cipher is None or not access_token:
            return

        oauth_repo = OAuthAccountRepository(self._session)
        account = await oauth_repo.get_by_provider(provider_name, provider_user_id)
        if account is None:
            return

        account.access_token_encrypted = self._cipher.encrypt(access_token)
        if token_data.get("refresh_token"):
            account.refresh_token_encrypted = self._cipher.encrypt(token_data["refresh_token"])
        expires_in = int(token_data.get("expires_in", 3600))
        account.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        if token_data.get("scope"):
            account.granted_scopes = token_data["scope"]
        await self._session.flush()

    async def _find_or_create_user(self, info: OAuthUserInfo) -> User:
        oauth_repo = OAuthAccountRepository(self._session)
        user_repo = UserRepository(self._session)

        # 1. Chercher par (provider, provider_user_id)
        account = await oauth_repo.get_by_provider(info.provider, info.provider_user_id)
        if account:
            user = await user_repo.get(account.user_id)
            if user:
                return user

        # 2. Chercher un user existant par email
        user = await user_repo.get_by_email(info.email)
        if user:
            # Lier ce provider au compte existant
            new_account = OAuthAccount(
                user_id=user.id,
                provider=info.provider,
                provider_user_id=info.provider_user_id,
                provider_email=info.email,
                provider_name=info.name,
                provider_avatar=info.avatar_url,
            )
            await oauth_repo.save(new_account)
            return user

        # 3. Créer un nouveau user
        user = User(email=info.email, hashed_password=None, is_active=True)
        user._is_new = True  # flag pour la réponse
        await user_repo.save(user)

        new_account = OAuthAccount(
            user_id=user.id,
            provider=info.provider,
            provider_user_id=info.provider_user_id,
            provider_email=info.email,
            provider_name=info.name,
            provider_avatar=info.avatar_url,
        )
        await oauth_repo.save(new_account)
        return user
