from __future__ import annotations

from typing import Sequence

import httpx

from .base import OAuthProvider, OAuthUserInfo


IDENTITY_SCOPES = ["openid", "email", "profile"]

# Les accès à l'API Google, par service : ce que montrent les lignes Gmail, Agenda et Drive des connecteurs
# (voir app/chat routes/connectors_routes.py::GOOGLE_SCOPES, qui lit ces mêmes accès dans l'autre sens).
SERVICE_SCOPES: dict[str, list[str]] = {
    "gmail": [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.send",
    ],
    "calendar": ["https://www.googleapis.com/auth/calendar"],
    "drive": [
        # Lecture seule sur tout le Drive : recherche et lecture de documents
        # existants par l'assistante.
        "https://www.googleapis.com/auth/drive.readonly",
        # Écriture volontairement restreinte aux fichiers créés par DONNA
        # (propose_drive_upload, confirm_action) — jamais un accès en
        # écriture au Drive existant de l'utilisateur.
        "https://www.googleapis.com/auth/drive.file",
    ],
}


# Tous les accès, identité comprise : ce que demande la liaison explicite quand aucun service n'est précisé.
ALL_SCOPES = IDENTITY_SCOPES + [scope for service in SERVICE_SCOPES.values() for scope in service]


class GoogleProvider(OAuthProvider):
    name = "google"
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://oauth2.googleapis.com/token"
    # La CONNEXION ne demande que l'identité : nom, adresse, photo. Gmail, Agenda et Drive se demandent ensuite, un service à la
    # fois, quand on en a besoin (voir `services` ci-dessous). Avant, la connexion réclamait tout d'un coup : un écran de
    # consentement chargé, avec l'avertissement « application non vérifiée » que Google réserve aux accès sensibles (Gmail, Drive),
    # alors que l'on voulait seulement se connecter.
    scopes = IDENTITY_SCOPES

    def get_auth_url(
        self, state: str, extra_params=None, *, reconsent: bool = False, services: Sequence[str] | None = None
    ) -> str:
        """Ce que l'on demande à Google dépend du geste :

        - **Connexion** (ni `reconsent` ni `services`) : l'identité seule, et aucun `prompt` — Google ne montre l'écran de
          consentement qu'à la première autorisation, puis redirige tout seul.
        - **Liaison d'un service** (`services`, depuis un compte connecté) : l'identité et les accès de ces services seulement,
          pour relier Gmail sans réclamer Agenda ni Drive. Un service inconnu est refusé (ValueError), jamais ignoré : une faute
          de frappe demanderait trop PEU en silence.
        - **Liaison explicite sans service précisé** (`reconsent`, « Connecter Google » des Réglages) : tout.

        `reconsent` garde `prompt=consent` : le geste « relier / reconnecter » doit garantir un refresh_token tout neuf (jeton
        perdu, accès révoqué puis réaccordé). `access_type=offline` obtient le refresh_token au premier consentement ; ensuite
        Google n'en renvoie plus, et le stockage garde celui déjà enregistré.

        `include_granted_scopes=true` PARTOUT : Google renvoie l'UNION de ce qui est déjà accordé et de ce qui est demandé. Une
        connexion qui ne redemande que l'identité ne retire donc rien à qui avait accordé Gmail avant, et relier Drive après Gmail
        ne retire pas Gmail — les accès enregistrés restent exacts (voir OAuthService._store_provider_tokens, qui ne rétrécit
        de toute façon jamais des jetons existants)."""
        params = {"access_type": "offline", "include_granted_scopes": "true"}
        if reconsent:
            params["prompt"] = "consent"
        if services:
            unknown = sorted(set(services) - SERVICE_SCOPES.keys())
            if unknown:
                raise ValueError(f"Service Google inconnu : {', '.join(unknown)}. Disponibles : {', '.join(SERVICE_SCOPES)}.")
            chosen = [name for name in SERVICE_SCOPES if name in services]
        else:
            chosen = list(SERVICE_SCOPES) if reconsent else []
        params["scope"] = " ".join(IDENTITY_SCOPES + [scope for name in chosen for scope in SERVICE_SCOPES[name]])
        if extra_params:
            params.update(extra_params)
        return super().get_auth_url(state, params)

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()

        return OAuthUserInfo(
            provider=self.name,
            provider_user_id=data["sub"],
            email=data["email"],
            name=data.get("name"),
            avatar_url=data.get("picture"),
            raw=data,
        )
