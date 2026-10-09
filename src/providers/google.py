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


class GoogleProvider(OAuthProvider):
    name = "google"
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://oauth2.googleapis.com/token"
    # La connexion demande TOUT, d'un coup (même liste et même ordre qu'avant la découpe par service).
    scopes = IDENTITY_SCOPES + [scope for service in SERVICE_SCOPES.values() for scope in service]

    def get_auth_url(
        self, state: str, extra_params=None, *, reconsent: bool = False, services: Sequence[str] | None = None
    ) -> str:
        """Connexion : aucun `prompt`. Google ne montre alors l'écran de
        consentement (avertissement « application non vérifiée », liste des
        accès, cases à valider) qu'à la PREMIÈRE autorisation, ou quand un
        scope ajouté depuis n'a jamais été accordé ; ensuite il redirige tout
        seul, au pire avec le sélecteur de compte. `prompt=consent` forcé à
        chaque connexion infligeait tout ce parcours à chaque reconnexion.

        `access_type=offline` suffit à obtenir le refresh_token au premier
        consentement ; aux connexions suivantes Google n'en renvoie pas de
        nouveau, et `_store_provider_tokens` garde alors celui déjà stocké
        (il ne remplace que s'il en reçoit un).

        Liaison explicite (`reconsent`) : `prompt=consent` est conservé — c'est
        le geste « reconnecter Google » qui doit garantir un refresh_token
        tout neuf (jeton perdu, accès révoqué puis réaccordé).

        `services` (liaison depuis un compte connecté) : on ne demande que l'identité et les accès de ces services — c'est ce
        qui permet de relier Gmail sans réclamer Agenda ni Drive. `include_granted_scopes` garde ce qui a déjà été accordé :
        Google renvoie l'UNION, donc relier Drive après Gmail ne retire pas Gmail, et les accès enregistrés restent exacts.
        Un service inconnu est refusé (ValueError), jamais ignoré : sans cela une faute de frappe demanderait trop peu en silence."""
        params = {"access_type": "offline"}
        if reconsent:
            params["prompt"] = "consent"
        if services:
            unknown = sorted(set(services) - SERVICE_SCOPES.keys())
            if unknown:
                raise ValueError(f"Service Google inconnu : {', '.join(unknown)}. Disponibles : {', '.join(SERVICE_SCOPES)}.")
            wanted = IDENTITY_SCOPES + [scope for name, scopes in SERVICE_SCOPES.items() if name in services for scope in scopes]
            params["scope"] = " ".join(wanted)
            params["include_granted_scopes"] = "true"
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
