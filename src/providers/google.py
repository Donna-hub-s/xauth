from __future__ import annotations

import httpx

from .base import OAuthProvider, OAuthUserInfo


class GoogleProvider(OAuthProvider):
    name = "google"
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://oauth2.googleapis.com/token"
    scopes = [
        "openid",
        "email",
        "profile",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/calendar",
        # Lecture seule sur tout le Drive : recherche et lecture de documents
        # existants par l'assistante.
        "https://www.googleapis.com/auth/drive.readonly",
        # Écriture volontairement restreinte aux fichiers créés par DONNA
        # (propose_drive_upload, confirm_action) — jamais un accès en
        # écriture au Drive existant de l'utilisateur.
        "https://www.googleapis.com/auth/drive.file",
    ]

    def get_auth_url(self, state: str, extra_params=None, *, reconsent: bool = False) -> str:
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
        tout neuf (jeton perdu, accès révoqué puis réaccordé)."""
        params = {"access_type": "offline"}
        if reconsent:
            params["prompt"] = "consent"
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
