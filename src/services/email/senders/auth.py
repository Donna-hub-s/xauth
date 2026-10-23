from __future__ import annotations

from ..base import EmailTransport


class AuthEmailSender(EmailTransport):
    """Emails liés à l'inscription et à la connexion."""

    async def welcome(self, to: str, username: str) -> bool:
        return await self.send(
            to=to,
            subject=f"Bienvenue sur {self.app_name}",
            template="welcome",
            context={"username": username},
        )

    async def new_device(
        self,
        to: str,
        username: str,
        device: str,
        ip_address: str,
    ) -> bool:
        """Avertit qu'une session vient de s'ouvrir depuis un appareil jamais vu.

        Par e-mail et non par notification dans l'application : si la connexion est celle d'un
        attaquant, un message affiché dans l'app lui serait adressé à LUI. L'e-mail part vers
        l'adresse du compte, donc vers la personne à prévenir.

        `device` et `ip_address` viennent d'un en-tête HTTP, donc d'une source non fiable : le
        gabarit est rendu avec l'échappement automatique de Jinja (voir base._render), ce qui
        empêche d'y glisser du balisage.
        """
        return await self.send(
            to=to,
            subject=f"Nouvelle connexion à votre compte {self.app_name}",
            template="new_device",
            context={
                "username": username,
                "device": device,
                "ip_address": ip_address,
                # Construite ici, comme pour les autres envois : le gabarit ne fabrique pas
                # d'URL, il affiche celle qu'on lui donne.
                "devices_url": f"{self.web_url}/fr/app",
            },
        )

    async def oauth_linked(
        self,
        to: str,
        username: str,
        provider: str,
        provider_email: str,
    ) -> bool:
        return await self.send(
            to=to,
            subject=f"Compte {provider} lié à votre profil",
            template="oauth_linked",
            context={
                "username": username,
                "provider": provider.capitalize(),
                "provider_email": provider_email,
            },
        )
