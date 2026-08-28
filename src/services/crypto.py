"""
Chiffrement symétrique (Fernet) des jetons OAuth tiers (Gmail, Calendar...)
stockés en base — distinct des jetons de session xauth (JWT RS256/hash), ces
jetons-là doivent être déchiffrables pour être réutilisés contre l'API du
provider, donc un simple hash (comme pour les refresh tokens xauth) ne
convient pas ici.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken


class TokenCipherError(Exception):
    """Clé de chiffrement absente/invalide, ou jeton corrompu au déchiffrement."""


class TokenCipher:
    def __init__(self, key: str | None) -> None:
        if not key:
            raise TokenCipherError(
                "XAUTH_TOKEN_ENCRYPTION_KEY absente — impossible de chiffrer/déchiffrer "
                "les jetons OAuth tiers."
            )
        try:
            self._fernet = Fernet(key.encode())
        except (ValueError, TypeError) as exc:
            raise TokenCipherError(f"Clé de chiffrement invalide : {exc}") from exc

    def encrypt(self, plain: str) -> str:
        return self._fernet.encrypt(plain.encode()).decode()

    def decrypt(self, cipher: str) -> str:
        try:
            return self._fernet.decrypt(cipher.encode()).decode()
        except InvalidToken as exc:
            raise TokenCipherError("Jeton chiffré invalide ou corrompu.") from exc
