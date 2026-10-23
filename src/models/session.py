from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .user import User


class Session(Base):
    __tablename__ = "xauth_sessions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_users.id"), nullable=False
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    refresh_token: Mapped[str] = mapped_column(String(255), nullable=False)
    # Identité de l'appareil : un identifiant OPAQUE et aléatoire émis par le
    # serveur à la première connexion depuis cet appareil, que le navigateur
    # conserve et renvoie ensuite (voir services/devices.py).
    #
    # Ce n'est PAS une empreinte au sens « entropie du navigateur » (canvas,
    # WebGL, polices) : cette technique sert à reconnaître un appareil même
    # après effacement des cookies, c'est du pistage, elle demande un
    # consentement et elle casse à chaque mise à jour du navigateur. Ici
    # l'identité est transparente — l'utilisateur voit la liste de ses
    # appareils et peut les révoquer — et c'est suffisant pour les deux seuls
    # usages voulus : « est-ce un appareil jamais vu ? » et « déconnecte mon
    # autre ordinateur ».
    #
    # Ce n'est JAMAIS un facteur d'authentification : la valeur vient du
    # navigateur, donc elle est falsifiable, et elle n'ouvre aucun droit. Elle
    # n'est comparée qu'aux sessions de CET utilisateur (voir
    # AuthService._resolve_device), sans quoi on pourrait sonder l'appareil
    # d'autrui.
    device_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    # User-Agent brut annoncé par le client : donnée NON FIABLE, bornée à la
    # taille de la colonne et nettoyée avant stockage. Gardé pour pouvoir
    # réétiqueter d'anciennes sessions si la dérivation s'améliore.
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # Étiquette lisible dérivée du User-Agent (« Chrome sur macOS ») : ce que
    # l'utilisateur lit dans ses appareils. Un identifiant opaque ne dit rien à
    # personne, donc l'interface montre ceci, jamais device_fingerprint.
    device_label: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    # Ouverture de la session — « connecté le ». Distinct de last_seen, qui
    # bouge à chaque rafraîchissement de jeton : sans cette colonne, « depuis
    # quand cet appareil est-il connecté ? » n'avait pas de réponse.
    #
    # Nullable à dessein : les sessions ouvertes AVANT cette colonne n'ont pas
    # de date d'ouverture connue, et l'ALTER TABLE les laisse à NULL. L'interface
    # lit alors « inconnue », ce qui est exact — une date inventée mentirait.
    created_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    # JTI du dernier access token émis pour cette session — blacklisté au logout
    last_jti: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="sessions")
