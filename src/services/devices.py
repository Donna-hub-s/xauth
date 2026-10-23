"""Identité des appareils connectés : un identifiant opaque, et une étiquette lisible.

Ce que ce module fait, et ce qu'il ne fait pas
----------------------------------------------
Il donne à chaque appareil une **identité transparente** : un identifiant aléatoire émis par
le serveur à la première connexion, que le navigateur conserve et renvoie ensuite. Cela suffit
aux deux seuls usages voulus — « est-ce un appareil jamais vu ? » (alerte) et « déconnecte mon
autre ordinateur » (révocation).

Il ne fait **pas** d'empreinte par entropie du navigateur (canvas, WebGL, énumération de
polices, horloge audio). Cette technique reconnaît un appareil même après effacement des
cookies ; c'est précisément ce qui en fait une technologie de pistage : consentement à
recueillir, fragilité à chaque mise à jour de navigateur, et un contresens dans une
application qui refuse déjà de charger une image externe ou de récupérer l'aperçu d'un lien
sans geste humain. L'utilisateur voit ici la liste de ses appareils et peut les révoquer :
c'est la transparence qui rend la fonction acceptable.

Deux règles de sécurité à ne pas relâcher
------------------------------------------
1. **Un identifiant d'appareil n'authentifie rien.** Il vient du navigateur, donc il est
   falsifiable. Il n'ouvre aucun droit, ne remplace aucun jeton, n'allège aucun contrôle — il
   étiquette et il déclenche une alerte, rien de plus.
2. **Il n'est comparé qu'aux sessions de son propre utilisateur.** Sinon présenter
   l'identifiant d'autrui permettrait de savoir s'il existe, donc de sonder les appareils d'un
   autre compte (voir `AuthService._resolve_device`).

Le User-Agent est une **donnée hostile** : un client écrit ce qu'il veut, de n'importe quelle
longueur. Il est donc borné et nettoyé avant d'approcher la base, et l'étiquette qu'on en tire
n'est qu'un confort d'affichage — jamais une décision.
"""

from __future__ import annotations

import re
import secrets

# Longueur de l'identifiant émis : 32 octets d'aléa en base64url. Assez pour qu'un client ne
# puisse pas deviner celui d'un appareil déjà connu (ce qui esquiverait l'alerte).
_ID_BYTES = 32
# Borne de ce qu'on accepte d'un navigateur. La colonne tient 255 ; refuser plus tôt évite de
# promener une chaîne arbitraire dans les journaux et les comparaisons.
_ID_MAX_LEN = 128
_ID_MIN_LEN = 16
# base64url strict : rien d'autre ne peut venir de `mint()`, donc tout le reste est refusé
# plutôt que nettoyé — un identifiant « réparé » ne correspondrait à aucune session de toute façon.
_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{%d,%d}$" % (_ID_MIN_LEN, _ID_MAX_LEN))

_UA_MAX_LEN = 500
_LABEL_MAX_LEN = 120

# Systèmes, du plus spécifique au plus général : « Android » contient « Linux » dans la plupart
# des User-Agents, et « iPadOS » s'annonce souvent comme « Mac OS X ». L'ordre fait le tri.
_SYSTEMS: tuple[tuple[str, str], ...] = (
    ("android", "Android"),
    ("iphone", "iOS"),
    ("ipad", "iPadOS"),
    ("cros", "ChromeOS"),
    ("mac os x", "macOS"),
    ("macintosh", "macOS"),
    ("windows", "Windows"),
    ("linux", "Linux"),
    ("freebsd", "FreeBSD"),
)

# Navigateurs, du plus spécifique au plus général : chacun de ces moteurs se déclare aussi
# « Chrome » ou « Safari » pour la compatibilité, donc tester Chrome en premier les masquerait tous.
_BROWSERS: tuple[tuple[str, str], ...] = (
    ("edg/", "Edge"),
    ("opr/", "Opera"),
    ("vivaldi", "Vivaldi"),
    ("brave", "Brave"),
    ("samsungbrowser", "Samsung Internet"),
    ("firefox", "Firefox"),
    ("chromium", "Chromium"),
    ("chrome", "Chrome"),
    ("safari", "Safari"),
)


def mint() -> str:
    """Émet un identifiant d'appareil. Le serveur en est la seule source."""
    return secrets.token_urlsafe(_ID_BYTES)


def normalize_id(raw: object) -> str | None:
    """L'identifiant présenté par un navigateur, ou None s'il est inutilisable.

    Refuse plutôt que répare : un identifiant mal formé ne peut correspondre à aucune session
    (elles ne contiennent que des valeurs issues de `mint`), donc le « corriger » ne ferait que
    masquer un client cassé ou malveillant.
    """
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    return value if _ID_PATTERN.match(value) else None


def clean_user_agent(raw: object) -> str | None:
    """Le User-Agent, borné et débarrassé de ses caractères de contrôle, ou None s'il est vide."""
    if not isinstance(raw, str):
        return None
    # Les caractères de contrôle (dont \r\n) n'ont rien à faire dans un en-tête : s'ils
    # arrivent quand même, ils ne doivent pas se retrouver dans un journal ni dans un e-mail.
    value = "".join(char for char in raw if char.isprintable()).strip()
    return value[:_UA_MAX_LEN] or None


def label(user_agent: object) -> str | None:
    """Étiquette lisible d'un appareil (« Chrome sur macOS »), ou None si indéchiffrable.

    None est un résultat légitime : un client sans User-Agent, ou avec un User-Agent exotique,
    s'affichera « appareil inconnu » — ce qui est honnête. Deviner serait pire que se taire.
    """
    cleaned = clean_user_agent(user_agent)
    if cleaned is None:
        return None
    lowered = cleaned.lower()
    browser = next((name for needle, name in _BROWSERS if needle in lowered), None)
    system = next((name for needle, name in _SYSTEMS if needle in lowered), None)
    if browser and system:
        return f"{browser} sur {system}"[:_LABEL_MAX_LEN]
    return (browser or system or None) and (browser or system)[:_LABEL_MAX_LEN]


def system_of(user_agent: object) -> str | None:
    """Le système seul (« macOS »), pour l'afficher à part de l'étiquette complète."""
    cleaned = clean_user_agent(user_agent)
    if cleaned is None:
        return None
    lowered = cleaned.lower()
    return next((name for needle, name in _SYSTEMS if needle in lowered), None)
