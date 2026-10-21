# xauth

Authentification et autorisation multi-espaces.

Multi-tenant, RBAC, journal d'audit, invitations par lien, MFA TOTP, JWT RS256, OAuth (Google, GitHub, Discord, Microsoft).

## Place dans DONNA

Ce dépôt est un composant de [DONNA](https://github.com/Donna-hub-s), assistante augmentée
bâtie sur le framework de plugins **xcore**. Il est monté comme sous-module à
`backend/app/xauth/` dans le dépôt applicatif, et n'est pas prévu pour tourner seul :
xcore le charge, lui injecte ses services et lit son `plugin.yaml`.

Les modules partagés avec les autres composants vivent dans
[donna-commons](https://github.com/Donna-hub-s/donna-commons).

## Historique

Extrait du monorepo avec `git filter-repo` : l'historique des fichiers de ce composant
est conservé, celui des autres composants ne l'est pas.

## Licence

MIT — voir [LICENSE](LICENSE).
