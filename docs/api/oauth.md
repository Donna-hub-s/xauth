# API — OAuth 2.0

XAuth supporte Google, GitHub, Discord, Microsoft. Un provider est activé uniquement si `client_id` et `client_secret` sont tous les deux présents dans les variables d'environnement.

Préfixe : `/xauth/oauth`.

---

## Configuration des providers

Dans `.env` (via la section `env:` de `plugin.yaml`) :

```bash
# Google
XAUTH_OAUTH_GOOGLE_CLIENT_ID=...
XAUTH_OAUTH_GOOGLE_CLIENT_SECRET=...

# GitHub
XAUTH_OAUTH_GITHUB_CLIENT_ID=...
XAUTH_OAUTH_GITHUB_CLIENT_SECRET=...

# Discord
XAUTH_OAUTH_DISCORD_CLIENT_ID=...
XAUTH_OAUTH_DISCORD_CLIENT_SECRET=...

# Microsoft / Azure AD
XAUTH_OAUTH_MICROSOFT_CLIENT_ID=...
XAUTH_OAUTH_MICROSOFT_CLIENT_SECRET=...
```

**Redirect URI à enregistrer chez le provider :**
```
{APP_BASE_URL}/xauth/oauth/{provider}/callback
```

Exemple : `https://api.monapp.com/xauth/oauth/google/callback`

---

## Endpoints

### GET `/providers`

Retourne la liste des providers activés.

```json
["google", "github"]
```

---

### GET `/{provider}/authorize`

Redirige le navigateur vers la page d'autorisation du provider.

```
GET /xauth/oauth/google/authorize
→ 302 Redirect → https://accounts.google.com/o/oauth2/auth?...
```

---

**Un service à la fois (Google).** `GET /oauth/google/authorize?services=gmail,drive` ne demande que l'identité et les accès de ces services (`gmail`, `calendar`, `drive` — `providers/google.py::SERVICE_SCOPES`), avec `include_granted_scopes=true` : Google renvoie l'**union** de ce qui est déjà accordé, donc relier Drive après Gmail ne retire pas Gmail. Pris en compte pour une **liaison** seulement (appelant authentifié, sans `direct`) : la connexion demande toujours tout, un appelant anonyme ne choisit pas ses accès. Un service inconnu répond **400**, jamais ignoré. Le frontend l'utilise pour les lignes Gmail, Agenda et Drive des connecteurs (`/oauth/google?link=1&services=…&next=…`, `frontend/lib/oauth-link.ts`).

**Consentement Google.** Une connexion n'envoie pas `prompt=consent` : Google ne montre l'écran de consentement (avertissement « application non vérifiée », liste des accès) qu'à la première autorisation ou quand un scope a été ajouté depuis, puis redirige seul. Le `refresh_token` n'est renvoyé qu'à ce premier consentement ; les connexions suivantes conservent celui déjà stocké. Seule la liaison depuis un compte connecté (`link=1`, bouton « reconnecter Google ») redemande le consentement, pour garantir un `refresh_token` neuf.

**Retour au navigateur.** Quand le flux échoue, le callback ne met dans l'adresse de retour qu'un **code** d'une liste fermée (`services/oauth.py`), jamais le texte de l'exception : `state_invalid` (demande expirée), `access_denied` (l'utilisateur a annulé chez le fournisseur), `account_disabled`, `provider_error` (le fournisseur ou le réseau a échoué), `provider_unknown`, et pour une liaison `already_linked`. Une connexion revient sur `/auth?error=<code>`, une liaison sur la page demandée avec `?linked=<provider>` ou `?link_error=<code>` — **y compris quand elle échoue ou est annulée** (le callback n'exige ni `code` ni `state`, pour ne jamais répondre par un 422 brut quand l'utilisateur annule). Le frontend traduit ces codes (`frontend/lib/oauth-feedback.ts`) ; le détail reste dans les logs du backend.

---

### GET `/{provider}/callback`

Callback appelé par le provider après autorisation. Crée ou connecte l'utilisateur, retourne les tokens.

Les nouveaux utilisateurs créés via OAuth sont automatiquement rattachés au tenant `default` avec le rôle `user`.

**Réponse 200 :**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "uuid...",
  "token_type": "bearer",
  "mfa_required": false
}
```

---

### POST `/{provider}/link`

Lie un compte OAuth à un compte existant (utilisateur déjà authentifié).

**Header :** `Authorization: Bearer <access_token>`

**Corps :**
```json
{
  "code": "authorization_code_from_provider",
  "redirect_uri": "https://..."
}
```

**Réponse 200 :**
```json
{
  "provider": "google",
  "provider_email": "user@gmail.com",
  "linked": true
}
```

Un email de confirmation `oauth_linked` est envoyé.

---

### DELETE `/{provider}/unlink`

Supprime le lien entre le compte et le provider OAuth.

**Header :** `Authorization: Bearer <access_token>`

**Contrainte :** impossible si le compte n'a pas de mot de passe défini et que c'est le seul provider lié (évite le blocage du compte).

---

### GET `/me/accounts`

Liste les comptes OAuth liés à l'utilisateur courant.

**Header :** `Authorization: Bearer <access_token>`

```json
[
  {
    "provider": "google",
    "provider_email": "user@gmail.com",
    "provider_user_id": "1234567890"
  }
]
```

---

## Comportement à la connexion OAuth

1. Si l'email du provider correspond à un utilisateur existant → connexion directe (ou création du lien OAuth)
2. Si l'email est inconnu → création d'un nouveau compte sans mot de passe + rattachement au tenant `default`
3. Si le provider retourne une erreur → `400 Bad Request` avec le message du provider
