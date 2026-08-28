from __future__ import annotations

import json
import time
from typing import Any, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# (max_requests, window_seconds)
DEFAULT_ROUTE_LIMITS: dict[str, tuple[int, int]] = {
    "/xauth/auth/login":       (10, 60),
    "/xauth/auth/register":    (5,  60),
    "/xauth/auth/verify-mfa":  (5,  60),
    "/xauth/password/forgot":  (3, 300),
    "/xauth/password/reset":   (5, 300),
    "/xauth/oauth":            (30,  60),
}

# Limite globale par IP sur toutes les autres routes xauth
_GLOBAL_LIMIT: tuple[int, int] = (300, 60)

_KEY_PREFIX = "xauth:rl"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware de rate limiting basé sur le cache Redis xcore.

    Stratégie : sliding-window approximée via get/set (compatible avec l'API
    cache xcore qui n'expose pas INCR/EXPIRE atomiques).

    La fenêtre se réinitialise au TTL d'origine à chaque nouvelle requête dans
    une fenêtre vide ; entre-temps le compteur est incrémenté en place.
    En cas d'indisponibilité du cache le middleware laisse passer (fail-open).
    """

    def __init__(
        self,
        app: ASGIApp,
        cache: Any,
        route_limits: dict[str, tuple[int, int]] | None = None,
        enabled: bool = True,
    ) -> None:
        super().__init__(app)
        self._cache = cache
        self._limits = route_limits or DEFAULT_ROUTE_LIMITS
        self._enabled = enabled

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _get_limit(self, path: str) -> tuple[int, int]:
        for prefix, limit in self._limits.items():
            if path.startswith(prefix):
                return limit
        return _GLOBAL_LIMIT

    async def _check(self, key: str, max_req: int, window: int) -> tuple[bool, int, int]:
        """
        Returns (is_limited, current_count, retry_after).
        """
        now = int(time.time())
        raw = await self._cache.get(key)

        if raw is None:
            data = {"count": 1, "reset_at": now + window}
            await self._cache.set(key, json.dumps(data), ttl=window)
            return False, 1, window

        data = json.loads(raw)
        reset_at: int = data["reset_at"]

        if now >= reset_at:
            data = {"count": 1, "reset_at": now + window}
            await self._cache.set(key, json.dumps(data), ttl=window)
            return False, 1, window

        data["count"] += 1
        remaining = max(1, reset_at - now)
        await self._cache.set(key, json.dumps(data), ttl=remaining)
        return data["count"] > max_req, data["count"], remaining

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self._enabled or not request.url.path.startswith("/xauth"):
            return await call_next(request)

        ip = self._get_client_ip(request)
        path = request.url.path
        max_req, window = self._get_limit(path)

        # Clé par IP + chemin normalisé (2 premiers segments après /xauth)
        segments = path.split("/")
        route_key = "/".join(segments[:4])
        key = f"{_KEY_PREFIX}:{ip}:{route_key}"

        try:
            limited, count, retry_after = await self._check(key, max_req, window)
            if limited:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please try again later."},
                    headers={"Retry-After": str(retry_after)},
                )
        except Exception:
            # Cache indisponible → fail-open
            pass

        return await call_next(request)
