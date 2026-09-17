from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)


_TEMPLATES_DIR = Path(__file__).parent.parent.parent.parent / "data" / "templates"


def _render(template_name: str, context: dict) -> str:
    """Render a Jinja2 HTML template from data/templates/."""
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as e:
        raise RuntimeError("jinja2 is required. Install with: uv add jinja2") from e

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    tpl = env.get_template(f"{template_name}.html")
    return tpl.render(**context)


class EmailTransport:
    """
    Wrapper autour de l'extension email Xcore.
    Les templates HTML sont rendus localement via Jinja2 (data/templates/)
    avant d'être transmis au transport xcore.
    """

    def __init__(self, email_ext: Any, app_base_url: str, app_name: str, web_app_url: str | None = None) -> None:
        self._ext = email_ext
        self.base_url = app_base_url.rstrip("/")
        # Liens destinés à l'utilisateur (connexion, nouveau mot de passe) : pages du frontend.
        self.web_url = (web_app_url or app_base_url).rstrip("/")
        self.app_name = app_name

    async def send(
        self,
        to: str,
        subject: str,
        template: str,
        context: dict,
    ) -> bool:
        # Un email qui ne part pas (extension absente, SMTP injoignable, template manquant)
        # ne doit jamais faire échouer l'action qui l'a déclenché (inscription, oubli…).
        if self._ext is None:
            _logger.warning("[xauth] email « %s » non envoyé : extension email indisponible", template)
            return False
        try:
            html = _render(template, self._with_defaults(context))
            return await self._ext.send(to=to, subject=subject, body=html, is_html=True)
        except Exception:
            _logger.exception("[xauth] échec de l'envoi de l'email « %s »", template)
            return False

    def queue(self, to: str, subject: str, body: str, is_html: bool = True) -> bool:
        """Fire-and-forget — non bloquant."""
        if self._ext is None:
            _logger.warning("[xauth] email « %s » non envoyé : extension email indisponible", subject)
            return False
        try:
            return self._ext.queue(to=to, subject=subject, body=body, is_html=is_html)
        except Exception:
            _logger.exception("[xauth] échec de la mise en file de l'email « %s »", subject)
            return False

    def queue_template(self, to: str, subject: str, template: str, context: dict) -> bool:
        """Fire-and-forget avec rendu Jinja2 local."""
        if self._ext is None:
            _logger.warning("[xauth] email « %s » non envoyé : extension email indisponible", template)
            return False
        try:
            html = _render(template, self._with_defaults(context))
            return self._ext.queue(to=to, subject=subject, body=html, is_html=True)
        except Exception:
            _logger.exception("[xauth] échec de la mise en file de l'email « %s »", template)
            return False

    def _with_defaults(self, context: dict) -> dict:
        context.setdefault("app_name", self.app_name)
        context.setdefault("base_url", self.base_url)
        context.setdefault("support_url", f"{self.base_url}/support")
        return context
