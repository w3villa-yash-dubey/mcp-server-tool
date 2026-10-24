"""Path-aware authentication for Weather + CRM on one Starlette app."""

from __future__ import annotations

from starlette.authentication import AuthCredentials, AuthenticationBackend
from starlette.requests import HTTPConnection

from crm_oauth_provider import CRMOAuthProvider
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser


class PathAwareAuthBackend(AuthenticationBackend):
    """Select the OAuth provider used to verify Bearer tokens by URL path."""

    def __init__(
        self,
        *,
        weather_auth,
        crm_auth: CRMOAuthProvider,
        crm_mcp_path: str,
    ) -> None:
        self._weather_auth = weather_auth
        self._crm_auth = crm_auth
        self._crm_mcp_path = crm_mcp_path.rstrip("/") or "/crm/mcp"

    async def authenticate(self, conn: HTTPConnection):
        path = conn.url.path.rstrip("/") or "/"
        verifier = self._crm_auth if path == self._crm_mcp_path else self._weather_auth
        token = self._extract_bearer(conn)
        if not token:
            return None
        auth_info = await verifier.verify_token(token)
        if not auth_info:
            return None
        return AuthCredentials(auth_info.scopes), AuthenticatedUser(auth_info)

    @staticmethod
    def _extract_bearer(conn: HTTPConnection) -> str:
        header = conn.headers.get("authorization") or ""
        if header.lower().startswith("bearer "):
            return header[7:].strip()
        return ""
