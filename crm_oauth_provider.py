"""Custom OAuth authorization server for CRM MCP."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from base64 import urlsafe_b64encode
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode, urlparse

from fastmcp.server.auth.auth import ClientRegistrationOptions, OAuthProvider, RevocationOptions
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from fastmcp.server.auth.jwt_issuer import JWTIssuer
from joserfc.errors import JoseError
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from crm_client import ValidationOutcome, validate_crm_credentials
from crm_login import render_login_page
from crm_storage import CRMStorage, PendingAuthorization, StoredAuthCode

if TYPE_CHECKING:
    from config import Settings

AUTH_CODE_TTL_SECONDS = 5 * 60
PENDING_TTL_SECONDS = 10 * 60
LOGIN_PATH = "/login"


class CRMOAuthProvider(OAuthProvider):
    def __init__(
        self,
        *,
        settings: Settings,
        storage: CRMStorage,
        crm_api_base_url: str,
    ) -> None:
        self._settings = settings
        self._storage = storage
        self._crm_api_base_url = crm_api_base_url
        self._jwt_signing_key = derive_jwt_key(
            high_entropy_material=settings.crm_oauth_jwt_signing_key,
            salt="crm-oauth-jwt",
        )
        self._jwt_issuer: JWTIssuer | None = None
        self._csrf_secret = settings.crm_oauth_jwt_signing_key.encode("utf-8")
        parsed_oauth = urlparse(settings.crm_oauth_base_url)
        self._oauth_mount_path = parsed_oauth.path.rstrip("/") or ""

        super().__init__(
            base_url=settings.crm_oauth_base_url,
            resource_base_url=settings.public_base_url,
            issuer_url=settings.crm_oauth_issuer_url,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=settings.crm_oauth_scopes,
                default_scopes=settings.crm_oauth_scopes,
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=settings.crm_oauth_scopes,
        )
        self._bootstrap_clients()

    def _bootstrap_clients(self) -> None:
        if not self._settings.crm_oauth_client_id:
            return
        redirect_uris = [
            AnyHttpUrl(u) for u in self._settings.crm_oauth_redirect_uris
        ] or None
        auth_method = (
            "client_secret_post"
            if self._settings.crm_oauth_client_secret
            else "none"
        )
        client = OAuthClientInformationFull(
            client_id=self._settings.crm_oauth_client_id,
            client_secret=self._settings.crm_oauth_client_secret,
            redirect_uris=redirect_uris,
            token_endpoint_auth_method=auth_method,
            grant_types=["authorization_code", "refresh_token"],
            scope=" ".join(self._settings.crm_oauth_scopes),
        )
        self._storage.save_client(client)

    def set_mcp_path(self, mcp_path: str | None) -> None:
        super().set_mcp_path(mcp_path)
        assert self.issuer_url is not None
        assert self._resource_url is not None
        issuer = str(self.issuer_url).rstrip("/")
        audience = str(self._resource_url).rstrip("/")
        self._jwt_issuer = JWTIssuer(
            issuer=issuer,
            audience=audience,
            signing_key=self._jwt_signing_key,
        )

    @property
    def jwt_issuer(self) -> JWTIssuer:
        if self._jwt_issuer is None:
            raise RuntimeError("JWT issuer not initialized")
        return self._jwt_issuer

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._storage.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if (
            client_info.scope is not None
            and self.client_registration_options
            and self.client_registration_options.valid_scopes
        ):
            requested = set(client_info.scope.split())
            valid = set(self.client_registration_options.valid_scopes)
            invalid = requested - valid
            if invalid:
                raise ValueError(
                    f"Requested scopes are not valid: {', '.join(sorted(invalid))}"
                )
        if client_info.client_id is None:
            raise ValueError("client_id is required")
        self._storage.save_client(client_info)

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        if client.client_id is None:
            raise AuthorizeError(error="invalid_client", error_description="Missing client ID")
        pending_id = secrets.token_urlsafe(24)
        self._storage.create_pending(
            PendingAuthorization(
                id=pending_id,
                client_id=client.client_id,
                redirect_uri=str(params.redirect_uri),
                redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                state=params.state,
                scopes=params.scopes or self._settings.crm_oauth_scopes,
                code_challenge=params.code_challenge,
                resource=params.resource,
                expires_at=time.time() + PENDING_TTL_SECONDS,
            )
        )
        query = urlencode({"txn_id": pending_id})
        return f"{self._oauth_mount_path}{LOGIN_PATH}?{query}"

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        if client.client_id is None:
            return None
        stored = self._storage.get_auth_code(authorization_code, client.client_id)
        if stored is None:
            return None
        return AuthorizationCode(
            code=stored.code,
            client_id=stored.client_id,
            redirect_uri=AnyHttpUrl(stored.redirect_uri),
            redirect_uri_provided_explicitly=stored.redirect_uri_provided_explicitly,
            scopes=stored.scopes,
            expires_at=stored.expires_at,
            code_challenge=stored.code_challenge,
            resource=stored.resource,
            subject=stored.connection_id,
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        if authorization_code.subject is None:
            raise TokenError("invalid_grant", "Authorization code is missing a connection")
        connection = self._storage.get_connection(authorization_code.subject)
        if connection is None or connection.revoked:
            raise TokenError("invalid_grant", "CRM connection is no longer valid")

        if client.client_id is None:
            raise TokenError("invalid_client", "Missing client ID")

        access_jti = secrets.token_urlsafe(24)
        refresh_jti = secrets.token_urlsafe(24)
        access_expires = self._settings.crm_access_token_ttl_seconds
        refresh_expires = self._settings.crm_refresh_token_ttl_seconds

        access_token = self.jwt_issuer.issue_access_token(
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            jti=access_jti,
            expires_in=access_expires,
            subject=authorization_code.subject,
        )
        refresh_token = self.jwt_issuer.issue_refresh_token(
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            jti=refresh_jti,
            expires_in=refresh_expires,
        )
        self._storage.save_refresh_token(
            jti=refresh_jti,
            connection_id=authorization_code.subject,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource,
            expires_at=time.time() + refresh_expires,
        )
        self._storage.mark_auth_code_used(authorization_code.code)

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=access_expires,
            refresh_token=refresh_token,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        try:
            payload = self.jwt_issuer.verify_token(refresh_token, expected_token_use="refresh")
        except JoseError:
            return None
        if client.client_id is None or payload.get("client_id") != client.client_id:
            return None
        jti = payload.get("jti")
        if not isinstance(jti, str):
            return None
        record = self._storage.get_refresh_token(jti)
        if record is None:
            return None
        scopes = record["scopes"]
        return RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=int(record["expires_at"]),
            resource=record.get("resource"),
            subject=record["connection_id"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        original = set(refresh_token.scopes)
        requested = set(scopes)
        if not requested.issubset(original):
            raise TokenError(
                "invalid_scope",
                "Requested scopes exceed those authorized by the refresh token.",
            )
        if refresh_token.subject is None:
            raise TokenError("invalid_grant", "Refresh token is missing a connection")
        connection = self._storage.get_connection(refresh_token.subject)
        if connection is None or connection.revoked:
            raise TokenError("invalid_grant", "CRM connection is no longer valid")

        try:
            old_payload = self.jwt_issuer.verify_token(
                refresh_token.token, expected_token_use="refresh"
            )
        except JoseError as exc:
            raise TokenError("invalid_grant", "Refresh token is invalid") from exc
        old_jti = old_payload.get("jti")
        if isinstance(old_jti, str):
            self._storage.delete_refresh_token(old_jti)

        if client.client_id is None:
            raise TokenError("invalid_client", "Missing client ID")

        access_jti = secrets.token_urlsafe(24)
        refresh_jti = secrets.token_urlsafe(24)
        access_expires = self._settings.crm_access_token_ttl_seconds
        refresh_expires = self._settings.crm_refresh_token_ttl_seconds

        access_token = self.jwt_issuer.issue_access_token(
            client_id=client.client_id,
            scopes=scopes,
            jti=access_jti,
            expires_in=access_expires,
            subject=refresh_token.subject,
        )
        new_refresh = self.jwt_issuer.issue_refresh_token(
            client_id=client.client_id,
            scopes=scopes,
            jti=refresh_jti,
            expires_in=refresh_expires,
        )
        self._storage.save_refresh_token(
            jti=refresh_jti,
            connection_id=refresh_token.subject,
            client_id=client.client_id,
            scopes=scopes,
            resource=refresh_token.resource,
            expires_at=time.time() + refresh_expires,
        )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=access_expires,
            refresh_token=new_refresh,
            scope=" ".join(scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        try:
            payload = self.jwt_issuer.verify_token(token, expected_token_use="access")
        except JoseError:
            return None
        client_id = payload.get("client_id")
        if not isinstance(client_id, str):
            return None
        subject = payload.get("sub")
        if not isinstance(subject, str):
            return None
        connection = self._storage.get_connection(subject)
        if connection is None or connection.revoked:
            return None
        scope_str = payload.get("scope", "")
        scopes = scope_str.split() if scope_str else self._settings.crm_oauth_scopes
        exp = payload.get("exp")
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=int(exp) if exp is not None else None,
            resource=str(self._resource_url) if self._resource_url else None,
            subject=subject,
            claims=dict(payload),
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, RefreshToken):
            try:
                payload = self.jwt_issuer.verify_token(
                    token.token, expected_token_use="refresh"
                )
            except JoseError:
                return
            jti = payload.get("jti")
            if isinstance(jti, str):
                self._storage.delete_refresh_token(jti)
        if token.subject:
            self._storage.revoke_connection(token.subject)

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        """Operational OAuth routes only; well-known discovery is registered at app root."""
        routes = super().get_routes(mcp_path)
        operational: list[Route] = []
        for route in routes:
            if isinstance(route, Route) and route.path.startswith(
                "/.well-known/oauth-authorization-server"
            ):
                continue
            operational.append(route)
        operational.extend(
            [
                Route(LOGIN_PATH, endpoint=self._handle_login_get, methods=["GET"]),
                Route(LOGIN_PATH, endpoint=self._handle_login_post, methods=["POST"]),
            ]
        )
        return operational

    def get_well_known_routes(self, mcp_path: str | None = None) -> list[Route]:
        """Discovery is assembled in app_factory / crm_discovery (root-level routes)."""
        return []

    def _login_csrf_cookie_name(self, request: Request) -> str:
        return "crm_login_csrf"

    def _sign_txn(self, txn_id: str) -> str:
        digest = hmac.new(self._csrf_secret, txn_id.encode(), hashlib.sha256).hexdigest()
        return digest

    def _verify_txn(self, txn_id: str, signature: str | None) -> bool:
        if not signature:
            return False
        expected = self._sign_txn(txn_id)
        return hmac.compare_digest(expected, signature)

    async def _handle_login_get(self, request: Request) -> Response:
        txn_id = request.query_params.get("txn_id", "").strip()
        if not txn_id or self._storage.get_pending(txn_id) is None:
            return HTMLResponse(
                "This login link is invalid or has expired. Start connection from ChatGPT again.",
                status_code=400,
            )
        form_action = f"{self._oauth_mount_path}{LOGIN_PATH}"
        response = HTMLResponse(render_login_page(txn_id=txn_id, form_action=form_action))
        response.set_cookie(
            self._login_csrf_cookie_name(request),
            self._sign_txn(txn_id),
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="lax",
            max_age=PENDING_TTL_SECONDS,
            path=self._oauth_mount_path or "/",
        )
        return response

    async def _handle_login_post(self, request: Request) -> Response:
        form = await request.form()
        txn_id = str(form.get("txn_id", "")).strip()
        company_id = str(form.get("company_id", "")).strip()
        api_token = str(form.get("crm_api_token", "")).strip()
        csrf_cookie = request.cookies.get(self._login_csrf_cookie_name(request))

        if not txn_id or not self._verify_txn(txn_id, csrf_cookie):
            return HTMLResponse("Invalid login session.", status_code=400)

        pending = self._storage.get_pending(txn_id)
        if pending is None:
            return HTMLResponse(
                "This authorization session expired. Start again from ChatGPT.",
                status_code=400,
            )

        if not company_id or not api_token:
            return HTMLResponse(
                render_login_page(
                    txn_id=txn_id,
                    form_action=f"{self._oauth_mount_path}{LOGIN_PATH}",
                    error_message="Both fields are required.",
                ),
                status_code=400,
            )

        validation = await validate_crm_credentials(
            base_url=self._crm_api_base_url,
            company_id=company_id,
            api_token=api_token,
        )
        if validation.outcome is not ValidationOutcome.OK:
            return HTMLResponse(
                render_login_page(
                    txn_id=txn_id,
                    form_action=f"{self._oauth_mount_path}{LOGIN_PATH}",
                    error_message="Could not verify your CRM credentials. Check the Company ID and token.",
                ),
                status_code=401,
            )

        connection = self._storage.create_connection(company_id, api_token)
        code = secrets.token_urlsafe(32)
        self._storage.create_auth_code(
            StoredAuthCode(
                code=code,
                connection_id=connection.id,
                client_id=pending.client_id,
                redirect_uri=pending.redirect_uri,
                redirect_uri_provided_explicitly=pending.redirect_uri_provided_explicitly,
                scopes=pending.scopes,
                code_challenge=pending.code_challenge,
                resource=pending.resource,
                expires_at=time.time() + AUTH_CODE_TTL_SECONDS,
                used=False,
            )
        )
        self._storage.delete_pending(txn_id)

        redirect_url = construct_redirect_uri(
            pending.redirect_uri,
            code=code,
            state=pending.state,
        )
        response = RedirectResponse(url=redirect_url, status_code=302)
        response.delete_cookie(
            self._login_csrf_cookie_name(request),
            path=self._oauth_mount_path or "/",
        )
        return response
