"""CRM OAuth / protected-resource discovery routes (RFC 8414 + RFC 9728)."""

from __future__ import annotations

from urllib.parse import urlparse

from mcp.server.auth.handlers.metadata import MetadataHandler
from mcp.server.auth.routes import cors_middleware, create_protected_resource_routes
from mcp.shared.auth import OAuthMetadata
from pydantic import AnyHttpUrl
from starlette.routing import Route

from config import Settings
from crm_oauth_provider import CRMOAuthProvider


def build_crm_oauth_metadata(
    settings: Settings,
    *,
    dcr_enabled: bool,
    revocation_enabled: bool,
) -> OAuthMetadata:
    """Authorization server metadata with absolute CRM OAuth URLs."""
    issuer = AnyHttpUrl(settings.crm_oauth_issuer_url)
    base = str(settings.crm_oauth_base_url).rstrip("/")
    metadata = OAuthMetadata(
        issuer=issuer,
        authorization_endpoint=AnyHttpUrl(f"{base}/authorize"),
        token_endpoint=AnyHttpUrl(f"{base}/token"),
        scopes_supported=settings.crm_oauth_scopes,
        response_types_supported=["code"],
        grant_types_supported=["authorization_code", "refresh_token"],
        token_endpoint_auth_methods_supported=["none", "client_secret_post", "client_secret_basic"],
        code_challenge_methods_supported=["S256"],
    )
    if dcr_enabled:
        metadata.registration_endpoint = AnyHttpUrl(f"{base}/register")
    if revocation_enabled:
        metadata.revocation_endpoint = AnyHttpUrl(f"{base}/revoke")
        metadata.revocation_endpoint_auth_methods_supported = [
            "none",
            "client_secret_post",
            "client_secret_basic",
        ]
    return metadata


def build_crm_discovery_routes(
    settings: Settings,
    crm_auth: CRMOAuthProvider,
) -> list[Route]:
    """Root-level well-known routes for CRM (not mounted under /crm-auth)."""
    resource_url = AnyHttpUrl(
        f"{settings.public_base_url.rstrip('/')}{settings.crm_mcp_path}"
    )
    issuer_url = AnyHttpUrl(settings.crm_oauth_issuer_url)

    routes = create_protected_resource_routes(
        resource_url=resource_url,
        authorization_servers=[issuer_url],
        scopes_supported=settings.crm_oauth_scopes,
    )

    dcr_enabled = bool(
        crm_auth.client_registration_options
        and crm_auth.client_registration_options.enabled
    )
    revocation_enabled = bool(
        crm_auth.revocation_options and crm_auth.revocation_options.enabled
    )
    metadata = build_crm_oauth_metadata(
        settings,
        dcr_enabled=dcr_enabled,
        revocation_enabled=revocation_enabled,
    )
    metadata_handler = MetadataHandler(metadata)
    as_endpoint = cors_middleware(metadata_handler.handle, ["GET", "OPTIONS"])

    issuer_path = urlparse(settings.crm_oauth_issuer_url).path.rstrip("/")
    if issuer_path:
        routes.append(
            Route(
                f"/.well-known/oauth-authorization-server{issuer_path}",
                endpoint=as_endpoint,
                methods=["GET", "OPTIONS"],
            )
        )

    # Some MCP clients path-match authorization-server discovery to the MCP resource path.
    mcp_path = settings.crm_mcp_path.rstrip("/")
    if mcp_path and mcp_path != issuer_path:
        routes.append(
            Route(
                f"/.well-known/oauth-authorization-server{mcp_path}",
                endpoint=as_endpoint,
                methods=["GET", "OPTIONS"],
            )
        )

    return routes
