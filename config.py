"""Shared environment configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.fernet import Fernet

_PLACEHOLDER_MARKERS = (
    "paste_generated",
    "replace-with",
    "replace_with",
    "your-",
    "changeme",
)


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _reject_placeholder(name: str, value: str) -> None:
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        raise RuntimeError(
            f"{name} is still a placeholder. Generate a real value and set it in .env "
            f"(see .env.example)."
        )


def _validate_crm_secrets(jwt_signing_key: str, credential_encryption_key: str) -> None:
    _reject_placeholder("CRM_OAUTH_JWT_SIGNING_KEY", jwt_signing_key)
    if len(jwt_signing_key) < 32:
        raise RuntimeError(
            "CRM_OAUTH_JWT_SIGNING_KEY is too short. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )

    _reject_placeholder("CRM_CREDENTIAL_ENCRYPTION_KEY", credential_encryption_key)
    try:
        Fernet(credential_encryption_key.encode("utf-8"))
    except ValueError as exc:
        raise RuntimeError(
            "CRM_CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key (44 url-safe base64 chars). "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        ) from exc


def _optional(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


def _absolute_url(public_base_url: str, url_or_path: str) -> str:
    """Resolve a configured URL or path against the public base URL."""
    value = url_or_path.strip()
    if not value:
        return public_base_url.rstrip("/")
    if value.startswith("http://") or value.startswith("https://"):
        return value.rstrip("/")
    return f"{public_base_url.rstrip('/')}/{value.lstrip('/')}".rstrip("/")


@dataclass(frozen=True)
class Settings:
    public_base_url: str
    base_url: str
    crm_api_base_url: str
    crm_oauth_base_url: str
    crm_oauth_issuer_url: str
    crm_mcp_path: str
    crm_oauth_jwt_signing_key: str
    crm_credential_encryption_key: str
    crm_database_path: str
    crm_oauth_client_id: str | None
    crm_oauth_client_secret: str | None
    crm_oauth_redirect_uris: list[str]
    crm_access_token_ttl_seconds: int
    crm_refresh_token_ttl_seconds: int
    crm_oauth_scopes: list[str]
    google_client_id: str
    google_client_secret: str


def load_settings() -> Settings:
    public_base_url = _optional("PUBLIC_BASE_URL", _optional("BASE_URL", "")).rstrip("/")
    if not public_base_url:
        raise RuntimeError("Set PUBLIC_BASE_URL or BASE_URL")

    base_url = _optional("BASE_URL", public_base_url).rstrip("/")
    crm_oauth_base = _absolute_url(
        public_base_url,
        _optional("CRM_OAUTH_BASE_URL", "/crm-auth"),
    )
    crm_issuer = _absolute_url(
        public_base_url,
        _optional("CRM_OAUTH_ISSUER_URL", crm_oauth_base),
    )
    if crm_issuer.rstrip("/").endswith("/crm/mcp"):
        raise RuntimeError("CRM_OAUTH_ISSUER_URL must not be the CRM MCP endpoint")

    redirect_raw = _optional("CRM_OAUTH_REDIRECT_URIS", "")
    redirect_uris = [u.strip() for u in redirect_raw.split(",") if u.strip()]

    scopes_raw = _optional("CRM_OAUTH_SCOPES", "crm:contacts:read")
    scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()]

    jwt_signing_key = _require("CRM_OAUTH_JWT_SIGNING_KEY")
    credential_encryption_key = _require("CRM_CREDENTIAL_ENCRYPTION_KEY")
    _validate_crm_secrets(jwt_signing_key, credential_encryption_key)

    return Settings(
        public_base_url=public_base_url,
        base_url=base_url,
        crm_api_base_url=_optional("CRM_API_BASE_URL", "https://crm.kivo.ai").rstrip("/"),
        crm_oauth_base_url=crm_oauth_base,
        crm_oauth_issuer_url=crm_issuer,
        crm_mcp_path=_optional("CRM_MCP_PATH", "/crm/mcp"),
        crm_oauth_jwt_signing_key=jwt_signing_key,
        crm_credential_encryption_key=credential_encryption_key,
        crm_database_path=_optional("CRM_DATABASE_PATH", "crm_data.sqlite3"),
        crm_oauth_client_id=os.environ.get("CRM_OAUTH_CLIENT_ID", "").strip() or None,
        crm_oauth_client_secret=os.environ.get("CRM_OAUTH_CLIENT_SECRET", "").strip() or None,
        crm_oauth_redirect_uris=redirect_uris,
        crm_access_token_ttl_seconds=int(_optional("CRM_ACCESS_TOKEN_TTL_SECONDS", "3600")),
        crm_refresh_token_ttl_seconds=int(_optional("CRM_REFRESH_TOKEN_TTL_SECONDS", "2592000")),
        crm_oauth_scopes=scopes,
        google_client_id=_require("GOOGLE_CLIENT_ID"),
        google_client_secret=_require("GOOGLE_CLIENT_SECRET"),
    )
