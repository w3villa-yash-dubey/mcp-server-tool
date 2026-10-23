from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import AnyHttpUrl

os.environ.setdefault("FASTMCP_TEST_MODE", "true")

from config import Settings  # noqa: E402
from crm_storage import CRMStorage  # noqa: E402


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    public = "https://example.test"
    return Settings(
        public_base_url=public,
        base_url=public,
        crm_api_base_url="https://crm.kivo.ai",
        crm_oauth_base_url=f"{public}/crm-auth",
        crm_oauth_issuer_url=f"{public}/crm-auth",
        crm_mcp_path="/crm/mcp",
        crm_oauth_jwt_signing_key=secrets.token_urlsafe(48),
        crm_credential_encryption_key=Fernet.generate_key().decode(),
        crm_database_path=str(tmp_path / "crm.sqlite3"),
        crm_oauth_client_id="chatgpt-test-client",
        crm_oauth_client_secret=None,
        crm_oauth_redirect_uris=["https://chatgpt.com/connector/oauth/callback"],
        crm_access_token_ttl_seconds=3600,
        crm_refresh_token_ttl_seconds=86400,
        crm_oauth_scopes=["crm:contacts:read"],
        google_client_id="test-google-client",
        google_client_secret="test-google-secret",
    )


@pytest.fixture
def storage(test_settings: Settings) -> CRMStorage:
    fernet = Fernet(test_settings.crm_credential_encryption_key.encode())
    return CRMStorage(test_settings.crm_database_path, fernet)


@pytest.fixture
def app(test_settings: Settings, storage: CRMStorage, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", test_settings.google_client_id)
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", test_settings.google_client_secret)
    monkeypatch.setenv("BASE_URL", test_settings.base_url)

    from app_factory import create_app

    return create_app(test_settings, storage)


@pytest.fixture
def oauth_client_info():
    from mcp.shared.auth import OAuthClientInformationFull

    return OAuthClientInformationFull(
        client_id="chatgpt-test-client",
        redirect_uris=[AnyHttpUrl("https://chatgpt.com/connector/oauth/callback")],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        scope="crm:contacts:read",
    )
