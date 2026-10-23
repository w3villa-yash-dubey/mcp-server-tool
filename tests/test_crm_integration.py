from __future__ import annotations

import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from fastmcp.utilities.tests import run_asgi_lifespan
from starlette.testclient import TestClient


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")
    return verifier, challenge


def test_weather_mcp_still_requires_auth(app):
    with TestClient(app) as client:
        response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert response.status_code == 401


def test_weather_oauth_metadata_unchanged(app, test_settings):
    with TestClient(app) as client:
        response = client.get("/.well-known/oauth-authorization-server")
        assert response.status_code == 200
        data = response.json()
        assert data["issuer"].rstrip("/") == test_settings.base_url.rstrip("/")


def test_crm_authorization_metadata_json(app, test_settings):
    public = test_settings.public_base_url.rstrip("/")
    expected_auth = f"{public}/crm-auth/authorize"
    expected_token = f"{public}/crm-auth/token"
    expected_register = f"{public}/crm-auth/register"

    with TestClient(app) as client:
        for path in (
            "/.well-known/oauth-authorization-server/crm-auth",
            "/.well-known/oauth-authorization-server/crm/mcp",
        ):
            response = client.get(path)
            assert response.status_code == 200
            data = response.json()
            assert data["issuer"] == test_settings.crm_oauth_issuer_url
            assert data["authorization_endpoint"] == expected_auth
            assert data["token_endpoint"] == expected_token
            assert data["registration_endpoint"] == expected_register
            assert data["authorization_endpoint"].startswith("https://")
            assert data["token_endpoint"].startswith("https://")
            assert "S256" in data.get("code_challenge_methods_supported", [])
            assert "none" in data.get("token_endpoint_auth_methods_supported", [])


def test_crm_protected_resource_metadata(app, test_settings):
    public = test_settings.public_base_url.rstrip("/")
    with TestClient(app) as client:
        response = client.get("/.well-known/oauth-protected-resource/crm/mcp")
        assert response.status_code == 200
        data = response.json()
        assert data["resource"] == f"{public}/crm/mcp"
        assert data["authorization_servers"] == [test_settings.crm_oauth_issuer_url]
        assert data["authorization_servers"] != [data["resource"]]

        challenge = client.post("/crm/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert challenge.status_code == 401
        www = challenge.headers.get("www-authenticate", "")
        assert f"{public}/.well-known/oauth-protected-resource/crm/mcp" in www


def test_crm_oauth_routes_not_under_mcp_mount(app):
    with TestClient(app) as client:
        assert client.get("/crm/mcp/authorize").status_code == 404
        assert client.get("/crm-auth/authorize", params={"response_type": "code"}).status_code != 404


def test_crm_login_form_fields(app, storage, oauth_client_info):
    storage.save_client(oauth_client_info)
    verifier, challenge = _pkce_pair()
    with TestClient(app) as client:
        auth = client.get(
            "/crm-auth/authorize",
            params={
                "response_type": "code",
                "client_id": oauth_client_info.client_id,
                "redirect_uri": "https://chatgpt.com/connector/oauth/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "crm:contacts:read",
                "resource": "https://example.test/crm/mcp",
            },
            follow_redirects=False,
        )
        assert auth.status_code == 302
        login_url = auth.headers["location"]
        assert "/crm-auth/login" in login_url
        login = client.get(login_url)
        assert login.status_code == 200
        body = login.text
        assert "Connect Your CRM Account" in body
        assert 'name="company_id"' in body
        assert 'name="crm_api_token"' in body
        assert 'type="password"' in body
        assert body.count("<input") == 3


@respx.mock
def test_valid_crm_credentials_continue_oauth(app, storage, oauth_client_info, test_settings):
    storage.save_client(oauth_client_info)
    respx.get(re.compile(r"/api/v1/accounts/.+/contacts/search")).mock(
        return_value=httpx.Response(200, json={"payload": []})
    )
    verifier, challenge = _pkce_pair()
    with TestClient(app) as client:
        auth = client.get(
            "/crm-auth/authorize",
            params={
                "response_type": "code",
                "client_id": oauth_client_info.client_id,
                "redirect_uri": "https://chatgpt.com/connector/oauth/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "crm:contacts:read",
                "resource": test_settings.public_base_url + test_settings.crm_mcp_path,
            },
            follow_redirects=False,
        )
        login_url = auth.headers["location"]
        login_page = client.get(login_url)
        txn_id = parse_qs(urlparse(login_url).query)["txn_id"][0]
        post = client.post(
            "/crm-auth/login",
            data={
                "txn_id": txn_id,
                "company_id": "42",
                "crm_api_token": "secret-crm-token",
            },
            follow_redirects=False,
        )
        assert post.status_code == 302
        redirect = post.headers["location"]
        assert redirect.startswith("https://chatgpt.com/connector/oauth/callback")
        assert "code=" in redirect
        assert "secret-crm-token" not in redirect
        assert "secret-crm-token" not in login_page.text


@respx.mock
def test_invalid_crm_credentials_rejected(app, storage, oauth_client_info):
    storage.save_client(oauth_client_info)
    respx.get(re.compile(r"/api/v1/accounts/.+/contacts/search")).mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    _, challenge = _pkce_pair()
    with TestClient(app) as client:
        auth = client.get(
            "/crm-auth/authorize",
            params={
                "response_type": "code",
                "client_id": oauth_client_info.client_id,
                "redirect_uri": "https://chatgpt.com/connector/oauth/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        login_url = auth.headers["location"]
        client.get(login_url)
        txn_id = parse_qs(urlparse(login_url).query)["txn_id"][0]
        post = client.post(
            "/crm-auth/login",
            data={"txn_id": txn_id, "company_id": "42", "crm_api_token": "bad"},
        )
        assert post.status_code == 401
        assert "secret" not in post.text.lower()


@respx.mock
@pytest.mark.parametrize(
    "status,expected_snippet",
    [
        (429, "rate limit"),
        (503, "temporarily"),
    ],
)
def test_crm_validation_error_handling(app, storage, oauth_client_info, status, expected_snippet):
    storage.save_client(oauth_client_info)
    respx.get(re.compile(r"/api/v1/accounts/.+/contacts/search")).mock(
        return_value=httpx.Response(status, json={"error": "x"})
    )
    _, challenge = _pkce_pair()
    with TestClient(app) as client:
        auth = client.get(
            "/crm-auth/authorize",
            params={
                "response_type": "code",
                "client_id": oauth_client_info.client_id,
                "redirect_uri": "https://chatgpt.com/connector/oauth/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        login_url = auth.headers["location"]
        client.get(login_url)
        txn_id = parse_qs(urlparse(login_url).query)["txn_id"][0]
        post = client.post(
            "/crm-auth/login",
            data={"txn_id": txn_id, "company_id": "42", "crm_api_token": "tok"},
        )
        assert post.status_code == 401


def test_invalid_redirect_uri_rejected(app, storage, oauth_client_info):
    storage.save_client(oauth_client_info)
    _, challenge = _pkce_pair()
    with TestClient(app) as client:
        response = client.get(
            "/crm-auth/authorize",
            params={
                "response_type": "code",
                "client_id": oauth_client_info.client_id,
                "redirect_uri": "https://evil.example/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert response.status_code == 400


@respx.mock
def test_pkce_and_token_validation(app, storage, oauth_client_info, test_settings):
    storage.save_client(oauth_client_info)
    respx.get(re.compile(r"/api/v1/accounts/.+/contacts/search")).mock(
        return_value=httpx.Response(200, json={"payload": []})
    )
    verifier, challenge = _pkce_pair()
    resource = test_settings.public_base_url + test_settings.crm_mcp_path

    with TestClient(app) as client:
        auth = client.get(
            "/crm-auth/authorize",
            params={
                "response_type": "code",
                "client_id": oauth_client_info.client_id,
                "redirect_uri": "https://chatgpt.com/connector/oauth/callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": resource,
            },
            follow_redirects=False,
        )
        login_url = auth.headers["location"]
        client.get(login_url)
        txn_id = parse_qs(urlparse(login_url).query)["txn_id"][0]
        post = client.post(
            "/crm-auth/login",
            data={"txn_id": txn_id, "company_id": "7", "crm_api_token": "tok"},
            follow_redirects=False,
        )
        redirect = post.headers["location"]
        code = parse_qs(urlparse(redirect).query)["code"][0]

        bad_pkce = client.post(
            "/crm-auth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://chatgpt.com/connector/oauth/callback",
                "client_id": oauth_client_info.client_id,
                "code_verifier": "wrong-verifier",
                "resource": resource,
            },
        )
        assert bad_pkce.status_code == 401

        token_response = client.post(
            "/crm-auth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://chatgpt.com/connector/oauth/callback",
                "client_id": oauth_client_info.client_id,
                "code_verifier": verifier,
                "resource": resource,
            },
        )
        assert token_response.status_code == 200
        access_token = token_response.json()["access_token"]
        assert "tok" not in access_token

        reuse = client.post(
            "/crm-auth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://chatgpt.com/connector/oauth/callback",
                "client_id": oauth_client_info.client_id,
                "code_verifier": verifier,
                "resource": resource,
            },
        )
        assert reuse.status_code == 401

        missing = client.post(
            "/crm/mcp",
            headers={"Authorization": "Bearer invalid-token"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert missing.status_code == 401


@respx.mock
@pytest.mark.asyncio
async def test_connection_isolation_and_tool_search(app, storage, oauth_client_info, test_settings):
    storage.save_client(oauth_client_info)
    respx.get(re.compile(r"/api/v1/accounts/100/contacts/search")).mock(
        return_value=httpx.Response(200, json={"payload": [{"id": 1}]})
    )
    respx.get(re.compile(r"/api/v1/accounts/200/contacts/search")).mock(
        return_value=httpx.Response(200, json={"payload": [{"id": 2}]})
    )

    conn_a = storage.create_connection("100", "token-a")
    conn_b = storage.create_connection("200", "token-b")
    assert conn_a.company_id != conn_b.company_id

    from crm_oauth_provider import CRMOAuthProvider
    from crm_storage import CRMStorage
    from fastmcp.utilities.tests import asgi_client
    from cryptography.fernet import Fernet

    settings = test_settings
    fernet = Fernet(settings.crm_credential_encryption_key.encode())
    local_storage = CRMStorage(settings.crm_database_path, fernet)
    provider = CRMOAuthProvider(
        settings=settings, storage=local_storage, crm_api_base_url=settings.crm_api_base_url
    )
    provider.set_mcp_path(settings.crm_mcp_path)
    token_a = provider.jwt_issuer.issue_access_token(
        client_id=oauth_client_info.client_id,
        scopes=settings.crm_oauth_scopes,
        jti=secrets.token_urlsafe(8),
        expires_in=3600,
        subject=conn_a.id,
    )
    token_b = provider.jwt_issuer.issue_access_token(
        client_id=oauth_client_info.client_id,
        scopes=settings.crm_oauth_scopes,
        jti=secrets.token_urlsafe(8),
        expires_in=3600,
        subject=conn_b.id,
    )

    from crm_mcp import build_crm_mcp

    crm_server = build_crm_mcp(
        provider,
        crm_api_base_url=settings.crm_api_base_url,
        storage=local_storage,
    )

    async with asgi_client(crm_server, path=settings.crm_mcp_path, headers={"Authorization": f"Bearer {token_b}"}) as client:
        result = await client.call_tool("search_contacts", {"query": "ada", "page": 1})
        assert "token-a" not in str(result.data)
        assert "token-b" not in str(result.data)
        assert result.data is not None


def test_app_starts(create_app_smoke):
    assert create_app_smoke is not None


@pytest.fixture
def create_app_smoke(test_settings, storage, monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", test_settings.google_client_id)
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", test_settings.google_client_secret)
    monkeypatch.setenv("BASE_URL", test_settings.base_url)
    from app_factory import create_app

    return create_app(test_settings, storage)
