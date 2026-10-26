"""HTTP client for the Kivo CRM API."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx

DEFAULT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
VALIDATION_QUERY = "connection-check"


class ValidationOutcome(str, Enum):
    OK = "ok"
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_NOT_FOUND = "account_not_found"
    RATE_LIMITED = "rate_limited"
    TEMPORARY_FAILURE = "temporary_failure"


@dataclass(frozen=True)
class ValidationResult:
    outcome: ValidationOutcome
    message: str


def _account_url(base_url: str, company_id: str, path: str) -> str:
    return f"{base_url}/api/v1/accounts/{company_id}/{path}"


def _contacts_search_url(base_url: str, company_id: str) -> str:
    return _account_url(base_url, company_id, "contacts/search")


def _contacts_filter_url(base_url: str, company_id: str) -> str:
    return _account_url(base_url, company_id, "contacts/filter")


def _boards_url(base_url: str, company_id: str) -> str:
    return _account_url(base_url, company_id, "boards")


def _agents_url(base_url: str, company_id: str) -> str:
    return _account_url(base_url, company_id, "agents")


def _auth_headers(api_token: str) -> dict[str, str]:
    return {
        "api_access_token": api_token,
        "Content-Type": "application/json",
    }


async def validate_crm_credentials(
    *,
    base_url: str,
    company_id: str,
    api_token: str,
    client: httpx.AsyncClient | None = None,
) -> ValidationResult:
    """Validate company ID and CRM token via contacts search (POC)."""
    url = _contacts_search_url(base_url, company_id.strip())
    headers = {
        "api_access_token": api_token.strip(),
        "Content-Type": "application/json",
    }
    params = {
        "include_contact_inboxes": "false",
        "page": "1",
        "sort": "-created_at",
        "q": VALIDATION_QUERY,
    }

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
    try:
        response = await http.get(url, headers=headers, params=params)
    except httpx.TimeoutException:
        return ValidationResult(
            ValidationOutcome.TEMPORARY_FAILURE,
            "CRM validation timed out. Try again shortly.",
        )
    except httpx.HTTPError:
        return ValidationResult(
            ValidationOutcome.TEMPORARY_FAILURE,
            "Could not reach the CRM service. Try again shortly.",
        )
    finally:
        if owns_client:
            await http.aclose()

    if response.status_code == 200:
        return ValidationResult(ValidationOutcome.OK, "Credentials accepted.")
    if response.status_code in (401, 403):
        return ValidationResult(
            ValidationOutcome.INVALID_CREDENTIALS,
            "Company ID or CRM API token is incorrect.",
        )
    if response.status_code == 404:
        return ValidationResult(
            ValidationOutcome.ACCOUNT_NOT_FOUND,
            "That CRM account could not be found.",
        )
    if response.status_code == 429:
        return ValidationResult(
            ValidationOutcome.RATE_LIMITED,
            "CRM rate limit reached. Wait a moment and try again.",
        )
    if response.status_code >= 500:
        return ValidationResult(
            ValidationOutcome.TEMPORARY_FAILURE,
            "CRM validation is temporarily unavailable.",
        )
    return ValidationResult(
        ValidationOutcome.TEMPORARY_FAILURE,
        "CRM validation failed with an unexpected response.",
    )


async def search_contacts(
    *,
    base_url: str,
    company_id: str,
    api_token: str,
    query: str,
    page: int = 1,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    url = _contacts_search_url(base_url, company_id)
    params = {
        "include_contact_inboxes": "false",
        "page": str(page),
        "sort": "-created_at",
        "q": query,
    }

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
    try:
        response = await http.get(url, headers=_auth_headers(api_token), params=params)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            return {"results": data}
        return data
    finally:
        if owns_client:
            await http.aclose()


async def filter_contacts(
    *,
    base_url: str,
    company_id: str,
    api_token: str,
    filters: list[dict[str, Any]],
    page: int = 1,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """POST contacts filter. actions is always empty (read-only)."""
    url = _contacts_filter_url(base_url, company_id)
    params = {
        "include_contact_inboxes": "false",
        "page": str(page),
        "sort": "-created_at",
    }
    body = {
        "filters": {"payload": filters},
        "actions": [],
        "is_actions": False,
    }

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
    try:
        response = await http.post(
            url, headers=_auth_headers(api_token), params=params, json=body
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            return {"results": data}
        return data
    finally:
        if owns_client:
            await http.aclose()


async def list_boards(
    *,
    base_url: str,
    company_id: str,
    api_token: str,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """List boards and their pipeline statuses (slim)."""
    url = _boards_url(base_url, company_id)
    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
    try:
        response = await http.get(url, headers=_auth_headers(api_token))
        response.raise_for_status()
        data = response.json()
    finally:
        if owns_client:
            await http.aclose()

    raw = data.get("boards_data", []) if isinstance(data, dict) else []
    boards = []
    for board in raw:
        if not isinstance(board, dict):
            continue
        statuses = [
            {"id": s.get("id"), "name": s.get("name")}
            for s in board.get("statuses_attributes") or []
            if isinstance(s, dict)
        ]
        boards.append(
            {"id": board.get("id"), "name": board.get("name"), "statuses": statuses}
        )
    return {"boards": boards, "total": len(boards)}


async def list_assignees(
    *,
    base_url: str,
    company_id: str,
    api_token: str,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """List agents/assignees (slim; no tokens)."""
    url = _agents_url(base_url, company_id)
    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
    try:
        response = await http.get(url, headers=_auth_headers(api_token))
        response.raise_for_status()
        data = response.json()
    finally:
        if owns_client:
            await http.aclose()

    raw = data if isinstance(data, list) else []
    assignees = []
    for agent in raw:
        if not isinstance(agent, dict):
            continue
        assignees.append(
            {
                "id": agent.get("id"),
                "name": agent.get("name") or agent.get("available_name"),
                "email": agent.get("email"),
                "role": agent.get("role"),
            }
        )
    return {"assignees": assignees, "total": len(assignees)}
