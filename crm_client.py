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


def _contacts_search_url(base_url: str, company_id: str) -> str:
    return f"{base_url}/api/v1/accounts/{company_id}/contacts/search"


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
    headers = {
        "api_access_token": api_token,
        "Content-Type": "application/json",
    }
    params = {
        "include_contact_inboxes": "false",
        "page": str(page),
        "sort": "-created_at",
        "q": query,
    }

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=DEFAULT_TIMEOUT)
    try:
        response = await http.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            return {"results": data}
        return data
    finally:
        if owns_client:
            await http.aclose()
