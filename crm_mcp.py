"""CRM MCP tools."""

from __future__ import annotations

import logging

import httpx
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token

from crm_client import search_contacts as crm_search_contacts
from crm_oauth_provider import CRMOAuthProvider

log = logging.getLogger("crm-mcp")


def build_crm_mcp(
    auth: CRMOAuthProvider,
    *,
    crm_api_base_url: str,
    storage,
) -> FastMCP:
    mcp = FastMCP("crm", auth=auth)

    @mcp.tool()
    async def search_contacts(query: str, page: int = 1) -> dict:
        """Search CRM contacts by text or phone number."""
        token = get_access_token()
        connection_id = token.subject or token.claims.get("sub")
        if not connection_id:
            raise PermissionError("Missing CRM connection on access token")
        connection = storage.get_connection(str(connection_id))
        if connection is None or connection.revoked:
            raise PermissionError("CRM connection is invalid or revoked")

        if page < 1:
            page = 1

        try:
            results = await crm_search_contacts(
                base_url=crm_api_base_url,
                company_id=connection.company_id,
                api_token=connection.api_token,
                query=query,
                page=page,
            )
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status in (401, 403):
                storage.revoke_connection(connection.id)
                raise PermissionError("CRM credentials are no longer valid") from exc
            if status == 429:
                return {"error": "CRM rate limit reached. Try again later."}
            return {"error": "CRM search failed temporarily."}
        except httpx.HTTPError as exc:
            log.warning("CRM search network error: %s", type(exc).__name__)
            return {"error": "Could not reach CRM. Try again later."}

        log.info(
            "CRM search_contacts ok connection=%s page=%s",
            connection_id[:8],
            page,
        )
        return results

    return mcp
