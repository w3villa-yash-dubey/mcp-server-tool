"""CRM MCP tools."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token

from crm_client import filter_contacts as crm_filter_contacts
from crm_client import list_assignees as crm_list_assignees
from crm_client import list_boards as crm_list_boards
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

    def _require_connection():
        token = get_access_token()
        connection_id = token.subject or token.claims.get("sub")
        if not connection_id:
            raise PermissionError("Missing CRM connection on access token")
        connection = storage.get_connection(str(connection_id))
        if connection is None or connection.revoked:
            raise PermissionError("CRM connection is invalid or revoked")
        return str(connection_id), connection

    async def _call_crm(coro, *, connection, connection_id: str, tool: str):
        try:
            results = await coro
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status in (401, 403):
                storage.revoke_connection(connection.id)
                raise PermissionError("CRM credentials are no longer valid") from exc
            if status == 429:
                return {"error": "CRM rate limit reached. Try again later."}
            return {"error": f"CRM {tool} failed temporarily."}
        except httpx.HTTPError as exc:
            log.warning("CRM %s network error: %s", tool, type(exc).__name__)
            return {"error": "Could not reach CRM. Try again later."}

        log.info("CRM %s ok connection=%s", tool, connection_id[:8])
        return results

    @mcp.tool()
    async def search_contacts(query: str, page: int = 1) -> dict:
        """Find CRM contacts with a free-text search.

        Use this when the user gives a name, phone, email, or other keyword and
        does NOT need structured conditions (source, assignee, board, AND/OR).

        Args:
            query: Search text (name, phone number, email, or keyword).
            page: Page number starting at 1 (default 1). Results are newest first.

        Returns:
            CRM search JSON with matching contacts (id, name, email, phone, etc.).
            Read-only; does not create or update contacts.
        """
        connection_id, connection = _require_connection()
        if page < 1:
            page = 1
        return await _call_crm(
            crm_search_contacts(
                base_url=crm_api_base_url,
                company_id=connection.company_id,
                api_token=connection.api_token,
                query=query,
                page=page,
            ),
            connection=connection,
            connection_id=connection_id,
            tool="search_contacts",
        )

    @mcp.tool()
    async def list_boards() -> dict:
        """List CRM boards and their pipeline statuses (id + name).

        Call this before filter_contacts when the user names a board or pipeline
        stage (e.g. "Default Board" vs "Default Board1"). Match the exact name to
        an id — do not guess ids. Statuses are per-board.

        Returns:
            {boards: [{id, name, statuses: [{id, name}]}], total}.
        """
        connection_id, connection = _require_connection()
        return await _call_crm(
            crm_list_boards(
                base_url=crm_api_base_url,
                company_id=connection.company_id,
                api_token=connection.api_token,
            ),
            connection=connection,
            connection_id=connection_id,
            tool="list_boards",
        )

    @mcp.tool()
    async def list_assignees() -> dict:
        """List CRM agents/assignees (id, name, email, role).

        Call this before filter_contacts when filtering by a person (e.g. assigned
        to Ishank). Match by name/email to get assignee_id. For unassigned leads
        use assignee_id values [0] — no list lookup needed.

        Returns:
            {assignees: [{id, name, email, role}], total}. Never includes API tokens.
        """
        connection_id, connection = _require_connection()
        return await _call_crm(
            crm_list_assignees(
                base_url=crm_api_base_url,
                company_id=connection.company_id,
                api_token=connection.api_token,
            ),
            connection=connection,
            connection_id=connection_id,
            tool="list_assignees",
        )

    @mcp.tool()
    async def filter_contacts(
        filters: list[dict[str, Any]],
        page: int = 1,
    ) -> dict:
        """Filter CRM contacts with structured rules (AND/OR groups). Read-only.

        Prefer this over search_contacts for conditions (source, assignee, board).
        When the user names a board or assignee, call list_boards / list_assignees
        first to resolve ids. lead_source uses string values (e.g. "Facebook").

        Args:
            filters: Non-empty list of filter condition objects. Each object may include:
                - attribute_key (str): lead_source, assignee_id (0 = unassigned),
                    board_id, name
                - filter_operator (str): equal_to | not_equal_to
                - values (list): strings for lead_source; ints for ids
                - query_operator (str, optional): and | or — joins to the NEXT row
                - filter_group_id (int, optional): group for nested logic (0, 1, 2...)
                - attribute_model (str, optional): usually "standard"
            page: Page number starting at 1 (default 1).

        Returns:
            meta + payload contacts. Never performs bulk actions.

        Example — Facebook source AND unassigned:
            [
              {"attribute_key":"lead_source","filter_operator":"equal_to",
               "values":["Facebook"],"query_operator":"and","filter_group_id":0,
               "attribute_model":"standard"},
              {"attribute_key":"assignee_id","filter_operator":"equal_to",
               "values":[0],"filter_group_id":0,"attribute_model":"standard"}
            ]
        """
        connection_id, connection = _require_connection()
        if page < 1:
            page = 1
        if not filters:
            return {"error": "filters must be a non-empty list"}
        return await _call_crm(
            crm_filter_contacts(
                base_url=crm_api_base_url,
                company_id=connection.company_id,
                api_token=connection.api_token,
                filters=filters,
                page=page,
            ),
            connection=connection,
            connection_id=connection_id,
            tool="filter_contacts",
        )

    return mcp
