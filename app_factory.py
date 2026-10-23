"""Build a combined ASGI app for Weather + CRM MCP servers."""

from __future__ import annotations

from urllib.parse import urlparse

from starlette.applications import Starlette
from starlette.routing import BaseRoute, Mount, Route

from config import Settings
from crm_discovery import build_crm_discovery_routes
from crm_mcp import build_crm_mcp
from crm_oauth_provider import CRMOAuthProvider
from crm_storage import CRMStorage
from fastmcp.utilities.lifespan import combine_lifespans
from weather_mcp import mcp as weather_mcp


def _split_crm_routes(
    crm_app: Starlette, mcp_path: str
) -> tuple[list[BaseRoute], list[BaseRoute]]:
    oauth_routes: list[BaseRoute] = []
    mcp_routes: list[BaseRoute] = []

    for route in crm_app.routes:
        if not isinstance(route, Route):
            oauth_routes.append(route)
            continue
        if route.path == mcp_path:
            mcp_routes.append(route)
        elif route.path.startswith("/.well-known/"):
            continue
        else:
            oauth_routes.append(route)
    return oauth_routes, mcp_routes


def create_app(settings: Settings, storage: CRMStorage) -> Starlette:
    crm_auth = CRMOAuthProvider(
        settings=settings,
        storage=storage,
        crm_api_base_url=settings.crm_api_base_url,
    )
    crm_server = build_crm_mcp(
        crm_auth,
        crm_api_base_url=settings.crm_api_base_url,
        storage=storage,
    )

    weather_app = weather_mcp.http_app(path="/mcp", transport="streamable-http")
    crm_app = crm_server.http_app(path=settings.crm_mcp_path, transport="streamable-http")

    crm_oauth_routes, crm_mcp_routes = _split_crm_routes(
        crm_app, settings.crm_mcp_path
    )
    crm_discovery_routes = build_crm_discovery_routes(settings, crm_auth)

    crm_oauth_app = Starlette(
        routes=crm_oauth_routes,
        middleware=crm_app.user_middleware,
    )

    routes: list[BaseRoute] = []
    routes.extend(crm_discovery_routes)
    routes.extend(crm_mcp_routes)
    oauth_mount = urlparse(settings.crm_oauth_base_url).path or "/crm-auth"
    routes.append(Mount(oauth_mount, app=crm_oauth_app))
    routes.extend(weather_app.routes)

    app = Starlette(
        routes=routes,
        middleware=weather_app.user_middleware,
        lifespan=combine_lifespans(weather_app.lifespan, crm_app.lifespan),
    )
    return app
