"""Weather MCP server (unchanged Google OAuth behavior)."""

from __future__ import annotations

import logging
import os
import sys

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.dependencies import get_access_token

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("weather-mcp")

auth = GoogleProvider(
    client_id=os.environ["GOOGLE_CLIENT_ID"],
    client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
    base_url=os.environ["BASE_URL"],
    required_scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
    ],
)

mcp = FastMCP("weather", auth=auth)

ALLOWED_DOMAIN = "w3villa.com"


def check_access() -> str:
    email = (get_access_token().claims.get("email") or "").lower()
    if not email.endswith("@" + ALLOWED_DOMAIN):
        raise PermissionError("You are not allowed to use this tool")
    return email


@mcp.tool()
async def get_weather(city: str) -> dict:
    """Get current weather and 3-day forecast for a city."""
    email = check_access()
    log.info("TOOL CALLED: get_weather(city=%r) by %s", city, email)
    async with httpx.AsyncClient() as c:
        g = (
            await c.get(
                "https://geocoding-api.open-meteo.com/v1/search",
                params={"name": city, "count": 1},
            )
        ).json()
        if not g.get("results"):
            log.warning("City not found: %r", city)
            return {"error": f"City '{city}' not found"}
        p = g["results"][0]
        w = (
            await c.get(
                "https://api.open-meteo.com/v1/forecast",
                params={
                    "latitude": p["latitude"],
                    "longitude": p["longitude"],
                    "current": "temperature_2m,relative_humidity_2m,wind_speed_10m,weather_code",
                    "daily": "temperature_2m_max,temperature_2m_min,precipitation_sum",
                    "forecast_days": 3,
                    "timezone": "auto",
                },
            )
        ).json()
    result = {
        "city": p["name"],
        "country": p.get("country"),
        "current": w["current"],
        "forecast": w["daily"],
        "source": "weather-mcp-tool (Open-Meteo API)",
    }
    temp = w["current"].get("temperature_2m")
    log.info(
        "TOOL OK: %s, %s — temp=%s°C (Open-Meteo)",
        p["name"],
        p.get("country"),
        temp,
    )
    return result
