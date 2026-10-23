"""Application entry point: Weather MCP + CRM MCP in one process."""

from __future__ import annotations

import os

from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

from app_factory import create_app
from config import load_settings
from crm_storage import CRMStorage


def _build_storage(settings) -> CRMStorage:
    fernet = Fernet(settings.crm_credential_encryption_key.encode("utf-8"))
    db_path = settings.crm_database_path
    if not os.path.isabs(db_path):
        db_path = os.path.join(os.path.dirname(__file__), db_path)
    return CRMStorage(path=db_path, fernet=fernet)


settings = load_settings()
storage = _build_storage(settings)
app = create_app(settings, storage)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
        reload=os.environ.get("RELOAD", "").lower() in {"1", "true", "yes"},
    )
