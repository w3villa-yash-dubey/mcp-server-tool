"""SQLite persistence for CRM connections and OAuth state."""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from cryptography.fernet import Fernet, InvalidToken
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import TypeAdapter

_CLIENT_ADAPTER = TypeAdapter(OAuthClientInformationFull)


@dataclass
class PendingAuthorization:
    id: str
    client_id: str
    redirect_uri: str
    redirect_uri_provided_explicitly: bool
    state: str | None
    scopes: list[str]
    code_challenge: str
    resource: str | None
    expires_at: float


@dataclass
class StoredAuthCode:
    code: str
    connection_id: str
    client_id: str
    redirect_uri: str
    redirect_uri_provided_explicitly: bool
    scopes: list[str]
    code_challenge: str
    resource: str | None
    expires_at: float
    used: bool


@dataclass
class CRMConnection:
    id: str
    company_id: str
    api_token: str
    revoked: bool


class CRMStorage:
    def __init__(self, path: str, fernet: Fernet) -> None:
        self._path = path
        self._fernet = fernet
        self._lock = threading.RLock()
        self._init_db()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS crm_connections (
                    id TEXT PRIMARY KEY,
                    company_id TEXT NOT NULL,
                    token_ciphertext BLOB NOT NULL,
                    created_at REAL NOT NULL,
                    revoked_at REAL
                );

                CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS oauth_pending (
                    id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    redirect_uri_provided_explicitly INTEGER NOT NULL,
                    state TEXT,
                    scopes_json TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    resource TEXT,
                    expires_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS oauth_auth_codes (
                    code TEXT PRIMARY KEY,
                    connection_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    redirect_uri_provided_explicitly INTEGER NOT NULL,
                    scopes_json TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    resource TEXT,
                    expires_at REAL NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
                    token_jti TEXT PRIMARY KEY,
                    connection_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    resource TEXT,
                    expires_at REAL NOT NULL
                );
                """
            )

    def _encrypt_token(self, token: str) -> bytes:
        return self._fernet.encrypt(token.encode("utf-8"))

    def _decrypt_token(self, ciphertext: bytes) -> str:
        try:
            return self._fernet.decrypt(ciphertext).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Stored CRM token could not be decrypted") from exc

    def create_connection(self, company_id: str, api_token: str) -> CRMConnection:
        connection_id = secrets.token_urlsafe(24)
        now = time.time()
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO crm_connections (id, company_id, token_ciphertext, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (connection_id, company_id, self._encrypt_token(api_token), now),
            )
        return CRMConnection(id=connection_id, company_id=company_id, api_token=api_token, revoked=False)

    def get_connection(self, connection_id: str) -> CRMConnection | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT id, company_id, token_ciphertext, revoked_at FROM crm_connections WHERE id = ?",
                (connection_id,),
            ).fetchone()
        if row is None:
            return None
        revoked = row["revoked_at"] is not None
        token = self._decrypt_token(row["token_ciphertext"])
        return CRMConnection(
            id=row["id"],
            company_id=row["company_id"],
            api_token=token,
            revoked=revoked,
        )

    def revoke_connection(self, connection_id: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE crm_connections SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (time.time(), connection_id),
            )

    def save_client(self, client: OAuthClientInformationFull) -> None:
        payload = _CLIENT_ADAPTER.dump_json(client).decode("utf-8")
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO oauth_clients (client_id, client_json) VALUES (?, ?)
                ON CONFLICT(client_id) DO UPDATE SET client_json = excluded.client_json
                """,
                (client.client_id, payload),
            )

    def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT client_json FROM oauth_clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        if row is None:
            return None
        return _CLIENT_ADAPTER.validate_json(row["client_json"])

    def create_pending(self, pending: PendingAuthorization) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO oauth_pending (
                    id, client_id, redirect_uri, redirect_uri_provided_explicitly,
                    state, scopes_json, code_challenge, resource, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pending.id,
                    pending.client_id,
                    pending.redirect_uri,
                    int(pending.redirect_uri_provided_explicitly),
                    pending.state,
                    json.dumps(pending.scopes),
                    pending.code_challenge,
                    pending.resource,
                    pending.expires_at,
                ),
            )

    def get_pending(self, pending_id: str) -> PendingAuthorization | None:
        with self._lock, self._conn() as conn:
            row = conn.execute("SELECT * FROM oauth_pending WHERE id = ?", (pending_id,)).fetchone()
        if row is None:
            return None
        if row["expires_at"] < time.time():
            self.delete_pending(pending_id)
            return None
        return PendingAuthorization(
            id=row["id"],
            client_id=row["client_id"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=bool(row["redirect_uri_provided_explicitly"]),
            state=row["state"],
            scopes=json.loads(row["scopes_json"]),
            code_challenge=row["code_challenge"],
            resource=row["resource"],
            expires_at=row["expires_at"],
        )

    def delete_pending(self, pending_id: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("DELETE FROM oauth_pending WHERE id = ?", (pending_id,))

    def create_auth_code(self, record: StoredAuthCode) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO oauth_auth_codes (
                    code, connection_id, client_id, redirect_uri,
                    redirect_uri_provided_explicitly, scopes_json, code_challenge,
                    resource, expires_at, used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    record.code,
                    record.connection_id,
                    record.client_id,
                    record.redirect_uri,
                    int(record.redirect_uri_provided_explicitly),
                    json.dumps(record.scopes),
                    record.code_challenge,
                    record.resource,
                    record.expires_at,
                ),
            )

    def get_auth_code(self, code: str, client_id: str) -> StoredAuthCode | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM oauth_auth_codes WHERE code = ? AND client_id = ?",
                (code, client_id),
            ).fetchone()
            if row is None:
                return None
            if row["used"]:
                return None
            if row["expires_at"] < time.time():
                conn.execute("DELETE FROM oauth_auth_codes WHERE code = ?", (code,))
                return None
        return StoredAuthCode(
            code=row["code"],
            connection_id=row["connection_id"],
            client_id=row["client_id"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=bool(row["redirect_uri_provided_explicitly"]),
            scopes=json.loads(row["scopes_json"]),
            code_challenge=row["code_challenge"],
            resource=row["resource"],
            expires_at=row["expires_at"],
            used=bool(row["used"]),
        )

    def mark_auth_code_used(self, code: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE oauth_auth_codes SET used = 1 WHERE code = ?",
                (code,),
            )

    def save_refresh_token(
        self,
        *,
        jti: str,
        connection_id: str,
        client_id: str,
        scopes: list[str],
        resource: str | None,
        expires_at: float,
    ) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO oauth_refresh_tokens (
                    token_jti, connection_id, client_id, scopes_json, resource, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(token_jti) DO UPDATE SET
                    connection_id = excluded.connection_id,
                    client_id = excluded.client_id,
                    scopes_json = excluded.scopes_json,
                    resource = excluded.resource,
                    expires_at = excluded.expires_at
                """,
                (jti, connection_id, client_id, json.dumps(scopes), resource, expires_at),
            )

    def get_refresh_token(self, jti: str) -> dict[str, Any] | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM oauth_refresh_tokens WHERE token_jti = ?",
                (jti,),
            ).fetchone()
        if row is None:
            return None
        if row["expires_at"] < time.time():
            self.delete_refresh_token(jti)
            return None
        return {
            "connection_id": row["connection_id"],
            "client_id": row["client_id"],
            "scopes": json.loads(row["scopes_json"]),
            "resource": row["resource"],
            "expires_at": row["expires_at"],
        }

    def delete_refresh_token(self, jti: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("DELETE FROM oauth_refresh_tokens WHERE token_jti = ?", (jti,))
