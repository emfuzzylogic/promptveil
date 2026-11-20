"""Storage layer for PromptVeil: audit logging and payload quarantine.

Provides:
- AuditStore: Akamai Managed PostgreSQL with seamless local SQLite fallback.
- QuarantineStore: Akamai Object Storage (S3/E3) with seamless local folder fallback.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass

try:
    import psycopg2
except ImportError:
    psycopg2 = None  # type: ignore[assignment]

try:
    import boto3
    from botocore.config import Config
except ImportError:
    boto3 = None  # type: ignore[assignment]
    Config = None  # type: ignore[assignment]


_MODULE_DIR = Path(__file__).resolve().parent

_AUDIT_COLUMNS = (
    "id",
    "timestamp",
    "status",
    "risk_score",
    "risk_category",
    "original_preview",
    "sanitized_preview",
    "reason",
    "quarantine_key",
    "latency_ms",
)

_CREATE_AUDIT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT,
    status TEXT,
    risk_score REAL,
    risk_category TEXT,
    original_preview TEXT,
    sanitized_preview TEXT,
    reason TEXT,
    quarantine_key TEXT,
    latency_ms INTEGER
)
"""


def _utc_now_iso() -> str:
    """Return a UTC ISO-8601 timestamp with fixed-width microseconds for reliable sorting."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class AuditStore:
    """Persistent audit log store backed by Akamai Managed PostgreSQL or local SQLite."""

    def __init__(
        self,
        database_url: str | None = None,
        sqlite_path: str = "audit_logs.db",
    ) -> None:
        raw_url = database_url if database_url is not None else os.getenv("DATABASE_URL", "")
        self._database_url: str = (raw_url or "").strip()

        sqlite_candidate = Path(sqlite_path)
        if not sqlite_candidate.is_absolute() and sqlite_path == "audit_logs.db":
            self._sqlite_path: Path = _MODULE_DIR / sqlite_candidate
        else:
            self._sqlite_path = sqlite_candidate

        self._use_postgres: bool = False
        self.last_error: str | None = None

        if self._database_url and psycopg2 is not None:
            try:
                self._init_postgres()
                self._use_postgres = True
            except Exception as exc:
                self.last_error = f"PostgreSQL connection failed: {exc}"
                self._use_postgres = False
        elif self._database_url and psycopg2 is None:
            self.last_error = "psycopg2 is not installed; falling back to SQLite."

        if not self._use_postgres:
            self._init_sqlite()

    def _pg_connect(self) -> Any:
        if psycopg2 is None:
            raise RuntimeError("psycopg2 is not installed")
        return psycopg2.connect(self._database_url, connect_timeout=5)

    def _init_postgres(self) -> None:
        conn = self._pg_connect()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(_CREATE_AUDIT_TABLE_SQL)
        finally:
            conn.close()

    def _sqlite_connect(self) -> sqlite3.Connection:
        self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(str(self._sqlite_path), timeout=10)

    def _init_sqlite(self) -> None:
        conn = self._sqlite_connect()
        try:
            with conn:
                conn.execute(_CREATE_AUDIT_TABLE_SQL)
        finally:
            conn.close()

    def _fallback_to_sqlite(self, exc: Exception) -> None:
        self.last_error = f"PostgreSQL runtime error (switched to SQLite): {exc}"
        self._use_postgres = False
        self._init_sqlite()

    def log_event(
        self,
        status: str,
        risk_score: float,
        risk_category: str,
        original_preview: str,
        sanitized_preview: str,
        reason: str,
        quarantine_key: str | None = None,
        latency_ms: int = 0,
        event_id: str | None = None,
        timestamp: str | None = None,
    ) -> str:
        """Insert a new audit log entry and return its event_id."""
        eid = event_id or str(uuid.uuid4())
        ts = timestamp or _utc_now_iso()
        params = (
            eid,
            ts,
            status,
            float(risk_score),
            risk_category,
            original_preview,
            sanitized_preview,
            reason,
            quarantine_key,
            int(latency_ms),
        )

        if self._use_postgres:
            pg_sql = (
                "INSERT INTO audit_logs "
                "(id, timestamp, status, risk_score, risk_category, "
                "original_preview, sanitized_preview, reason, quarantine_key, latency_ms) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            )
            last_exc: Exception | None = None
            for _ in range(2):
                conn = None
                try:
                    conn = self._pg_connect()
                    with conn:
                        with conn.cursor() as cur:
                            cur.execute(pg_sql, params)
                    return eid
                except Exception as exc:
                    last_exc = exc
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
            if last_exc is not None:
                self._fallback_to_sqlite(last_exc)

        sqlite_sql = (
            "INSERT INTO audit_logs "
            "(id, timestamp, status, risk_score, risk_category, "
            "original_preview, sanitized_preview, reason, quarantine_key, latency_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        conn = self._sqlite_connect()
        try:
            with conn:
                conn.execute(sqlite_sql, params)
        finally:
            conn.close()
        return eid

    def get_recent_logs(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return up to `limit` most recent audit log records ordered newest first."""
        safe_limit = max(0, int(limit))
        if safe_limit == 0:
            return []

        if self._use_postgres:
            pg_sql = (
                "SELECT id, timestamp, status, risk_score, risk_category, "
                "original_preview, sanitized_preview, reason, quarantine_key, latency_ms "
                "FROM audit_logs ORDER BY timestamp DESC LIMIT %s"
            )
            last_exc: Exception | None = None
            for _ in range(2):
                conn = None
                try:
                    conn = self._pg_connect()
                    with conn.cursor() as cur:
                        cur.execute(pg_sql, (safe_limit,))
                        rows = cur.fetchall()
                    return [dict(zip(_AUDIT_COLUMNS, row)) for row in rows]
                except Exception as exc:
                    last_exc = exc
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            pass
            if last_exc is not None:
                self._fallback_to_sqlite(last_exc)

        sqlite_sql = (
            "SELECT id, timestamp, status, risk_score, risk_category, "
            "original_preview, sanitized_preview, reason, quarantine_key, latency_ms "
            "FROM audit_logs ORDER BY timestamp DESC LIMIT ?"
        )
        conn = self._sqlite_connect()
        try:
            cur = conn.execute(sqlite_sql, (safe_limit,))
            rows = cur.fetchall()
        finally:
            conn.close()
        return [dict(zip(_AUDIT_COLUMNS, row)) for row in rows]

    def db_backend_name(self) -> str:
        """Return the active database backend display name."""
        if self._use_postgres:
            return "Akamai Managed PostgreSQL"
        return "Local SQLite (Fallback)"


class QuarantineStore:
    """Quarantine payload store backed by Akamai Object Storage (E3) or local JSON folder."""

    def __init__(
        self,
        endpoint_url: str | None = None,
        bucket: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        fallback_dir: str = "quarantine_fallback",
    ) -> None:
        raw_endpoint = endpoint_url if endpoint_url is not None else os.getenv("AKAMAI_S3_ENDPOINT", "")
        raw_bucket = bucket if bucket is not None else os.getenv("AKAMAI_S3_BUCKET", "")
        raw_access = access_key if access_key is not None else os.getenv("AKAMAI_S3_ACCESS_KEY", "")
        raw_secret = secret_key if secret_key is not None else os.getenv("AKAMAI_S3_SECRET_KEY", "")

        self._endpoint_url: str = (raw_endpoint or "").strip()
        if self._endpoint_url and not self._endpoint_url.startswith(("http://", "https://")):
            self._endpoint_url = f"https://{self._endpoint_url}"
        self._bucket: str = (raw_bucket or "").strip()
        self._access_key: str = (raw_access or "").strip()
        self._secret_key: str = (raw_secret or "").strip()

        dir_candidate = Path(fallback_dir)
        if not dir_candidate.is_absolute() and fallback_dir == "quarantine_fallback":
            self._fallback_dir: Path = _MODULE_DIR / dir_candidate
        else:
            self._fallback_dir = dir_candidate

        self._s3_client: Any = None
        self._use_s3: bool = False
        self.last_error: str | None = None

        has_all_creds = bool(
            self._endpoint_url and self._bucket and self._access_key and self._secret_key
        )
        if has_all_creds and boto3 is not None and Config is not None:
            try:
                try:
                    s3_config = Config(
                        signature_version="s3v4",
                        request_checksum_calculation="when_required",
                        connect_timeout=5,
                        read_timeout=10,
                    )
                except TypeError:
                    s3_config = Config(
                        signature_version="s3v4",
                        connect_timeout=5,
                        read_timeout=10,
                    )
                client = boto3.client(
                    "s3",
                    endpoint_url=self._endpoint_url,
                    aws_access_key_id=self._access_key,
                    aws_secret_access_key=self._secret_key,
                    config=s3_config,
                )
                client.head_bucket(Bucket=self._bucket)
                self._s3_client = client
                self._use_s3 = True
            except Exception as exc:
                self.last_error = f"Akamai Object Storage unavailable: {exc}"
                self._use_s3 = False
        elif has_all_creds:
            self.last_error = "boto3 is not installed; falling back to local quarantine folder."

        if not self._use_s3:
            self._fallback_dir.mkdir(parents=True, exist_ok=True)

    def _safe_local_path(self, key: str) -> Path:
        base = self._fallback_dir.resolve()
        normalized_key = key.lstrip("/")
        target = (base / normalized_key).resolve()
        if base != target and base not in target.parents:
            raise ValueError(f"Invalid quarantine key path: {key}")
        return target

    def quarantine_payload(self, payload_dict: dict[str, Any]) -> str:
        """Persist a quarantined payload JSON document and return its object key."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        short_id = uuid.uuid4().hex[:8]
        key = f"quarantine/{ts}_{short_id}.json"
        body = json.dumps(payload_dict, indent=2, default=str)

        if self._use_s3 and self._s3_client is not None:
            try:
                self._s3_client.put_object(
                    Bucket=self._bucket,
                    Key=key,
                    Body=body.encode("utf-8"),
                    ContentType="application/json",
                )
                return key
            except Exception as exc:
                self.last_error = f"S3 upload failed (falling back locally): {exc}"
                self._use_s3 = False

        target = self._safe_local_path(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        return key

    def list_quarantined(self, limit: int = 10) -> list[str]:
        """Return up to `limit` newest quarantined object keys under quarantine/."""
        safe_limit = max(0, int(limit))
        if safe_limit == 0:
            return []

        if self._use_s3 and self._s3_client is not None:
            try:
                keys: list[str] = []
                paginator = self._s3_client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=self._bucket, Prefix="quarantine/"):
                    for obj in page.get("Contents", []):
                        obj_key = obj.get("Key", "")
                        if obj_key and obj_key != "quarantine/" and obj_key.endswith(".json"):
                            keys.append(obj_key)
                keys.sort(reverse=True)
                return keys[:safe_limit]
            except Exception as exc:
                self.last_error = f"S3 list failed (falling back locally): {exc}"
                self._use_s3 = False

        q_dir = self._fallback_dir / "quarantine"
        if not q_dir.exists():
            return []
        local_keys = [
            f"quarantine/{p.name}"
            for p in q_dir.iterdir()
            if p.is_file() and p.suffix == ".json"
        ]
        local_keys.sort(reverse=True)
        return local_keys[:safe_limit]

    def get_quarantined_content(self, key: str) -> dict[str, Any]:
        """Read and parse the JSON payload for the given quarantine key."""
        if self._use_s3 and self._s3_client is not None:
            try:
                resp = self._s3_client.get_object(Bucket=self._bucket, Key=key)
                raw = resp["Body"].read().decode("utf-8")
                return json.loads(raw)
            except Exception as exc:
                self.last_error = f"S3 get failed for {key}: {exc}"
                # Try local fallback in case the key was written locally earlier
                local_target = self._safe_local_path(key)
                if local_target.is_file():
                    return json.loads(local_target.read_text(encoding="utf-8"))
                raise

        target = self._safe_local_path(key)
        return json.loads(target.read_text(encoding="utf-8"))

    def s3_backend_name(self) -> str:
        """Return the active quarantine storage backend display name."""
        if self._use_s3:
            return "Akamai Object Storage"
        return "Local Quarantine Folder (Fallback)"
