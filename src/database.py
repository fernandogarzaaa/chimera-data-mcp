from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Column,
    Engine,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    event,
    inspect,
    text,
)
from sqlalchemy.engine import make_url

from errors import ClientSafeError


DEFAULT_DATABASE_URL = "sqlite:///./retail_supply_chain.db"
SECURITY_VIOLATION_MESSAGE = "Security Violation: Unauthorized data mutation attempt detected. Only read-only SELECT operations are authorized."
COMMENT_PATTERN = re.compile(r"(--[^\n]*$)|(/\*.*?\*/)", re.MULTILINE | re.DOTALL)
MUTATION_PATTERN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT)\b",
    re.IGNORECASE,
)
ENTRYPOINT_PATTERN = re.compile(r"^(SELECT|WITH)\b", re.IGNORECASE)
DEFAULT_MAX_ROWS = 1000
STATEMENT_TIMEOUT_MS = 10_000

# SQLite authorizer: only reading is allowed on the query connection.
_SQLITE_ALLOWED_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
    getattr(sqlite3, "SQLITE_RECURSIVE", 33),
}


_SQLITE_INTROSPECTION_PRAGMAS = {
    "table_info",
    "table_xinfo",
    "table_list",
    "index_list",
    "index_info",
    "index_xinfo",
    "foreign_key_list",
    "database_list",
}


def _sqlite_authorizer(action: int, arg1: Any, arg2: Any, dbname: Any, source: Any) -> int:
    if action in _SQLITE_ALLOWED_ACTIONS:
        return sqlite3.SQLITE_OK
    # PRAGMAs may only be read (``PRAGMA name``, used by SQLAlchemy on connect)
    # or be schema-introspection calls such as ``PRAGMA table_xinfo(t)``.
    # Setting any PRAGMA (query_only = OFF, writable_schema = 1, ...) is denied.
    if action == sqlite3.SQLITE_PRAGMA and (
        arg2 is None or str(arg1).lower() in _SQLITE_INTROSPECTION_PRAGMAS
    ):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _max_rows() -> int:
    try:
        return max(1, int(os.getenv("MAX_QUERY_ROWS", str(DEFAULT_MAX_ROWS))))
    except ValueError:
        return DEFAULT_MAX_ROWS


def _readonly_engine(database_url: str) -> Engine:
    """Engine whose connections cannot modify data.

    * SQLite file DBs are opened with ``mode=ro`` + ``PRAGMA query_only`` and
      an authorizer that only permits SELECT/READ/FUNCTION.
    * PostgreSQL / MySQL sessions are switched to READ ONLY transactions with
      a statement timeout on connect.
    * Other backends fall back to the SQL keyword filter only (documented in
      the README); point DATABASE_URL at a read-only database user there.
    """
    url = make_url(database_url)
    backend = url.get_backend_name()
    if backend == "sqlite":
        database = url.database or ""
        if database in ("", ":memory:"):
            raise ValueError("an in-memory SQLite database cannot be opened read-only")
        path = Path(database).resolve()
        uri = f"file:{path.as_posix()}?mode=ro"

        def _connect() -> sqlite3.Connection:
            conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
            conn.execute("PRAGMA query_only = ON")
            conn.set_authorizer(_sqlite_authorizer)
            return conn

        return create_engine("sqlite://", creator=_connect, future=True)

    engine = create_engine(database_url, future=True)
    if backend == "postgresql":

        @event.listens_for(engine, "connect")
        def _pg_readonly(dbapi_conn: Any, _record: Any) -> None:
            cur = dbapi_conn.cursor()
            cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
            cur.execute(f"SET statement_timeout = {STATEMENT_TIMEOUT_MS}")
            cur.close()

    elif backend in ("mysql", "mariadb"):

        @event.listens_for(engine, "connect")
        def _mysql_readonly(dbapi_conn: Any, _record: Any) -> None:
            cur = dbapi_conn.cursor()
            cur.execute("SET SESSION TRANSACTION READ ONLY")
            cur.execute(f"SET SESSION MAX_EXECUTION_TIME = {STATEMENT_TIMEOUT_MS}")
            cur.close()

    return engine


class DatabaseManager:
    def __init__(self) -> None:
        configured_url = os.getenv("DATABASE_URL", "").strip()
        self.database_url = configured_url or DEFAULT_DATABASE_URL
        self.max_rows = _max_rows()

        if self.database_url == DEFAULT_DATABASE_URL:
            sqlite_path = Path("./retail_supply_chain.db")
            if not sqlite_path.exists():
                self._bootstrap_default_database(sqlite_path)

        # All queries (and schema inspection) go through a read-only engine.
        self.engine = _readonly_engine(self.database_url)

    def _bootstrap_default_database(self, sqlite_path: Path) -> None:
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        metadata = MetaData()
        writer = create_engine(self.database_url, future=True)

        sales_performance = Table(
            "sales_performance",
            metadata,
            Column("transaction_id", Integer, primary_key=True),
            Column("date", String(32), nullable=False),
            Column("store_id", String(32), nullable=False),
            Column("product_category", String(64), nullable=False),
            Column("revenue", Float, nullable=False),
            Column("units_sold", Integer, nullable=False),
        )

        inventory_status = Table(
            "inventory_status",
            metadata,
            Column("item_id", Integer, primary_key=True),
            Column("sku", String(64), nullable=False),
            Column("warehouse_location", String(64), nullable=False),
            Column("stock_on_hand", Integer, nullable=False),
            Column("reorder_point", Integer, nullable=False),
            Column("lead_time_days", Integer, nullable=False),
        )

        metadata.create_all(writer)

        sales_rows: list[dict[str, Any]] = [
            {"transaction_id": 1, "date": "2026-01-03", "store_id": "NYC-01", "product_category": "Electronics", "revenue": 18250.75, "units_sold": 42},
            {"transaction_id": 2, "date": "2026-01-05", "store_id": "DAL-07", "product_category": "Groceries", "revenue": 9340.10, "units_sold": 315},
            {"transaction_id": 3, "date": "2026-01-07", "store_id": "SEA-03", "product_category": "Home Goods", "revenue": 12110.50, "units_sold": 88},
            {"transaction_id": 4, "date": "2026-01-10", "store_id": "CHI-05", "product_category": "Apparel", "revenue": 7780.60, "units_sold": 126},
            {"transaction_id": 5, "date": "2026-01-13", "store_id": "MIA-02", "product_category": "Sports", "revenue": 6499.95, "units_sold": 54},
            {"transaction_id": 6, "date": "2026-01-16", "store_id": "BOS-08", "product_category": "Beauty", "revenue": 5035.40, "units_sold": 142},
            {"transaction_id": 7, "date": "2026-01-19", "store_id": "LA-11", "product_category": "Furniture", "revenue": 22375.90, "units_sold": 29},
            {"transaction_id": 8, "date": "2026-01-21", "store_id": "PHX-04", "product_category": "Pharmacy", "revenue": 4310.22, "units_sold": 167},
            {"transaction_id": 9, "date": "2026-01-25", "store_id": "ATL-06", "product_category": "Pet Supplies", "revenue": 3899.77, "units_sold": 73},
            {"transaction_id": 10, "date": "2026-01-28", "store_id": "DEN-09", "product_category": "Automotive", "revenue": 9950.30, "units_sold": 61},
        ]

        inventory_rows: list[dict[str, Any]] = [
            {"item_id": 1, "sku": "ELEC-1001", "warehouse_location": "WH-NORTH", "stock_on_hand": 220, "reorder_point": 120, "lead_time_days": 12},
            {"item_id": 2, "sku": "GROC-2045", "warehouse_location": "WH-SOUTH", "stock_on_hand": 980, "reorder_point": 600, "lead_time_days": 4},
            {"item_id": 3, "sku": "HOME-3320", "warehouse_location": "WH-WEST", "stock_on_hand": 310, "reorder_point": 180, "lead_time_days": 8},
            {"item_id": 4, "sku": "APP-1902", "warehouse_location": "WH-EAST", "stock_on_hand": 540, "reorder_point": 300, "lead_time_days": 7},
            {"item_id": 5, "sku": "SPRT-4478", "warehouse_location": "WH-CENTRAL", "stock_on_hand": 140, "reorder_point": 90, "lead_time_days": 14},
            {"item_id": 6, "sku": "BEAU-8760", "warehouse_location": "WH-SOUTH", "stock_on_hand": 460, "reorder_point": 220, "lead_time_days": 5},
            {"item_id": 7, "sku": "FURN-1290", "warehouse_location": "WH-WEST", "stock_on_hand": 95, "reorder_point": 70, "lead_time_days": 21},
            {"item_id": 8, "sku": "PHAR-5601", "warehouse_location": "WH-NORTH", "stock_on_hand": 730, "reorder_point": 400, "lead_time_days": 6},
            {"item_id": 9, "sku": "PET-3339", "warehouse_location": "WH-EAST", "stock_on_hand": 205, "reorder_point": 110, "lead_time_days": 10},
            {"item_id": 10, "sku": "AUTO-9322", "warehouse_location": "WH-CENTRAL", "stock_on_hand": 160, "reorder_point": 120, "lead_time_days": 16},
        ]

        with writer.begin() as connection:
            connection.execute(sales_performance.insert(), sales_rows)
            connection.execute(inventory_status.insert(), inventory_rows)
        writer.dispose()

    def get_schema_layout(self) -> str:
        inspector = inspect(self.engine)
        schema_map: dict[str, list[dict[str, Any]]] = {}

        for table_name in inspector.get_table_names():
            columns = inspector.get_columns(table_name)
            pk_constraint = inspector.get_pk_constraint(table_name) or {}
            constrained_columns = pk_constraint.get("constrained_columns") or []
            primary_key_columns = set(constrained_columns)
            foreign_key_columns: set[str] = set()
            for fk in inspector.get_foreign_keys(table_name):
                foreign_key_columns.update(fk.get("constrained_columns") or [])

            table_layout: list[dict[str, Any]] = []
            for column in columns:
                table_layout.append(
                    {
                        "column_name": column.get("name"),
                        "data_type": str(column.get("type")),
                        "nullable": bool(column.get("nullable", True)),
                        "primary_key": column.get("name") in primary_key_columns,
                        "foreign_key": column.get("name") in foreign_key_columns,
                    }
                )
            schema_map[table_name] = table_layout

        return json.dumps(schema_map, separators=(",", ":"))

    def execute_query(self, sql_query: str) -> list[dict[str, Any]]:
        cleaned_query = COMMENT_PATTERN.sub(" ", sql_query).strip()

        if not ENTRYPOINT_PATTERN.match(cleaned_query):
            raise ClientSafeError(SECURITY_VIOLATION_MESSAGE)

        if MUTATION_PATTERN.search(cleaned_query):
            raise ClientSafeError(SECURITY_VIOLATION_MESSAGE)

        # Execution errors propagate to the tool wrapper, which formats them
        # via _safe_error: no tracebacks (and no server paths) reach clients.
        # The connection itself is read-only (see _readonly_engine); the
        # keyword filter above is only a first, friendly line of defence.
        # Results are capped at max_rows to bound memory use.
        with self.engine.connect() as connection:
            result = connection.execute(text(cleaned_query))
            rows = result.mappings().fetchmany(self.max_rows)
            result.close()
            connection.rollback()
            return [dict(row) for row in rows]
