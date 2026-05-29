"""Database access and schema inspection utilities for Chimera Data MCP."""

from __future__ import annotations

import json
import os
import re
from datetime import date
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Column,
    Date,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.exc import SQLAlchemyError


READ_ONLY_ERROR = "Security Violation: Only read-only SELECT operations are authorized."
_MUTATION_PATTERN = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|create|replace)\b", re.IGNORECASE
)


class DatabaseManager:
    """Manages read-only querying and schema discovery against the configured database."""

    def __init__(self) -> None:
        """Initialize the SQLAlchemy engine and seed fallback SQLite data when needed."""
        self.default_url = "sqlite:///./retail_supply_chain.db"
        self.database_url = os.getenv("DATABASE_URL", self.default_url)

        if self.database_url == self.default_url:
            sqlite_path = Path("./retail_supply_chain.db")
            if not sqlite_path.exists():
                self._seed_default_sqlite(sqlite_path)

        self.engine = create_engine(self.database_url, future=True)

    def _seed_default_sqlite(self, sqlite_path: Path) -> None:
        """Create and seed sample enterprise tables for local bootstrap usage."""
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        bootstrap_engine = create_engine(self.default_url, future=True)
        metadata = MetaData()

        sales_performance = Table(
            "sales_performance",
            metadata,
            Column("transaction_id", Integer, primary_key=True),
            Column("date", Date, nullable=False),
            Column("store_id", String(30), nullable=False),
            Column("product_category", String(60), nullable=False),
            Column("revenue", Float, nullable=False),
            Column("units_sold", Integer, nullable=False),
        )

        inventory_status = Table(
            "inventory_status",
            metadata,
            Column("item_id", Integer, primary_key=True),
            Column("sku", String(40), nullable=False),
            Column("warehouse_location", String(50), nullable=False),
            Column("stock_on_hand", Integer, nullable=False),
            Column("reorder_point", Integer, nullable=False),
            Column("lead_time_days", Integer, nullable=False),
        )

        metadata.create_all(bootstrap_engine)

        sales_rows: list[dict[str, Any]] = [
            {
                "transaction_id": 1,
                "date": date(2026, 1, 3),
                "store_id": "NYC-01",
                "product_category": "Electronics",
                "revenue": 18250.75,
                "units_sold": 42,
            },
            {
                "transaction_id": 2,
                "date": date(2026, 1, 5),
                "store_id": "DAL-07",
                "product_category": "Groceries",
                "revenue": 9340.10,
                "units_sold": 315,
            },
            {
                "transaction_id": 3,
                "date": date(2026, 1, 7),
                "store_id": "SEA-03",
                "product_category": "Home Goods",
                "revenue": 12110.50,
                "units_sold": 88,
            },
            {
                "transaction_id": 4,
                "date": date(2026, 1, 10),
                "store_id": "CHI-05",
                "product_category": "Apparel",
                "revenue": 7780.60,
                "units_sold": 126,
            },
            {
                "transaction_id": 5,
                "date": date(2026, 1, 13),
                "store_id": "MIA-02",
                "product_category": "Sports",
                "revenue": 6499.95,
                "units_sold": 54,
            },
            {
                "transaction_id": 6,
                "date": date(2026, 1, 16),
                "store_id": "BOS-08",
                "product_category": "Beauty",
                "revenue": 5035.40,
                "units_sold": 142,
            },
            {
                "transaction_id": 7,
                "date": date(2026, 1, 19),
                "store_id": "LA-11",
                "product_category": "Furniture",
                "revenue": 22375.90,
                "units_sold": 29,
            },
            {
                "transaction_id": 8,
                "date": date(2026, 1, 21),
                "store_id": "PHX-04",
                "product_category": "Pharmacy",
                "revenue": 4310.22,
                "units_sold": 167,
            },
            {
                "transaction_id": 9,
                "date": date(2026, 1, 25),
                "store_id": "ATL-06",
                "product_category": "Pet Supplies",
                "revenue": 3899.77,
                "units_sold": 73,
            },
            {
                "transaction_id": 10,
                "date": date(2026, 1, 28),
                "store_id": "DEN-09",
                "product_category": "Automotive",
                "revenue": 9950.30,
                "units_sold": 61,
            },
        ]

        inventory_rows: list[dict[str, Any]] = [
            {
                "item_id": 1,
                "sku": "ELEC-1001",
                "warehouse_location": "WH-NORTH",
                "stock_on_hand": 220,
                "reorder_point": 120,
                "lead_time_days": 12,
            },
            {
                "item_id": 2,
                "sku": "GROC-2045",
                "warehouse_location": "WH-SOUTH",
                "stock_on_hand": 980,
                "reorder_point": 600,
                "lead_time_days": 4,
            },
            {
                "item_id": 3,
                "sku": "HOME-3320",
                "warehouse_location": "WH-WEST",
                "stock_on_hand": 310,
                "reorder_point": 180,
                "lead_time_days": 8,
            },
            {
                "item_id": 4,
                "sku": "APP-1902",
                "warehouse_location": "WH-EAST",
                "stock_on_hand": 540,
                "reorder_point": 300,
                "lead_time_days": 7,
            },
            {
                "item_id": 5,
                "sku": "SPRT-4478",
                "warehouse_location": "WH-CENTRAL",
                "stock_on_hand": 140,
                "reorder_point": 90,
                "lead_time_days": 14,
            },
            {
                "item_id": 6,
                "sku": "BEAU-8760",
                "warehouse_location": "WH-SOUTH",
                "stock_on_hand": 460,
                "reorder_point": 220,
                "lead_time_days": 5,
            },
            {
                "item_id": 7,
                "sku": "FURN-1290",
                "warehouse_location": "WH-WEST",
                "stock_on_hand": 95,
                "reorder_point": 70,
                "lead_time_days": 21,
            },
            {
                "item_id": 8,
                "sku": "PHAR-5601",
                "warehouse_location": "WH-NORTH",
                "stock_on_hand": 730,
                "reorder_point": 400,
                "lead_time_days": 6,
            },
            {
                "item_id": 9,
                "sku": "PET-3339",
                "warehouse_location": "WH-EAST",
                "stock_on_hand": 205,
                "reorder_point": 110,
                "lead_time_days": 10,
            },
            {
                "item_id": 10,
                "sku": "AUTO-9322",
                "warehouse_location": "WH-CENTRAL",
                "stock_on_hand": 160,
                "reorder_point": 120,
                "lead_time_days": 16,
            },
        ]

        with bootstrap_engine.begin() as connection:
            connection.execute(sales_performance.insert(), sales_rows)
            connection.execute(inventory_status.insert(), inventory_rows)

    def get_schema_layout(self) -> str:
        """Return compact JSON with table/column metadata without scanning table rows."""
        inspector = inspect(self.engine)
        schema: dict[str, Any] = {"tables": {}}

        for table_name in inspector.get_table_names():
            columns = inspector.get_columns(table_name)
            pk_info = inspector.get_pk_constraint(table_name) or {}
            foreign_keys = inspector.get_foreign_keys(table_name)

            schema["tables"][table_name] = {
                "columns": [
                    {
                        "name": column["name"],
                        "type": str(column["type"]),
                        "nullable": bool(column.get("nullable", True)),
                        "primary_key": column["name"]
                        in (pk_info.get("constrained_columns") or []),
                    }
                    for column in columns
                ],
                "primary_key": pk_info.get("constrained_columns") or [],
                "foreign_keys": [
                    {
                        "columns": fk.get("constrained_columns") or [],
                        "referred_table": fk.get("referred_table"),
                        "referred_columns": fk.get("referred_columns") or [],
                    }
                    for fk in foreign_keys
                ],
            }

        return json.dumps(schema, separators=(",", ":"))

    def execute_query(self, sql_query: str) -> list[dict[str, Any]] | str:
        """Execute a validated read-only SQL query and return rows as dictionaries."""
        normalized_query = " ".join(sql_query.lower().strip().split())
        if not normalized_query.startswith(("select", "with")) or _MUTATION_PATTERN.search(
            normalized_query
        ):
            raise ValueError(READ_ONLY_ERROR)

        try:
            with self.engine.connect() as connection:
                result = connection.execute(text(sql_query))
                return [dict(row) for row in result.mappings().all()]
        except SQLAlchemyError as exc:
            return f"Database Error: {exc}"
