from __future__ import annotations

import json
import os
import re
import traceback
from pathlib import Path
from typing import Any

from sqlalchemy import Column, Float, Integer, MetaData, String, Table, create_engine, inspect, text


DEFAULT_DATABASE_URL = "sqlite:///./retail_supply_chain.db"
SECURITY_VIOLATION_MESSAGE = "Security Violation: Unauthorized data mutation attempt detected. Only read-only SELECT operations are authorized."
COMMENT_PATTERN = re.compile(r"(--[^\n]*$)|(/\*.*?\*/)", re.MULTILINE | re.DOTALL)
MUTATION_PATTERN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|GRANT)\b",
    re.IGNORECASE,
)
ENTRYPOINT_PATTERN = re.compile(r"^(SELECT|WITH)\b", re.IGNORECASE)


class DatabaseManager:
    def __init__(self) -> None:
        configured_url = os.getenv("DATABASE_URL", "").strip()
        self.database_url = configured_url or DEFAULT_DATABASE_URL
        self.engine = create_engine(self.database_url, future=True)

        if self.database_url == DEFAULT_DATABASE_URL:
            sqlite_path = Path("./retail_supply_chain.db")
            if not sqlite_path.exists():
                self._bootstrap_default_database(sqlite_path)

    def _bootstrap_default_database(self, sqlite_path: Path) -> None:
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        metadata = MetaData()

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

        metadata.create_all(self.engine)

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

        with self.engine.begin() as connection:
            connection.execute(sales_performance.insert(), sales_rows)
            connection.execute(inventory_status.insert(), inventory_rows)

    def get_schema_layout(self) -> str:
        inspector = inspect(self.engine)
        schema_map: dict[str, list[dict[str, Any]]] = {}

        for table_name in inspector.get_table_names():
            columns = inspector.get_columns(table_name)
            primary_key_columns = set((inspector.get_pk_constraint(table_name) or {}).get("constrained_columns") or [])
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

    def execute_query(self, sql_query: str) -> list[dict[str, Any]] | str:
        cleaned_query = COMMENT_PATTERN.sub(" ", sql_query).strip()

        if not ENTRYPOINT_PATTERN.match(cleaned_query):
            raise ValueError(SECURITY_VIOLATION_MESSAGE)

        if MUTATION_PATTERN.search(cleaned_query):
            raise ValueError(SECURITY_VIOLATION_MESSAGE)

        try:
            with self.engine.connect() as connection:
                result = connection.execute(text(cleaned_query))
                return [dict(row) for row in result.mappings().all()]
        except Exception:
            return traceback.format_exc()
