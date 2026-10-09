"""Smoke tests for the database, sandbox and MCP server modules."""

import importlib
import json

import pytest


@pytest.fixture()
def db(tmp_path, monkeypatch):
    # DatabaseManager bootstraps ./retail_supply_chain.db in the CWD by default.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    from database import DatabaseManager

    return DatabaseManager()


def test_default_database_bootstraps_schema(db):
    schema = json.loads(db.get_schema_layout())
    assert {"sales_performance", "inventory_status"} <= set(schema)


def test_readonly_select_returns_rows(db):
    rows = db.execute_query("SELECT COUNT(*) AS n FROM sales_performance")
    assert isinstance(rows, list)
    assert rows[0]["n"] > 0


@pytest.mark.parametrize(
    "sql",
    ["DELETE FROM sales_performance", "SELECT 1; DROP TABLE sales_performance"],
)
def test_mutations_are_rejected(db, sql):
    with pytest.raises(ValueError):
        db.execute_query(sql)


def test_sandbox_runs_pandas_analysis():
    from sandbox import AnalyticsSandbox

    result = AnalyticsSandbox().execute_analysis(
        "total = int(df['x'].sum())\nprint(total)", [{"x": 1}, {"x": 2}]
    )
    assert result["success"] is True
    assert result["stdout"].strip() == "3"


def test_sandbox_blocks_imports():
    from sandbox import AnalyticsSandbox

    result = AnalyticsSandbox().execute_analysis("import os", [])
    assert result["success"] is False


def test_server_module_imports(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    main = importlib.import_module("main")
    assert main.mcp is not None
