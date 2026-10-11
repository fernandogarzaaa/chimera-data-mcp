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


def test_tool_errors_do_not_leak_tracebacks(tmp_path, monkeypatch):
    """Unexpected tool failures return a generic one-line error (logged
    server-side), never a stack trace or raw message that could embed server
    filesystem paths. Deliberate ClientSafeError messages still pass through."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    main = importlib.import_module("main")
    from errors import ClientSafeError

    def _run():
        # unexpected failures: generic message, no leak
        monkeypatch.setattr(
            main.database_manager, "get_schema_layout",
            lambda: (_ for _ in ()).throw(RuntimeError("boom-schema")),
        )
        out = main.get_schema_layout()
        assert "boom-schema" not in out and "Traceback" not in out and "/home/" not in out
        assert "an unexpected error occurred" in out

        monkeypatch.setattr(
            main.database_manager, "execute_query",
            lambda q: (_ for _ in ()).throw(RuntimeError("boom-query")),
        )
        err = json.loads(main.execute_readonly_query("SELECT 1"))
        assert "boom-query" not in err["error"] and "Traceback" not in err["error"]

        monkeypatch.setattr(
            main.analytics_sandbox, "execute_analysis",
            lambda code, ctx: (_ for _ in ()).throw(RuntimeError("boom-sandbox")),
        )
        res = main.run_python_analytics("1+1", [])
        assert res["success"] is False
        assert "boom-sandbox" not in res["stderr"] and "Traceback" not in res["stderr"]

        # deliberate client-safe errors: message passes through
        monkeypatch.setattr(
            main.database_manager, "execute_query",
            lambda q: (_ for _ in ()).throw(ClientSafeError("deliberate-safe-message")),
        )
        err = json.loads(main.execute_readonly_query("SELECT 1"))
        assert "deliberate-safe-message" in err["error"]

    _run()


def test_failed_sql_query_returns_no_traceback(db):
    """A SQL execution failure (not just a wrapper failure) reaches the
    client as a generic error: DatabaseManager no longer returns
    traceback.format_exc() strings."""
    main = importlib.import_module("main")
    err = json.loads(main.execute_readonly_query("SELECT * FROM no_such_table_xyz"))
    assert "Traceback" not in err["error"] and "/home/" not in err["error"]
    assert "an unexpected error occurred" in err["error"]


def test_mutation_refusal_message_reaches_client(db):
    """The deliberate security-violation refusal is client-safe and keeps its message."""
    main = importlib.import_module("main")
    err = json.loads(main.execute_readonly_query("DROP TABLE sales_performance"))
    assert "Security Violation" in err["error"]
