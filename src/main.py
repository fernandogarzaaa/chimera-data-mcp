"""MCP server entrypoint for the Chimera Enterprise Data Analyst."""

from __future__ import annotations

import traceback
from typing import Any

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

try:
    from .database import DatabaseManager
    from .sandbox import AnalyticsSandbox
except ImportError:
    from database import DatabaseManager
    from sandbox import AnalyticsSandbox

load_dotenv()

server = FastMCP("Chimera-Enterprise-Data-Analyst")
database_manager = DatabaseManager()
analytics_sandbox = AnalyticsSandbox()


class QueryRequest(BaseModel):
    """Validated input for read-only SQL execution."""

    sql_query: str = Field(min_length=1)


class PythonAnalyticsRequest(BaseModel):
    """Validated input for Python analytics execution."""

    python_code: str = Field(min_length=1)
    data_context: list[dict[str, Any]]


@server.tool()
def get_schema_layout() -> str:
    """Call this first to inspect available business schemas without returning data rows."""
    try:
        return database_manager.get_schema_layout()
    except Exception:
        return f"Schema Inspection Error:\n{traceback.format_exc()}"


@server.tool()
def execute_readonly_query(sql_query: str) -> list[dict[str, Any]] | str:
    """Execute read-only SQL (`SELECT`/`WITH`) against the active data lake."""
    try:
        validated = QueryRequest(sql_query=sql_query)
        return database_manager.execute_query(validated.sql_query)
    except Exception:
        return f"Query Execution Error:\n{traceback.format_exc()}"


@server.tool()
def run_python_analytics(python_code: str, data_context: list[dict[str, Any]]) -> dict[str, Any]:
    """Run pandas analytics where `data_context` is auto-injected as DataFrame `df`."""
    try:
        validated = PythonAnalyticsRequest(
            python_code=python_code,
            data_context=data_context,
        )
        return analytics_sandbox.execute_analysis(
            validated.python_code,
            validated.data_context,
        )
    except Exception:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Analytics Tool Error:\n{traceback.format_exc()}",
            "local_state": "{}",
        }


if __name__ == "__main__":
    server.run(transport="stdio")
