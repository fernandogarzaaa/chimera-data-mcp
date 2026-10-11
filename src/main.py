from __future__ import annotations

import json
import logging
from typing import Any

from dotenv import load_dotenv
from fastmcp import FastMCP

from database import DatabaseManager
from errors import ClientSafeError
from sandbox import AnalyticsSandbox

load_dotenv()

logger = logging.getLogger(__name__)

mcp = FastMCP("Chimera-Enterprise-Data-Analyst")
database_manager = DatabaseManager()
analytics_sandbox = AnalyticsSandbox()


def _safe_error(exc: BaseException) -> str:
    """Client-safe one-line error for MCP clients.

    Deliberate ClientSafeError messages are human-written and pass through.
    Unexpected exceptions are logged server-side with their full traceback
    and replaced with a generic message: a raw exception message can embed
    server filesystem paths just as a stack trace can.
    """
    if isinstance(exc, ClientSafeError):
        return f"{type(exc).__name__}: {exc}"
    logger.exception("unexpected tool failure")
    return f"{type(exc).__name__}: an unexpected error occurred"


@mcp.tool()
def get_schema_layout() -> str:
    """
    Return the complete table-and-column layout for the active database as compact JSON.

    Use this tool first during exploration to understand all available tables, column names,
    SQL data types, nullability, and primary/foreign key flags before writing queries.
    """
    try:
        return database_manager.get_schema_layout()
    except Exception as exc:
        return _safe_error(exc)


@mcp.tool()
def execute_readonly_query(sql_query: str) -> str:
    """
    Execute a strictly read-only SQL query and return JSON-encoded results.

    This tool accepts SQL that begins only with SELECT or WITH and blocks any mutation intent.
    On success, it returns a JSON array of row objects; on failure, it returns a JSON error object.
    """
    try:
        result = database_manager.execute_query(sql_query)
        return json.dumps(result, default=str)
    except Exception as exc:
        return json.dumps({"error": _safe_error(exc)})


@mcp.tool()
def run_python_analytics(python_code: str, data_context: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Run analyst-provided Python code inside a constrained sandbox against query output.

    The input rows are provided to the sandbox as a pandas DataFrame named df,
    while pandas and numpy are preloaded as pd and np for calculation workflows.
    """
    try:
        return analytics_sandbox.execute_analysis(python_code, data_context)
    except Exception as exc:
        return {
            "success": False,
            "stdout": "",
            "stderr": _safe_error(exc),
            "local_state": "{}",
        }


if __name__ == "__main__":
    mcp.run()
