from __future__ import annotations

import json
import traceback
from typing import Any

from dotenv import load_dotenv
from fastmcp import FastMCP

from database import DatabaseManager
from sandbox import AnalyticsSandbox

load_dotenv()

mcp = FastMCP("Chimera-Enterprise-Data-Analyst")
database_manager = DatabaseManager()
analytics_sandbox = AnalyticsSandbox()


@mcp.tool()
def get_schema_layout() -> str:
    """
    Return the complete table-and-column layout for the active database as compact JSON.

    Use this tool first during exploration to understand all available tables, column names,
    SQL data types, nullability, and primary/foreign key flags before writing queries.
    """
    try:
        return database_manager.get_schema_layout()
    except Exception:
        return traceback.format_exc()


@mcp.tool()
def execute_readonly_query(sql_query: str) -> str:
    """
    Execute a strictly read-only SQL query and return JSON-encoded results.

    This tool accepts SQL that begins only with SELECT or WITH and blocks any mutation intent.
    On success, it returns a JSON array of row objects; on failure, it returns a JSON error object.
    """
    try:
        result = database_manager.execute_query(sql_query)
        if isinstance(result, str):
            return json.dumps({"error": result})
        return json.dumps(result, default=str)
    except Exception:
        return json.dumps({"error": traceback.format_exc()})


@mcp.tool()
def run_python_analytics(python_code: str, data_context: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Run analyst-provided Python code inside a constrained sandbox against query output.

    The input rows are provided to the sandbox as a pandas DataFrame named df,
    while pandas and numpy are preloaded as pd and np for calculation workflows.
    """
    try:
        return analytics_sandbox.execute_analysis(python_code, data_context)
    except Exception:
        return {
            "success": False,
            "stdout": "",
            "stderr": traceback.format_exc(),
            "local_state": "{}",
        }


if __name__ == "__main__":
    mcp.run()
