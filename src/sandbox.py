from __future__ import annotations

import io
import json
import traceback
from contextlib import redirect_stderr, redirect_stdout
from typing import Any

import numpy as np
import pandas as pd


SAFE_BUILTINS: dict[str, Any] = {
    "abs": abs,
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "enumerate": enumerate,
    "filter": filter,
    "float": float,
    "int": int,
    "len": len,
    "list": list,
    "map": map,
    "max": max,
    "min": min,
    "print": print,
    "range": range,
    "round": round,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
}


class AnalyticsSandbox:
    def execute_analysis(self, python_code: str, raw_data: list[dict[str, Any]]) -> dict[str, Any]:
        df = pd.DataFrame(raw_data)
        local_env: dict[str, Any] = {"pd": pd, "np": np, "df": df}
        initial_state: dict[str, str] = {
            key: repr(value)
            for key, value in local_env.items()
        }

        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        try:
            with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                exec(python_code, {"__builtins__": SAFE_BUILTINS}, local_env)

            state_changes: dict[str, str] = {}
            for key, value in local_env.items():
                if key.startswith("__"):
                    continue
                current_repr = repr(value)
                if key not in initial_state or initial_state[key] != current_repr:
                    state_changes[key] = current_repr

            return {
                "success": True,
                "stdout": stdout_buffer.getvalue(),
                "stderr": stderr_buffer.getvalue(),
                "local_state": json.dumps(state_changes, default=str),
            }
        except Exception:
            stderr_buffer.write(traceback.format_exc())
            state_changes = {}
            for key, value in local_env.items():
                if key.startswith("__"):
                    continue
                current_repr = repr(value)
                if key not in initial_state or initial_state[key] != current_repr:
                    state_changes[key] = current_repr

            return {
                "success": False,
                "stdout": stdout_buffer.getvalue(),
                "stderr": stderr_buffer.getvalue(),
                "local_state": json.dumps(state_changes, default=str),
            }
