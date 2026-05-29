from __future__ import annotations

import ast
import io
import json
import sys
import time
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

DANGEROUS_NAMES = {
    "__import__",
    "eval",
    "exec",
    "open",
    "compile",
    "globals",
    "locals",
    "getattr",
    "setattr",
    "delattr",
    "vars",
    "help",
    "type",
    "object",
}
MAX_EXECUTION_SECONDS = 2.0


class AnalyticsSandbox:
    def _validate_python_code(self, python_code: str) -> None:
        tree = ast.parse(python_code, mode="exec")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)):
                raise ValueError("Unsafe Python code detected: import/global statements are not allowed.")
            if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
                raise ValueError("Unsafe Python code detected: dunder attribute access is not allowed.")
            if isinstance(node, ast.Name) and node.id in DANGEROUS_NAMES:
                raise ValueError(f"Unsafe Python code detected: use of '{node.id}' is not allowed.")

    def _timeout_tracer(self, start_time: float) -> Any:
        def tracer(frame: Any, event: str, arg: Any) -> Any:
            if event == "line" and (time.monotonic() - start_time) > MAX_EXECUTION_SECONDS:
                raise TimeoutError(
                    f"Sandbox execution exceeded {MAX_EXECUTION_SECONDS:.1f} seconds timeout."
                )
            return tracer

        return tracer

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
            self._validate_python_code(python_code)
            with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                start_time = time.monotonic()
                sys.settrace(self._timeout_tracer(start_time))
                exec(python_code, {"__builtins__": SAFE_BUILTINS}, local_env)
                sys.settrace(None)

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
        finally:
            sys.settrace(None)
