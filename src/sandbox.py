"""Isolated execution sandbox for pandas-based analytics code."""

from __future__ import annotations

import io
import sys
import traceback
from typing import Any

import numpy as np
import pandas as pd

_SAFE_BUILTINS = {
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
    """Executes analyst-authored Python snippets in a constrained local namespace."""

    @staticmethod
    def _safe_repr(value: Any, max_chars: int = 400) -> str:
        """Render objects with bounded size to keep response payloads compact."""
        rendered = repr(value)
        if len(rendered) > max_chars:
            return f"{rendered[:max_chars]}...<truncated>"
        return rendered

    @staticmethod
    def _df_state(current_df: Any, original_df: pd.DataFrame) -> tuple[bool, tuple[int, int] | str]:
        """Report whether df changed and capture a safe shape descriptor."""
        if not isinstance(current_df, pd.DataFrame):
            return True, "df_not_dataframe"
        return (not current_df.equals(original_df), tuple(current_df.shape))

    def execute_analysis(self, python_code: str, raw_data: list[dict[str, Any]]) -> dict[str, Any]:
        """Run python analysis code with a pre-injected DataFrame named ``df``."""
        df = pd.DataFrame(raw_data)
        df_before = df.copy(deep=True)
        local_env: dict[str, Any] = {"pd": pd, "np": np, "df": df}
        initial_keys = set(local_env.keys())

        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        original_stdout = sys.stdout
        original_stderr = sys.stderr
        try:
            sys.stdout = stdout_buffer
            sys.stderr = stderr_buffer
            exec(python_code, {"__builtins__": _SAFE_BUILTINS}, local_env)

            created_or_mutated = {
                key: self._safe_repr(value)
                for key, value in local_env.items()
                if key not in initial_keys and not key.startswith("__")
            }
            df_changed, df_shape = self._df_state(local_env.get("df"), df_before)
            created_or_mutated["df_changed"] = df_changed
            created_or_mutated["df_shape"] = df_shape

            return {
                "success": True,
                "stdout": stdout_buffer.getvalue(),
                "stderr": stderr_buffer.getvalue(),
                "local_state": self._safe_repr(created_or_mutated),
            }
        except Exception:
            stderr_buffer.write(traceback.format_exc())
            created_or_mutated = {
                key: self._safe_repr(value)
                for key, value in local_env.items()
                if key not in initial_keys and not key.startswith("__")
            }
            df_changed, df_shape = self._df_state(local_env.get("df"), df_before)
            created_or_mutated["df_changed"] = df_changed
            created_or_mutated["df_shape"] = df_shape
            return {
                "success": False,
                "stdout": stdout_buffer.getvalue(),
                "stderr": stderr_buffer.getvalue(),
                "local_state": self._safe_repr(created_or_mutated),
            }
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
