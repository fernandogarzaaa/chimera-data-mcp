"""Isolated execution sandbox for pandas-based analytics code."""

from __future__ import annotations

import io
import sys
import traceback
from typing import Any

import numpy as np
import pandas as pd


class AnalyticsSandbox:
    """Executes analyst-authored Python snippets in a constrained local namespace."""

    def execute_analysis(self, python_code: str, raw_data: list[dict[str, Any]]) -> dict[str, Any]:
        """Run python analysis code with a pre-injected DataFrame named ``df``."""
        df = pd.DataFrame(raw_data)
        local_env: dict[str, Any] = {"pd": pd, "np": np, "df": df}
        initial_keys = set(local_env.keys())

        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()

        original_stdout = sys.stdout
        original_stderr = sys.stderr
        try:
            sys.stdout = stdout_buffer
            sys.stderr = stderr_buffer
            exec(python_code, {"__builtins__": __builtins__}, local_env)

            created_or_mutated = {
                key: repr(value)
                for key, value in local_env.items()
                if key not in initial_keys and not key.startswith("__")
            }
            return {
                "success": True,
                "stdout": stdout_buffer.getvalue(),
                "stderr": stderr_buffer.getvalue(),
                "local_state": repr(created_or_mutated),
            }
        except Exception:
            stderr_buffer.write(traceback.format_exc())
            created_or_mutated = {
                key: repr(value)
                for key, value in local_env.items()
                if key not in initial_keys and not key.startswith("__")
            }
            return {
                "success": False,
                "stdout": stdout_buffer.getvalue(),
                "stderr": stderr_buffer.getvalue(),
                "local_state": repr(created_or_mutated),
            }
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
