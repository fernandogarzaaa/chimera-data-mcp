"""Analytics sandbox: runs analyst code in a locked-down child process.

The previous in-process ``exec`` exposed the real ``pandas``/``numpy``
modules, so ``pd.read_csv('/etc/...')``, ``df.to_csv(...)`` and
``pd.read_pickle(...)`` could read/write server files or execute code.
User code now runs in ``sandbox_worker.py`` (a separate interpreter with an
empty environment, resource limits, no free file descriptors, an audit hook
and allow-listed pandas/numpy facades). See that module for the layers.

The AST policy check also runs here, in the parent, so obviously unsafe
code is rejected without starting a process.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from errors import ClientSafeError

_WORKER = Path(__file__).resolve().with_name("sandbox_worker.py")

MAX_EXECUTION_SECONDS = float(os.getenv("SANDBOX_TIMEOUT_SECONDS", "2.0"))
MAX_MEMORY_MB = int(os.getenv("SANDBOX_MAX_MEMORY_MB", "512"))
# Worker start-up (interpreter + pandas import) is not charged to the analyst.
STARTUP_ALLOWANCE_SECONDS = float(os.getenv("SANDBOX_STARTUP_SECONDS", "20"))
MAX_OUTPUT_BYTES = 1_000_000


def _load_policy() -> Any:
    """Import the worker module for its AST policy without running main()."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("_chimera_sandbox_policy", _WORKER)
    if spec is None or spec.loader is None:  # pragma: no cover - packaging error
        raise RuntimeError("sandbox worker missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_policy = _load_policy()
SAFE_BUILTINS = _policy.SAFE_BUILTINS
DANGEROUS_NAMES = _policy.DANGEROUS_NAMES
blocked_attribute = _policy.blocked_attribute


def _failure(stderr: str) -> dict[str, Any]:
    return {"success": False, "stdout": "", "stderr": stderr, "local_state": "{}"}


class AnalyticsSandbox:
    def _validate_python_code(self, python_code: str) -> None:
        """Reject unsafe code with a client-safe error (message is human-written)."""
        try:
            _policy.validate(python_code)
        except _policy.SandboxViolation as exc:
            raise ClientSafeError(str(exc)) from None

    def execute_analysis(self, python_code: str, raw_data: list[dict[str, Any]]) -> dict[str, Any]:
        try:
            self._validate_python_code(python_code)
        except SyntaxError as exc:
            return _failure(f"SyntaxError: {exc}")
        except ClientSafeError as exc:
            return _failure(f"ClientSafeError: {exc}")

        request = json.dumps(
            {
                "code": python_code,
                "raw_data": raw_data,
                "timeout": MAX_EXECUTION_SECONDS,
                "memory_mb": MAX_MEMORY_MB,
            },
            default=str,
        )
        # Minimal environment: no DATABASE_URL, API keys or other secrets.
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONHASHSEED": "0"}
        if sys.platform == "win32":  # pragma: no cover - needed for interpreter start
            env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
        with tempfile.TemporaryDirectory(prefix="chimera-sandbox-") as workdir:
            try:
                proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                    [sys.executable, "-I", str(_WORKER)],
                    input=request,
                    capture_output=True,
                    text=True,
                    timeout=MAX_EXECUTION_SECONDS + STARTUP_ALLOWANCE_SECONDS,
                    cwd=workdir,
                    env=env,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return _failure(
                    f"TimeoutError: Sandbox execution exceeded {MAX_EXECUTION_SECONDS:.1f} seconds timeout."
                )

        stdout = proc.stdout[:MAX_OUTPUT_BYTES]
        try:
            result = json.loads(stdout)
        except ValueError:
            # The worker died before reporting: CPU/memory limit (signal) or a
            # crash. Never forward its raw stderr (it can contain paths).
            if proc.returncode is not None and proc.returncode < 0:
                return _failure("ResourceLimitError: sandbox process was terminated (CPU or memory limit exceeded).")
            return _failure("SandboxError: sandbox process exited without a result.")
        if not isinstance(result, dict) or "success" not in result:
            return _failure("SandboxError: malformed sandbox result.")
        return {
            "success": bool(result.get("success")),
            "stdout": str(result.get("stdout", "")),
            "stderr": str(result.get("stderr", "")),
            "local_state": str(result.get("local_state", "{}")),
        }
