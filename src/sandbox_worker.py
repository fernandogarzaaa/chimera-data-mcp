"""Out-of-process worker for ``run_python_analytics``.

The parent (``sandbox.AnalyticsSandbox``) starts this file with
``python -I sandbox_worker.py``, writes one JSON request to stdin and reads
one JSON response from stdout. This module is deliberately self-contained
(stdlib + pandas + numpy only) so it can run in isolated mode without the
project on ``sys.path``.

Defence in depth, outermost first:

1. Separate process with an empty environment (no DATABASE_URL, no API keys)
   and a throwaway working directory; the parent enforces a wall-clock timeout.
2. Resource limits (POSIX): CPU seconds, address space, max file size 0,
   no new processes, and no free file descriptors (every fd >= 3 is closed
   and RLIMIT_NOFILE is set to 3), so ``open()``, sockets and ``pd.read_*`` /
   ``to_*`` fail at the kernel level even if Python-level checks are bypassed.
3. A ``sys.addaudithook`` hook (cannot be removed once installed) that
   rejects file opens, process creation, sockets, ctypes, unpickling and new
   imports after setup.
4. The user code only sees allow-listed facades of pandas/numpy (no
   ``pd.read_*``, ``np.load``/``np.save``/``np.fromfile``, ``pd.io`` ...), a
   tiny builtins table, and an AST check that rejects imports, dunder and
   private attributes, frame/traceback introspection attributes, and any
   IO-style attribute such as ``to_csv`` / ``to_pickle`` / ``tofile``.
"""

from __future__ import annotations

import ast
import io
import json
import os
import re
import signal
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from typing import Any

# Keep native thread pools small: they reserve address space and would
# fight the RLIMIT_AS limit below.
for _var in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_MAX_THREADS"):
    os.environ.setdefault(_var, "1")

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

# Pre-import pandas/numpy submodules that common analytics touch lazily, so
# they are loaded before file access is cut off.
def _warm_up() -> None:
    df = pd.DataFrame({"a": [1, 2, 3], "c": [1.5, 2.5, 3.5], "b": ["x", "y", "x"], "d": ["2024-01-01"] * 3})
    steps = (
        lambda: df.describe(include="all"),
        lambda: df.groupby("b")[["a", "c"]].agg(["sum", "mean", "count", "std"]),
        lambda: df.pivot_table(index="b", values="a", aggfunc="sum"),
        lambda: pd.to_datetime(df["d"]).dt.month,
        lambda: df["a"].rolling(2).mean(),
        lambda: df.query("a > 1"),
        lambda: df["b"].str.upper(),
        lambda: df.merge(df, on="a"),
        lambda: pd.concat([df, df]),
        lambda: pd.cut(df["a"], 2),
        lambda: df.corr(numeric_only=True),
        lambda: df.to_dict(orient="records"),
        lambda: df.to_string(),
        lambda: df.sort_values("a").head(),
        lambda: df.value_counts(),
        lambda: np.percentile(np.arange(10), 50),
        lambda: np.random.default_rng(0).normal(size=3),
        lambda: np.linalg.norm(np.ones(3)),
        lambda: repr(df),
    )
    for step in steps:
        try:
            step()
        except Exception:  # noqa: BLE001,S112 - warm-up is best effort
            continue

SAFE_BUILTINS: dict[str, Any] = {
    name: getattr(__builtins__, name) if not isinstance(__builtins__, dict) else __builtins__[name]
    for name in (
        "abs", "all", "any", "bool", "dict", "enumerate", "filter", "float", "int",
        "len", "list", "map", "max", "min", "print", "range", "round", "set",
        "sorted", "str", "sum", "tuple", "zip", "reversed", "isinstance",
        "ValueError", "TypeError", "KeyError", "IndexError", "ZeroDivisionError",
        "Exception", "True", "False", "None",
    )
    if (name in __builtins__ if isinstance(__builtins__, dict) else hasattr(__builtins__, name))
}

DANGEROUS_NAMES = {
    "__import__", "eval", "exec", "open", "compile", "globals", "locals",
    "getattr", "setattr", "delattr", "vars", "help", "type", "object",
    "breakpoint", "input", "memoryview", "super", "classmethod", "staticmethod",
    "property", "dir",
}

# Attribute names that perform file/network IO, (de)serialise pickles, or
# expose interpreter internals (frames, code objects, module globals).
_SAFE_TO_METHODS = {
    "to_dict", "to_list", "to_numpy", "to_records", "to_frame", "to_datetime",
    "to_numeric", "to_timedelta", "to_period", "to_timestamp", "to_pydatetime",
    "to_series", "to_flat_index", "to_string", "to_offset",
}
_BLOCKED_ATTR_NAMES = {
    "tofile", "fromfile", "dump", "dumps", "load", "loads", "save", "savez",
    "savez_compressed", "savetxt", "loadtxt", "genfromtxt", "memmap", "fromregex",
    "DataSource", "ctypes", "ctypeslib", "lib", "io", "api", "plot", "plotting",
    "style", "eval", "pipe", "testing", "compat", "core", "errors", "options",
    "set_option", "f2py", "show_config", "system", "popen", "spawn", "fork",
    "environ", "modules", "builtins",
}
_BLOCKED_ATTR_PREFIX = re.compile(r"^(_|read_|gi_|cr_|ag_|f_|tb_|co_|func_|im_)")


def blocked_attribute(attr: str) -> bool:
    if attr in _BLOCKED_ATTR_NAMES or _BLOCKED_ATTR_PREFIX.match(attr):
        return True
    if attr.startswith("to_") and attr not in _SAFE_TO_METHODS:
        return True
    return False


class SandboxViolation(Exception):
    """Raised for code rejected by the sandbox policy (message is client-safe)."""


def validate(python_code: str) -> None:
    tree = ast.parse(python_code, mode="exec")
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)):
            raise SandboxViolation("Unsafe Python code detected: import/global statements are not allowed.")
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__"):
                raise SandboxViolation("Unsafe Python code detected: dunder attribute access is not allowed.")
            if blocked_attribute(node.attr):
                raise SandboxViolation(
                    f"Unsafe Python code detected: attribute '{node.attr}' is not allowed "
                    "(file/network IO, serialisation and interpreter internals are disabled)."
                )
        if isinstance(node, ast.Name) and node.id in DANGEROUS_NAMES:
            raise SandboxViolation(f"Unsafe Python code detected: use of '{node.id}' is not allowed.")


class _Facade:
    """Read-only, allow-listed view of a module."""

    __slots__ = ("_name", "_attrs")

    def __init__(self, name: str, module: Any, names: list[str], extra: dict[str, Any] | None = None) -> None:
        attrs = {n: getattr(module, n) for n in names if hasattr(module, n)}
        attrs.update(extra or {})
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_attrs", attrs)

    def __getattr__(self, item: str) -> Any:
        attrs = object.__getattribute__(self, "_attrs")
        if item in attrs:
            return attrs[item]
        raise AttributeError(f"'{object.__getattribute__(self, '_name')}.{item}' is not available in the sandbox")

    def __setattr__(self, key: str, value: Any) -> None:
        raise AttributeError("sandbox modules are read-only")

    def __repr__(self) -> str:
        return f"<sandbox module {object.__getattribute__(self, '_name')}>"


PD_NAMES = [
    "DataFrame", "Series", "Index", "MultiIndex", "RangeIndex", "DatetimeIndex",
    "Categorical", "CategoricalDtype", "Timestamp", "Timedelta", "Period", "Interval",
    "DateOffset", "Grouper", "IndexSlice", "NA", "NaT", "concat", "merge", "merge_asof",
    "merge_ordered", "pivot", "pivot_table", "melt", "wide_to_long", "crosstab", "cut",
    "qcut", "get_dummies", "from_dummies", "factorize", "unique", "isna", "isnull",
    "notna", "notnull", "to_datetime", "to_numeric", "to_timedelta", "date_range",
    "bdate_range", "period_range", "timedelta_range", "interval_range", "json_normalize",
    "Int64Dtype", "Float64Dtype", "StringDtype", "BooleanDtype",
]
NP_NAMES = [
    "array", "asarray", "arange", "linspace", "logspace", "zeros", "ones", "full",
    "zeros_like", "ones_like", "full_like", "eye", "identity", "mean", "average",
    "median", "std", "var", "sum", "prod", "min", "max", "amin", "amax", "ptp",
    "argmin", "argmax", "argsort", "sort", "unique", "cumsum", "cumprod", "diff",
    "gradient", "round", "around", "abs", "absolute", "sqrt", "square", "exp", "log",
    "log10", "log2", "log1p", "expm1", "power", "clip", "where", "select", "percentile",
    "quantile", "nanpercentile", "nanquantile", "isnan", "isinf", "isfinite",
    "nanmean", "nanmedian", "nanstd", "nanvar", "nansum", "nanmin", "nanmax",
    "nanargmin", "nanargmax", "corrcoef", "cov", "histogram", "bincount", "digitize",
    "floor", "ceil", "trunc", "sign", "maximum", "minimum", "fmax", "fmin", "mod",
    "concatenate", "stack", "vstack", "hstack", "column_stack", "split", "reshape",
    "ravel", "transpose", "dot", "matmul", "outer", "inner", "cross", "einsum",
    "polyfit", "polyval", "interp", "convolve", "count_nonzero", "nonzero",
    "searchsorted", "in1d", "isin", "intersect1d", "union1d", "setdiff1d", "tile",
    "repeat", "flip", "roll", "allclose", "isclose", "array_equal", "nan", "inf", "pi",
    "e", "newaxis", "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32",
    "uint64", "float16", "float32", "float64", "bool_", "str_", "datetime64",
    "timedelta64", "dtype", "ndarray", "sin", "cos", "tan", "arcsin", "arccos",
    "arctan", "arctan2", "sinh", "cosh", "tanh", "deg2rad", "rad2deg", "floor_divide",
    "true_divide", "divide", "multiply", "add", "subtract", "negative", "reciprocal",
    "any", "all", "logical_and", "logical_or", "logical_not", "logical_xor",
]
NP_RANDOM_NAMES = ["default_rng", "Generator", "PCG64"]
NP_LINALG_NAMES = ["norm", "inv", "pinv", "det", "solve", "lstsq", "eig", "eigh", "eigvals", "svd", "qr", "matrix_rank", "cholesky"]


def make_namespace(raw_data: list[dict[str, Any]]) -> dict[str, Any]:
    np_facade = _Facade(
        "np",
        np,
        NP_NAMES,
        {
            "random": _Facade("np.random", np.random, NP_RANDOM_NAMES),
            "linalg": _Facade("np.linalg", np.linalg, NP_LINALG_NAMES),
        },
    )
    return {"pd": _Facade("pd", pd, PD_NAMES), "np": np_facade, "df": pd.DataFrame(raw_data)}


# --------------------------------------------------------------------------
# Lockdown
# --------------------------------------------------------------------------

_LOCKED = False
_ALLOWED_CODE: Any = None  # the analyst's compiled code object (one exec allowed)
_BLOCKED_EVENT_PREFIXES = (
    "open", "os.", "subprocess.", "socket.", "ctypes.", "shutil.", "pty.", "fcntl.",
    "mmap.", "import", "pickle.", "marshal.", "code.",
    "sys.setprofile", "sys.settrace", "urllib.", "http.", "ftplib.", "smtplib.",
    "webbrowser.", "winreg.", "msvcrt.", "_winapi.", "glob.", "tempfile.", "sqlite3.",
    "builtins.input", "cpython.run_", "function.__new__", "object.__setattr__",
    "object.__delattr__", "sys.addaudithook", "resource.setrlimit",
)
_ALLOWED_EVENTS = {"os.listdir"}  # nothing currently relies on this; kept explicit


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    if not _LOCKED:
        return
    if event in _ALLOWED_EVENTS:
        return
    if event == "exec" and args and args[0] is _ALLOWED_CODE:
        return
    if event == "exec":
        # Only the analyst's own (pre-validated) code object may run; any
        # nested eval/exec of another code object is refused. Plain
        # ``compile`` (e.g. ast.parse inside DataFrame.query) is harmless on
        # its own because running the result needs exec.
        raise PermissionError(f"sandbox: '{event}' is not permitted")
    if event.startswith(_BLOCKED_EVENT_PREFIXES):
        raise PermissionError(f"sandbox: operation '{event}' is not permitted")


def _apply_resource_limits(cpu_seconds: int, memory_mb: int) -> None:
    try:
        import resource
    except ImportError:  # pragma: no cover - non-POSIX
        return

    def _set(limit: int, value: int) -> None:
        try:
            soft, hard = resource.getrlimit(limit)
            if hard != resource.RLIM_INFINITY:
                value = min(value, hard)
            resource.setrlimit(limit, (value, value))
        except (ValueError, OSError):
            pass

    used = resource.getrusage(resource.RUSAGE_SELF)
    _set(resource.RLIMIT_CPU, int(used.ru_utime + used.ru_stime) + cpu_seconds + 1)
    if memory_mb > 0:
        current_vm = 0
        try:
            with open("/proc/self/status", encoding="ascii") as fh:
                for line in fh:
                    if line.startswith("VmSize:"):
                        current_vm = int(line.split()[1]) * 1024
                        break
        except OSError:
            pass
        _set(resource.RLIMIT_AS, current_vm + memory_mb * 1024 * 1024)
    _set(resource.RLIMIT_FSIZE, 0)
    if hasattr(resource, "RLIMIT_NPROC"):
        _set(resource.RLIMIT_NPROC, 0)
    if hasattr(resource, "RLIMIT_CORE"):
        _set(resource.RLIMIT_CORE, 0)
    # No free file descriptors: close everything above stdio, then cap.
    try:
        os.closerange(3, 65536)
    except OSError:
        pass
    _set(resource.RLIMIT_NOFILE, 3)


def _collect_state_changes(local_env: dict[str, Any], initial_state: dict[str, str]) -> dict[str, str]:
    state_changes: dict[str, str] = {}
    for key, value in local_env.items():
        if key.startswith("__"):
            continue
        current_repr = repr(value)
        if key not in initial_state or initial_state[key] != current_repr:
            state_changes[key] = current_repr
    return state_changes


def _timeout_handler(signum: int, frame: Any) -> None:
    raise TimeoutError("Sandbox execution exceeded the time limit.")


def main() -> int:
    global _LOCKED, _ALLOWED_CODE
    request = json.loads(sys.stdin.read())
    _warm_up()
    code: str = request["code"]
    raw_data: list[dict[str, Any]] = request.get("raw_data") or []
    timeout = float(request.get("timeout", 2.0))
    memory_mb = int(request.get("memory_mb", 512))

    real_stdout = sys.stdout
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    local_env: dict[str, Any] = {}
    initial_state: dict[str, str] = {}
    success = False
    try:
        validate(code)
        compiled = compile(code, "<analysis>", "exec")
        _ALLOWED_CODE = compiled
        local_env = make_namespace(raw_data)
        initial_state = {k: repr(v) for k, v in local_env.items()}

        sys.addaudithook(_audit_hook)
        _apply_resource_limits(cpu_seconds=max(1, int(timeout + 0.999)), memory_mb=memory_mb)
        if hasattr(signal, "setitimer"):
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.setitimer(signal.ITIMER_REAL, timeout)
        _LOCKED = True
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            exec(compiled, {"__builtins__": SAFE_BUILTINS}, local_env)  # noqa: S102 - sandboxed
        if hasattr(signal, "setitimer"):
            signal.setitimer(signal.ITIMER_REAL, 0)
        success = True
    except SandboxViolation as exc:
        stderr_buffer.write(f"ClientSafeError: {exc}")
    except MemoryError:
        stderr_buffer.write("MemoryError: sandbox memory limit exceeded")
    except BaseException as exc:  # noqa: BLE001 - report analyst errors as one line
        if hasattr(signal, "setitimer"):
            signal.setitimer(signal.ITIMER_REAL, 0)
        stderr_buffer.write(f"{type(exc).__name__}: {exc}")

    try:
        state = json.dumps(_collect_state_changes(local_env, initial_state), default=str)
    except BaseException as exc:  # noqa: BLE001
        state = json.dumps({"_error": f"could not serialise state: {type(exc).__name__}"})
    real_stdout.write(
        json.dumps(
            {
                "success": success,
                "stdout": stdout_buffer.getvalue(),
                "stderr": stderr_buffer.getvalue(),
                "local_state": state,
            }
        )
    )
    real_stdout.flush()
    return 0


if __name__ == "__main__":
    start = time.monotonic()
    sys.exit(main())
