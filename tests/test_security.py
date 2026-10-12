"""Adversarial tests: sandbox escapes and SQL write attempts must fail.

These reproduce the escapes from the Oct 2026 audit (pandas/numpy file IO,
read_pickle) and check each defence layer separately.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import sqlalchemy

ROWS = [{"x": 1, "k": "a"}, {"x": 2, "k": "b"}, {"x": 3, "k": "a"}]
WORKER = Path(__file__).resolve().parent.parent / "src" / "sandbox_worker.py"


@pytest.fixture(scope="module")
def sandbox():
    from sandbox import AnalyticsSandbox

    return AnalyticsSandbox()


@pytest.fixture()
def secret_file(tmp_path):
    path = tmp_path / "secret.txt"
    path.write_text("TOP-SECRET-VALUE\n")
    return path


# ---------------------------------------------------------------- happy path


def test_common_analytics_still_work(sandbox):
    code = (
        "g = df.groupby('k')['x'].sum().to_dict()\n"
        "print(g)\n"
        "print(round(float(np.mean(df['x'])), 2))\n"
        "print(df.query('x > 1').shape[0])\n"
        "print(pd.to_datetime('2024-03-05').month)\n"
        "rng = np.random.default_rng(1)\n"
        "n = len(rng.normal(size=4))\n"
    )
    result = sandbox.execute_analysis(code, ROWS)
    assert result["success"] is True, result
    assert result["stdout"].splitlines() == ["{'a': 4, 'b': 2}", "2.0", "2", "3"]
    assert result["stderr"] == ""
    state = json.loads(result["local_state"])
    assert state["n"] == "4"
    assert "df" not in state  # unchanged variables are not reported


def test_state_changes_report_modified_df(sandbox):
    result = sandbox.execute_analysis("df['y'] = df['x'] * 2", ROWS)
    assert result["success"] is True
    assert "y" in json.loads(result["local_state"])["df"]


def test_analyst_runtime_errors_are_one_line(sandbox):
    result = sandbox.execute_analysis("x = 1\ny = 1 / 0", ROWS)
    assert result["success"] is False
    assert result["stderr"].startswith("ZeroDivisionError")
    assert "Traceback" not in result["stderr"] and "sandbox_worker" not in result["stderr"]
    assert json.loads(result["local_state"]) == {"x": "1"}


def test_syntax_error_is_reported(sandbox):
    result = sandbox.execute_analysis("def (", ROWS)
    assert result["success"] is False
    assert result["stderr"].startswith("SyntaxError")


# ------------------------------------------------- audit escapes (must fail)


@pytest.mark.parametrize(
    "code",
    [
        "data = pd.read_csv({path!r})",
        "data = pd.read_pickle({path!r})",
        "df.to_csv({path!r})",
        "df.to_pickle({path!r})",
        "df.to_json({path!r})",
        "np.load({path!r})",
        "np.save({path!r}, np.ones(2))",
        "np.fromfile({path!r})",
        "np.array([1]).tofile({path!r})",
        "x = pd.io",
        "x = np.lib",
        "x = df._mgr",
        "x = df.__class__",
        "open({path!r})",
        "import os",
        "eval('1')",
    ],
)
def test_direct_file_io_is_rejected_before_running(sandbox, secret_file, code):
    result = sandbox.execute_analysis(code.format(path=str(secret_file)), ROWS)
    assert result["success"] is False
    assert result["stderr"].startswith("ClientSafeError: Unsafe Python code detected")
    assert "TOP-SECRET" not in result["stdout"] + result["stderr"] + result["local_state"]


@pytest.mark.parametrize(
    "code",
    [
        # string-dispatched methods bypass the AST attribute check; the
        # audit hook / fd limit in the worker must stop them.
        "r = df.apply('to_pickle', path={path!r})",
        "r = df.agg('to_csv', path_or_buf={path!r})",
        "r = df['x'].agg('to_csv', {path!r})",
        "r = df.transform('to_json', path_or_buf={path!r})",
    ],
)
def test_string_dispatched_io_is_blocked_at_runtime(sandbox, tmp_path, code):
    target = tmp_path / "written.out"
    result = sandbox.execute_analysis(code.format(path=str(target)), ROWS)
    assert result["success"] is False
    assert not target.exists()


def test_audit_hook_is_active_in_worker(sandbox, tmp_path):
    # String dispatch reaches DataFrame.to_pickle -> open(); the audit hook
    # must refuse it (PermissionError) before the fd limit (OSError) is hit.
    target = tmp_path / "p.pkl"
    result = sandbox.execute_analysis(f"df.apply('to_pickle', path={str(target)!r})", ROWS)
    assert result["stderr"].startswith("PermissionError: sandbox: operation 'open'"), result["stderr"]
    assert not target.exists()


def test_worker_enforces_policy_on_its_own():
    # The worker must not rely on the parent having validated the code.
    req = json.dumps({"code": "df.to_csv('x.csv')", "raw_data": ROWS})
    proc = subprocess.run([sys.executable, "-I", str(WORKER)], input=req, capture_output=True,
                          text=True, timeout=120, check=False)
    out = json.loads(proc.stdout)
    assert out["success"] is False
    assert out["stderr"].startswith("ClientSafeError: Unsafe Python code detected: attribute 'to_csv'")
    assert proc.returncode == 0


def test_audit_hook_is_active_in_worker(sandbox, tmp_path):
    # String dispatch reaches DataFrame.to_pickle -> open(); the audit hook
    # must refuse it (PermissionError) before the fd limit (OSError) is hit.
    target = tmp_path / "p.pkl"
    result = sandbox.execute_analysis(f"df.apply('to_pickle', path={str(target)!r})", ROWS)
    assert result["stderr"].startswith("PermissionError: sandbox: operation 'open'"), result["stderr"]
    assert not target.exists()


def test_worker_enforces_policy_on_its_own():
    # The worker must not rely on the parent having validated the code.
    req = json.dumps({"code": "df.to_csv('x.csv')", "raw_data": ROWS})
    proc = subprocess.run([sys.executable, "-I", str(WORKER)], input=req, capture_output=True,
                          text=True, timeout=120, check=False)
    out = json.loads(proc.stdout)
    assert out["success"] is False
    assert out["stderr"].startswith("ClientSafeError: Unsafe Python code detected: attribute 'to_csv'")
    assert proc.returncode == 0


def test_frame_introspection_is_rejected(sandbox):
    code = "def g():\n    yield 1\nit = g()\nf = it.gi_frame"
    result = sandbox.execute_analysis(code, ROWS)
    assert result["success"] is False
    assert "gi_frame" in result["stderr"]


def test_facade_hides_unlisted_module_attributes(sandbox):
    result = sandbox.execute_analysis("x = pd.ExcelWriter", ROWS)
    assert result["success"] is False
    assert "not available in the sandbox" in result["stderr"]
    result = sandbox.execute_analysis("pd.DataFrame = None", ROWS)
    assert result["success"] is False
    assert "read-only" in result["stderr"]


def test_worker_environment_has_no_secrets(sandbox, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:hunter2@db/prod")
    # No os/environ access is possible from user code; the env passed to the
    # child is checked directly via the subprocess call arguments instead.
    captured = {}
    real_run = subprocess.run

    def spy(*args, **kwargs):
        captured.update(kwargs)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    result = sandbox.execute_analysis("x = 1", ROWS)
    assert result["success"] is True
    assert "DATABASE_URL" not in captured["env"]
    assert set(captured["env"]) <= {"PATH", "PYTHONHASHSEED", "SYSTEMROOT"}
    assert captured["cwd"] != os.getcwd()


def test_cpu_bound_code_times_out(sandbox):
    result = sandbox.execute_analysis("x = 0\nwhile True:\n    x += 1", ROWS)
    assert result["success"] is False
    assert result["stderr"].startswith("TimeoutError"), result["stderr"]


@pytest.mark.skipif(sys.platform != "linux", reason="RLIMIT_AS is enforced on Linux")
def test_huge_allocation_hits_memory_limit(sandbox):
    # ~800 MB: fits on a normal host/CI runner, but not in the 512 MB budget.
    result = sandbox.execute_analysis("a = np.ones(10**8)", ROWS)
    assert result["success"] is False
    assert "Memory" in result["stderr"] or "ResourceLimit" in result["stderr"]


def test_parent_timeout_is_reported(monkeypatch, sandbox):
    import sandbox as sandbox_module

    def boom(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="worker", timeout=1)

    monkeypatch.setattr(sandbox_module.subprocess, "run", boom)
    result = sandbox.execute_analysis("x = 1", ROWS)
    assert result == {
        "success": False,
        "stdout": "",
        "stderr": f"TimeoutError: Sandbox execution exceeded {sandbox_module.MAX_EXECUTION_SECONDS:.1f} seconds timeout.",
        "local_state": "{}",
    }


@pytest.mark.parametrize(
    ("returncode", "stdout", "expected"),
    [
        (-9, "", "ResourceLimitError"),
        (1, "Traceback /srv/app/x.py", "SandboxError: sandbox process exited without a result."),
        (0, "[1, 2]", "SandboxError: malformed sandbox result."),
    ],
)
def test_worker_crash_never_leaks_raw_output(monkeypatch, sandbox, returncode, stdout, expected):
    import sandbox as sandbox_module

    monkeypatch.setattr(
        sandbox_module.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, returncode, stdout=stdout, stderr="/srv/secret/path"),
    )
    result = sandbox.execute_analysis("x = 1", ROWS)
    assert result["success"] is False
    assert result["stderr"].startswith(expected)
    assert "/srv" not in result["stderr"]


# --------------------------------------------- worker defence layers directly


def _run_worker_snippet(snippet: str) -> subprocess.CompletedProcess:
    """Run a snippet that imports the worker and applies its lockdown."""
    program = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('w', {str(WORKER)!r})\n"
        "w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)\n"
        + snippet
    )
    return subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, timeout=60, check=False
    )


@pytest.mark.skipif(sys.platform != "linux", reason="rlimits are POSIX/Linux")
def test_kernel_limits_block_file_access_without_audit_hook(secret_file):
    # Even with the Python-level audit hook absent, no fd can be allocated.
    proc = _run_worker_snippet(
        "import os\n"
        "w._apply_resource_limits(cpu_seconds=5, memory_mb=256)\n"
        "try:\n"
        f"    os.open({str(secret_file)!r}, os.O_RDONLY)\n"
        "    print('OPENED')\n"
        "except OSError as e:\n"
        "    print('BLOCKED', e.errno)\n"
        "try:\n"
        "    os.fork(); print('FORKED')\n"
        "except OSError:\n"
        "    print('NOFORK')\n"
    )
    assert "OPENED" not in proc.stdout
    assert "BLOCKED 24" in proc.stdout  # EMFILE
    assert "FORKED" not in proc.stdout or os.geteuid() == 0


def test_audit_hook_blocks_open_and_subprocess_once_locked(secret_file):
    proc = _run_worker_snippet(
        "import sys, os\n"
        "sys.addaudithook(w._audit_hook)\n"
        f"open({str(secret_file)!r}).read(); print('UNLOCKED-OK')\n"
        "w._LOCKED = True\n"
        "for fn in (lambda: open(" + repr(str(secret_file)) + "), lambda: os.system('true'),\n"
        "           lambda: __import__('socket').socket(), lambda: exec('1'), lambda: eval('1+1')):\n"
        "    try:\n"
        "        fn(); print('ALLOWED')\n"
        "    except PermissionError:\n"
        "        print('DENIED')\n"
    )
    lines = proc.stdout.split()
    assert lines[0] == "UNLOCKED-OK"
    assert lines[1:] == ["DENIED"] * 5, proc.stdout + proc.stderr


def test_blocked_attribute_policy():
    from sandbox import blocked_attribute

    for name in ["to_csv", "to_pickle", "to_parquet", "to_sql", "read_csv", "read_pickle",
                 "tofile", "load", "save", "_mgr", "gi_frame", "f_globals", "tb_frame",
                 "co_code", "func_globals", "io", "lib", "style"]:
        assert blocked_attribute(name), name
    for name in ["to_dict", "to_list", "to_numpy", "to_string", "to_datetime", "sum",
                 "groupby", "mean", "query", "values", "shape", "torque", "reader"]:
        assert not blocked_attribute(name), name


# ------------------------------------------------------- read-only database


@pytest.fixture()
def db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("MAX_QUERY_ROWS", raising=False)
    from database import DatabaseManager

    return DatabaseManager()


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO sales_performance VALUES (99, 'd', 's', 'c', 1.0, 1)",
        "DELETE FROM sales_performance",
        "UPDATE inventory_status SET stock_on_hand = 0",
        "DROP TABLE sales_performance",
        "CREATE TABLE pwn (x int)",
        "ATTACH DATABASE 'pwn.db' AS pwn",
        "PRAGMA query_only = OFF",
        "PRAGMA writable_schema = 1",
    ],
)
def test_connection_itself_is_read_only(db, statement, tmp_path):
    """Bypass the keyword filter entirely: the DB connection must refuse writes."""
    raw = db.engine.raw_connection()
    try:
        with pytest.raises(Exception):  # noqa: B017,PT011 - sqlite3.DatabaseError
            raw.cursor().execute(statement)
    finally:
        raw.close()
    assert db.execute_query("SELECT COUNT(*) AS n FROM sales_performance") == [{"n": 10}]
    assert not (tmp_path / "pwn.db").exists()


@pytest.mark.parametrize("statement", ["PRAGMA table_info(sales_performance)", "VACUUM", "EXPLAIN SELECT 1"])
def test_non_select_entrypoints_are_refused(db, statement):
    from errors import ClientSafeError

    with pytest.raises(ClientSafeError, match="Security Violation"):
        db.execute_query(statement)


@pytest.mark.parametrize("statement", ["PRAGMA table_info(sales_performance)", "VACUUM", "EXPLAIN SELECT 1"])
def test_non_select_entrypoints_are_refused(db, statement):
    from errors import ClientSafeError

    with pytest.raises(ClientSafeError, match="Security Violation"):
        db.execute_query(statement)


def test_cte_write_is_blocked(db):
    # A WITH ... statement passes the entrypoint check; the keyword filter or
    # the read-only connection must still stop the write.
    with pytest.raises((ValueError, sqlalchemy.exc.DatabaseError)):
        db.execute_query("WITH t AS (SELECT 1) INSERT INTO sales_performance SELECT * FROM sales_performance")


def test_schema_and_select_still_work_read_only(db):
    schema = json.loads(db.get_schema_layout())
    assert [c["column_name"] for c in schema["sales_performance"]][0] == "transaction_id"
    assert schema["sales_performance"][0]["primary_key"] is True
    rows = db.execute_query("WITH t AS (SELECT store_id FROM sales_performance) SELECT COUNT(*) AS n FROM t")
    assert rows == [{"n": 10}]


def test_row_limit_caps_results(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("MAX_QUERY_ROWS", "3")
    from database import DatabaseManager

    db = DatabaseManager()
    assert db.max_rows == 3
    assert len(db.execute_query("SELECT * FROM sales_performance")) == 3
    assert len(db.execute_query("SELECT * FROM sales_performance LIMIT 2")) == 2


@pytest.mark.parametrize(("value", "expected"), [("", 1000), ("abc", 1000), ("0", 1), ("-5", 1), ("25", 25)])
def test_max_rows_parsing(monkeypatch, value, expected):
    from database import _max_rows

    monkeypatch.setenv("MAX_QUERY_ROWS", value) if value else monkeypatch.delenv("MAX_QUERY_ROWS", raising=False)
    assert _max_rows() == expected


def test_in_memory_sqlite_is_refused():
    from database import _readonly_engine

    with pytest.raises(ValueError):
        _readonly_engine("sqlite:///:memory:")


def test_existing_sqlite_url_is_opened_read_only(tmp_path):
    import sqlite3

    from database import _readonly_engine

    path = tmp_path / "other.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (x int)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    con.close()
    engine = _readonly_engine(f"sqlite:///{path}")
    with engine.connect() as conn:
        assert conn.execute(sqlalchemy.text("SELECT x FROM t")).all() == [(1,)]
        with pytest.raises(sqlalchemy.exc.DatabaseError):
            conn.execute(sqlalchemy.text("INSERT INTO t VALUES (2)"))


def test_postgres_engine_registers_read_only_session(monkeypatch):
    pytest.importorskip("psycopg2")
    from database import _readonly_engine

    engine = _readonly_engine("postgresql://u:p@localhost:1/db")
    executed = []

    class Cur:
        def execute(self, sql):
            executed.append(sql)

        def close(self):
            pass

    class Conn:
        def cursor(self):
            return Cur()

    engine.dispatch.connect(Conn(), None)
    assert executed[0] == "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"
    assert executed[1].startswith("SET statement_timeout = ")


# ------------------------------------------------ hardening the verifier itself


def test_unsafe_code_is_rejected_in_parent_without_spawning(monkeypatch, sandbox):
    import sandbox as sandbox_module

    def must_not_run(*a, **k):
        raise AssertionError("worker must not start for code rejected by policy")

    monkeypatch.setattr(sandbox_module.subprocess, "run", must_not_run)
    result = sandbox.execute_analysis("df.to_csv('x')", ROWS)
    assert result == {
        "success": False,
        "stdout": "",
        "stderr": "ClientSafeError: Unsafe Python code detected: attribute 'to_csv' is not allowed "
        "(file/network IO, serialisation and interpreter internals are disabled).",
        "local_state": "{}",
    }


def test_validate_raises_client_safe_error(sandbox):
    from errors import ClientSafeError

    with pytest.raises(ClientSafeError):
        sandbox._validate_python_code("x = df.to_pickle")


@pytest.mark.parametrize(
    ("returncode", "stdout", "expected"),
    [
        (0, "", "SandboxError: sandbox process exited without a result."),
        (0, '{"stdout": "x"}', "SandboxError: malformed sandbox result."),
        (0, "x" * 2_000_000, "SandboxError: sandbox process exited without a result."),
    ],
)
def test_worker_protocol_errors(monkeypatch, sandbox, returncode, stdout, expected):
    import sandbox as sandbox_module

    monkeypatch.setattr(
        sandbox_module.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, returncode, stdout=stdout, stderr=""),
    )
    assert sandbox.execute_analysis("x = 1", ROWS)["stderr"] == expected


def test_worker_result_fields_are_normalised(monkeypatch, sandbox):
    import sandbox as sandbox_module

    payload = json.dumps({"success": 1, "stdout": 5, "stderr": None, "local_state": {"a": 1}})
    monkeypatch.setattr(
        sandbox_module.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=payload, stderr=""),
    )
    assert sandbox.execute_analysis("x = 1", ROWS) == {
        "success": True,
        "stdout": "5",
        "stderr": "None",
        "local_state": "{'a': 1}",
    }


def test_worker_invocation_is_isolated(monkeypatch, sandbox):
    import sandbox as sandbox_module

    seen = {}

    def spy(argv, **kwargs):
        seen["argv"] = argv
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout='{"success": true}', stderr="")

    monkeypatch.setattr(sandbox_module.subprocess, "run", spy)
    sandbox.execute_analysis("x = 1", ROWS)
    assert seen["argv"] == [sys.executable, "-I", str(WORKER)]
    assert seen["check"] is False and seen["capture_output"] is True
    assert seen["timeout"] == sandbox_module.MAX_EXECUTION_SECONDS + sandbox_module.STARTUP_ALLOWANCE_SECONDS
    request = json.loads(seen["input"])
    assert request == {
        "code": "x = 1",
        "raw_data": ROWS,
        "timeout": sandbox_module.MAX_EXECUTION_SECONDS,
        "memory_mb": sandbox_module.MAX_MEMORY_MB,
    }


def test_default_database_contents(db):
    schema = json.loads(db.get_schema_layout())
    for table in ("sales_performance", "inventory_status"):
        cols = schema[table]
        assert all(c["nullable"] is False for c in cols[1:]), cols
        assert [c["column_name"] for c in cols if c["primary_key"]] == [cols[0]["column_name"]]
    assert [c["data_type"] for c in schema["sales_performance"]] == [
        "INTEGER", "VARCHAR(32)", "VARCHAR(32)", "VARCHAR(64)", "FLOAT", "INTEGER"
    ]
    assert [c["data_type"] for c in schema["inventory_status"]] == [
        "INTEGER", "VARCHAR(64)", "VARCHAR(64)", "INTEGER", "INTEGER", "INTEGER"
    ]
    sales = db.execute_query("SELECT * FROM sales_performance ORDER BY transaction_id")
    inv = db.execute_query("SELECT * FROM inventory_status ORDER BY item_id")
    assert len(sales) == 10 and len(inv) == 10
    assert round(sum(r["revenue"] for r in sales), 2) == 99553.49
    assert sum(r["units_sold"] for r in sales) == 1097
    assert sales[0] == {"transaction_id": 1, "date": "2026-01-03", "store_id": "NYC-01",
                        "product_category": "Electronics", "revenue": 18250.75, "units_sold": 42}
    assert sum(r["stock_on_hand"] for r in inv) == 3840
    assert sum(r["reorder_point"] for r in inv) == 2210
    assert sum(r["lead_time_days"] for r in inv) == 103
    assert [r["sku"] for r in inv][:2] == ["ELEC-1001", "GROC-2045"]
    assert {r["warehouse_location"] for r in inv} == {"WH-NORTH", "WH-SOUTH", "WH-WEST", "WH-EAST", "WH-CENTRAL"}


def test_query_from_another_thread(db):
    import threading

    out = []
    t = threading.Thread(target=lambda: out.append(db.execute_query("SELECT 1 AS one")))
    t.start()
    t.join(10)
    assert out == [[{"one": 1}]]


def test_sqlite_authorizer_decisions():
    import sqlite3

    from database import _sqlite_authorizer

    assert _sqlite_authorizer(sqlite3.SQLITE_SELECT, None, None, None, None) == sqlite3.SQLITE_OK
    assert _sqlite_authorizer(sqlite3.SQLITE_READ, "t", "c", "main", None) == sqlite3.SQLITE_OK
    assert _sqlite_authorizer(sqlite3.SQLITE_PRAGMA, "table_xinfo", "t", "main", None) == sqlite3.SQLITE_OK
    assert _sqlite_authorizer(sqlite3.SQLITE_PRAGMA, "read_uncommitted", None, None, None) == sqlite3.SQLITE_OK
    assert _sqlite_authorizer(sqlite3.SQLITE_PRAGMA, "query_only", "0", None, None) == sqlite3.SQLITE_DENY
    assert _sqlite_authorizer(sqlite3.SQLITE_INSERT, "t", None, "main", None) == sqlite3.SQLITE_DENY
    assert _sqlite_authorizer(sqlite3.SQLITE_ATTACH, "x.db", None, None, None) == sqlite3.SQLITE_DENY
