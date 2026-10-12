# chimera-data-mcp

## Architectural Flowchart

```text
Client Agent
     |
     v
FastMCP Server (Chimera-Enterprise-Data-Analyst)
     |
     +------------------------+
     |                        |
     v                        v
Secure Database Engine   Execution Sandbox Engine
(SQLAlchemy + Read-only) (Pandas/Numpy + Isolated exec)
```

## Setup Instructions

1. Create a virtual environment:
   ```bash
   python -m venv venv
   ```
2. Activate it:
   - macOS/Linux:
     ```bash
     source venv/bin/activate
     ```
   - Windows (PowerShell):
     ```powershell
     .\venv\Scripts\Activate.ps1
     ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Launch the MCP server:
   ```bash
   python src/main.py
   ```

## Claude Desktop Integration

Add this block to your `claude_desktop_config.json` under `mcpServers` to run over `stdio` transport:

```json
{
  "mcpServers": {
    "chimera-data-mcp": {
      "command": "python",
      "args": [
        "/tmp/workspace/fernandogarzaaa/chimera-data-mcp/src/main.py"
      ]
    }
  }
}
```

## Security model

**Do not expose this server to untrusted clients without reviewing the limits below.**
An MCP client (or a prompt-injected LLM driving it) controls the SQL and the
Python it sends.

### `run_python_analytics`

Analyst code runs in a separate Python process (`src/sandbox_worker.py`), not
inside the server:

- empty environment (no `DATABASE_URL`/API keys) and a throwaway working directory;
- resource limits on Linux/POSIX: CPU time, address space
  (`SANDBOX_MAX_MEMORY_MB`, default 512), max file size 0, no child processes,
  and no free file descriptors, so file and socket access fails in the kernel;
- an audit hook that refuses file opens, process creation, sockets, ctypes,
  unpickling, imports and nested `exec`/`eval` once user code starts;
- `pd` / `np` are allow-listed facades (no `pd.read_*`, `pd.io`, `np.load`,
  `np.save`, `np.fromfile`, ...); an AST check rejects imports, `_private` /
  dunder attributes, frame/traceback attributes and IO methods such as
  `to_csv`, `to_pickle`, `tofile`.

Settings: `SANDBOX_TIMEOUT_SECONDS` (default 2), `SANDBOX_MAX_MEMORY_MB`
(default 512), `SANDBOX_STARTUP_SECONDS` (default 20, worker start-up allowance).
On Windows the resource limits are not available; only the other layers apply.
For hostile multi-tenant use, run the server itself in a container as well.

### `execute_readonly_query`

- SQLite databases are opened with `mode=ro`, `PRAGMA query_only=ON` and an
  authorizer that only allows reads; the keyword filter is just a first check.
- PostgreSQL and MySQL/MariaDB sessions are set to `READ ONLY` transactions
  with a 10 s statement timeout on connect. For any other backend only the
  keyword filter applies, so use a database user that has read-only grants.
- Results are capped at `MAX_QUERY_ROWS` rows (default 1000).
