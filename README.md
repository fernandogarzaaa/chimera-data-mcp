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
