# chimera-data-mcp

## Architecture Layout

```text
[LLM Agent (Claude/Desktop)]
            |
            v
   [MCP stdio transport]
            |
            v
[Chimera-Enterprise-Data-Analyst MCP Server]
   |                |                    |
   |                |                    |
   v                v                    v
[get_schema_layout] [execute_readonly_query] [run_python_analytics]
   |                |                    |
   v                v                    v
SQLAlchemy inspect  Secure SELECT-only    Isolated Python namespace
(table metadata)    query execution       (pd, np, df pre-injected)
            \           |                 /
             \          v                /
              \   Enterprise Database   /
               \_______________________/
```

## Quickstart

1. `python -m venv venv`
2. `source venv/bin/activate`
3. `pip install -r requirements.txt`
4. `python src/main.py`

## Claude Desktop Integration Config

Add this entry to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "chimera-data-mcp": {
      "command": "python",
      "args": ["/absolute/path/to/src/main.py"]
    }
  }
}
```
