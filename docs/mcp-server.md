# CodeGuard MCP Server

The CodeGuard MCP server exposes all 23 core security rules as individual [Model Context Protocol](https://modelcontextprotocol.io/) tools over streamable HTTP. Deploy it once on your infrastructure and every AI coding assistant in your organization gets access to the same curated, versioned security guidance — no per-repo file installation needed.

!!! info "When to use the MCP server"
    The MCP server is best suited for teams that already operate MCP infrastructure and want a single, centrally managed source of CodeGuard rules. For most individual users and teams, [rule files or Agent Skills](install-paths.md) are simpler. See [Choosing an Install Path](install-paths.md#mcp-server) for a full comparison.

## Quick Start

### Run locally with uv

```bash
cd src/codeguard-mcp
uv sync
uv run fastmcp run src/codeguard_mcp/server.py:mcp \
    --transport streamable-http --host 0.0.0.0 --port 8080
```

### Docker

```bash
cd src/codeguard-mcp
docker compose up --build
```

## Connect Your IDE

Add the server to your MCP client configuration:

=== "Local"

    ```json
    {
      "mcpServers": {
        "codeguard": {
          "url": "http://localhost:8080/mcp"
        }
      }
    }
    ```

=== "Org-wide"

    Put the server behind a reverse proxy with TLS and SSO, then point every developer's IDE at the internal URL:

    ```json
    {
      "mcpServers": {
        "codeguard": {
          "url": "https://codeguard-mcp.internal.company.com/mcp"
        }
      }
    }
    ```

## Install the Meta Skill

The meta skill tells your AI assistant how to use the CodeGuard MCP tools. It lives at `.agents/skills/codeguard-mcp-meta/SKILL.md` and needs to be installed in your project.

=== "Copy from repo"

    ```bash
    cp -r src/codeguard-mcp/.agents /path/to/your/project/
    ```

=== "Download from server"

    ```bash
    curl -o codeguard-meta-skill.zip http://localhost:8080/download/skill
    unzip codeguard-meta-skill.zip -d /path/to/your/project/
    ```

    The `/download/skill` endpoint returns a zip containing the `.agents/` directory. Unzip it into your project root.

## How It Works

The server reads the 23 security rules from `sources/rules/core/` and registers each one as a no-argument MCP tool. When your AI assistant generates or reviews code, it invokes the relevant tools and applies the returned guidance.

```
Developer writes code
        ↓
AI assistant reads the meta skill
        ↓
Invokes codeguard_1_* tools (always-on guardrails)
        ↓
Invokes codeguard_0_* tools (context-selected by language + domain)
        ↓
Applies security guidance to generated code
        ↓
Documents which rules were applied
```

### Tool Taxonomy

| Prefix | When invoked | Count | Examples |
|:-------|:------------|:------|:--------|
| `codeguard_1_*` | **Always** — before any code change | 3 | `codeguard_1_hardcoded_credentials`, `codeguard_1_crypto_algorithms` |
| `codeguard_0_*` | **Context-selected** by language and domain | 20 | `codeguard_0_input_validation_injection`, `codeguard_0_api_web_services` |

## Configuration

All settings are controlled via environment variables with the `CODEGUARD_` prefix:

| Variable | Default | Description |
|:---------|:--------|:------------|
| `CODEGUARD_HOST` | `0.0.0.0` | Bind address |
| `CODEGUARD_PORT` | `8080` | Bind port |
| `CODEGUARD_LOG_LEVEL` | `INFO` | Log level |
| `CODEGUARD_TRANSPORT` | `streamable-http` | `streamable-http` or `stdio` |
| `CODEGUARD_RULES_DIR` | `sources/rules/core/` | Path to rule markdown files |

Copy `.env.example` from `src/codeguard-mcp/` to `.env` and edit as needed before running.

## Endpoints

| Method | Path | Description |
|:-------|:-----|:------------|
| `POST` | `/mcp` | MCP protocol endpoint |
| `GET` | `/health` | Health check — returns `{"status": "ok", "version": "..."}` |
| `GET` | `/download/skill` | Download the meta skill as a `.agents/` zip |

## Next Steps

[Choosing an Install Path →](install-paths.md){ .md-button .md-button--primary }
[Getting Started →](getting-started.md){ .md-button }
