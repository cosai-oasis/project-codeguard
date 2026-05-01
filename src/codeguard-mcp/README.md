# CodeGuard MCP Server

An [MCP](https://modelcontextprotocol.io/) server that exposes [CoSAI CodeGuard](https://project-codeguard.org/) security rules as individual tools over streamable HTTP. Deploy it on your infrastructure and give every AI coding assistant in your organization access to curated, versioned security guidance.

## What It Does

The server reads the **23 security rules** from `sources/rules/core/` in this repository and registers each one as a no-argument MCP tool. AI assistants invoke the tools at code-generation time and apply the returned guidance.

Rules cover: hardcoded credentials, cryptography, authentication & MFA, authorization, input validation, API security, session management, client-side web security, container/K8s/IaC hardening, logging, file uploads, supply chain, mobile security, and more.

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

Configure your MCP client to connect to the server:

```json
{
  "mcpServers": {
    "codeguard": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

For org-wide deployment, put the server behind your reverse proxy with TLS + SSO and point every developer's IDE at the internal URL:

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

The meta skill tells your AI assistant *how* to use the CodeGuard tools. It lives at `.agents/skills/codeguard-mcp-meta/SKILL.md` and needs to be installed in your project.

**Option A:** Copy it manually from this repo:

```bash
cp -r src/codeguard-mcp/.agents /path/to/your/project/
```

**Option B:** Download from the running server:

```
GET http://localhost:8080/download/skill
```

This returns a zip containing the `.agents/` directory. Unzip it into your project root.

## How It Works

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

| Prefix | When | Count | Examples |
|--------|------|-------|----------|
| `codeguard_1_*` | **Always** before any code change | 3 | `codeguard_1_hardcoded_credentials`, `codeguard_1_crypto_algorithms` |
| `codeguard_0_*` | **Context-select** by language + domain | 20 | `codeguard_0_input_validation_injection`, `codeguard_0_api_web_services` |

## Configuration

All settings via environment variables (prefix `CODEGUARD_`):

| Variable | Default | Description |
|----------|---------|-------------|
| `CODEGUARD_HOST` | `0.0.0.0` | Bind address |
| `CODEGUARD_PORT` | `8080` | Bind port |
| `CODEGUARD_LOG_LEVEL` | `INFO` | Log level |
| `CODEGUARD_TRANSPORT` | `streamable-http` | `streamable-http` or `stdio` |
| `CODEGUARD_RULES_DIR` | `sources/rules/core/` | Path to rule markdown files |

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/mcp` | MCP protocol endpoint |
| `GET` | `/health` | Health check (`{"status": "ok"}`) |
| `GET` | `/download/skill` | Download `.agents/` skill zip |

## License

See the repository root [LICENSE.md](../../LICENSE.md).
