# ── Build stage ──────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

COPY src/codeguard-mcp/pyproject.toml src/codeguard-mcp/uv.lock src/codeguard-mcp/README.md ./src/codeguard-mcp/
RUN cd src/codeguard-mcp && uv sync --locked --no-dev --no-editable

COPY skills/ ./skills/
COPY src/codeguard-mcp/src/ ./src/codeguard-mcp/src/
COPY src/codeguard-mcp/.agents/ ./src/codeguard-mcp/.agents/

# ── Runtime stage ────────────────────────────────────────────────────
FROM python:3.11-slim

RUN groupadd -r codeguard && useradd -r -g codeguard codeguard

WORKDIR /app

COPY --from=builder /app/src/codeguard-mcp/.venv    /app/src/codeguard-mcp/.venv
COPY --from=builder /app/src/codeguard-mcp/src      /app/src/codeguard-mcp/src
COPY --from=builder /app/src/codeguard-mcp/.agents  /app/src/codeguard-mcp/.agents
COPY --from=builder /app/skills                     /app/skills

ENV PATH="/app/src/codeguard-mcp/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src/codeguard-mcp/src \
    CODEGUARD_HOST=0.0.0.0 \
    CODEGUARD_SKILLS_PATH=/app/skills/software-security

USER codeguard
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=2)"]

ENTRYPOINT ["/app/src/codeguard-mcp/.venv/bin/fastmcp"]
CMD ["run", "src/codeguard-mcp/src/codeguard_mcp/server.py:mcp", "--transport=streamable-http", "--host=0.0.0.0", "--port=8080"]
