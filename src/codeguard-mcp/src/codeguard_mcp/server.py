"""CoSAI CodeGuard MCP Server — security rules as MCP skills (resources)."""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.server.providers.skills import SkillProvider
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse

from codeguard_mcp.config import settings
from codeguard_mcp.log import setup_logging

setup_logging(settings.LOG_LEVEL)
logger = logging.getLogger(__name__)

mcp = FastMCP(
    "CodeGuard MCP Server",
    instructions=(
        "This server provides access to CoSAI CodeGuard security rules. "
        "Each rule is exposed as an MCP resource via the skill:// URI scheme. "
        "Use list_resources() to discover available rules and "
        "read_resource() to fetch their content."
    ),
    mask_error_details=True,
)


# ── Health endpoint ──────────────────────────────────────────────────


@mcp.custom_route("/health", methods=["GET"], name="health")
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "version": settings.APP_VERSION})


# ── Download endpoint (meta skill zip) ───────────────────────────────


@mcp.custom_route("/download/skill", methods=["GET"], name="download_skill")
async def download_skill(_: Request) -> StreamingResponse | JSONResponse:
    """Serve a zip of the .agents/ directory containing the CodeGuard meta skill."""
    agents_dir = Path(__file__).resolve().parent.parent.parent / ".agents"
    if not agents_dir.is_dir():
        return JSONResponse({"error": ".agents directory not found"}, status_code=404)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fp in agents_dir.rglob("*"):
            if fp.is_file():
                zf.write(fp, arcname=Path(".agents") / fp.relative_to(agents_dir))
    buf.seek(0)

    return StreamingResponse(
        iter([buf.read()]),
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="codeguard-mcp-meta-skill.zip"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, max-age=3600",
        },
    )


# ── Skills provider (software-security skill) ────────────────────────

mcp.add_provider(SkillProvider(Path(settings.SKILLS_PATH)))


# ── Entrypoint ────────────────────────────────────────────────────────


def main() -> None:
    logger.info(
        "Starting CodeGuard MCP Server v%s on %s:%d (%s)",
        settings.APP_VERSION,
        settings.HOST,
        settings.PORT,
        settings.TRANSPORT,
    )
    mcp.run(transport=settings.TRANSPORT, host=settings.HOST, port=settings.PORT)
