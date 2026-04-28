"""CoSAI CodeGuard MCP Server — security rules as MCP tools."""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse

from codeguard_mcp.config import settings
from codeguard_mcp.log import setup_logging
from codeguard_mcp.rule_processor import RuleProcessor
from codeguard_mcp.tool_factory import RuleToolFactory

setup_logging(settings.LOG_LEVEL)
logger = logging.getLogger(__name__)

mcp = FastMCP(
    "CodeGuard MCP Server",
    instructions=(
        "This server provides access to CoSAI CodeGuard security rules. "
        "Each rule is exposed as a separate tool that returns security "
        "guidance for specific programming languages and security domains."
    ),
    mask_error_details=True,
)


# ── Custom routes ────────────────────────────────────────────────────


@mcp.custom_route("/health", methods=["GET"], name="health")
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "version": settings.APP_VERSION})


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


# ── Rule registration ────────────────────────────────────────────────


def _register_rules() -> None:
    processor = RuleProcessor()
    factory = RuleToolFactory()
    rules = processor.get_all_rules()

    logger.info("Registering %d security rules as MCP tools", len(rules))
    for rule in rules:
        mcp.add_tool(factory.create_tool(rule))

    logger.info("All %d tools registered", len(rules))


_register_rules()


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
