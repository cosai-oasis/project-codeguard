"""Bounded scoring I/O for the pinned Inspect runtime.

Inspect exposes sample readers and score_async(samples=...), but its incremental
writer is private. Keep that dependency here; upgrade tests must cover sample
preservation, bounded flushing, cancellation, and header-only finalization.
"""

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
from inspect_ai.log import EvalLog, EvalSample, condense_sample, read_eval_log_sample_async
from inspect_ai.log._recorders import create_recorder_for_location

WRITE_BUFFER_SAMPLES = 8


@asynccontextmanager
async def scoring_samples(
    log: EvalLog,
    source: Path,
    keys: list[tuple[str | int, int]],
    destination: Path,
    prepare: Callable[[EvalSample], Awaitable[None]],
):
    """Yield Inspect's sample callback; finish the temporary log on success."""
    writer = create_recorder_for_location(str(destination), str(destination.parent))
    semaphore = anyio.Semaphore(1)
    written = 0

    @asynccontextmanager
    async def read_sample(index: int) -> AsyncGenerator[EvalSample]:
        nonlocal written
        # score_async schedules all samples concurrently. Bound both reads and
        # scoring, and periodically release the writer's buffered transcripts.
        async with semaphore:
            sample = await read_eval_log_sample_async(
                source, *keys[index], resolve_attachments=True
            )
            await prepare(sample)
            yield sample
            await writer.log_sample(log.eval, condense_sample(sample))
            written += 1
            if written % WRITE_BUFFER_SAMPLES == 0:
                await writer.flush(log.eval)

    try:
        await writer.log_init(log.eval, location=str(destination))
        await writer.log_start(log.eval, log.plan)
        yield read_sample
        await writer.log_finish(
            log.eval,
            log.status,
            log.stats,
            log.results,
            log.reductions,
            log.error,
            # Finalization needs only the header, never the saved transcripts.
            header_only=True,
            invalidated=log.invalidated,
            log_updates=log.log_updates,
            config_updates=log.config_updates,
        )
    finally:
        # Also release the recorder's temporary buffers on failure/cancellation.
        with anyio.CancelScope(shield=True):
            await writer.log_discard(log.eval)
