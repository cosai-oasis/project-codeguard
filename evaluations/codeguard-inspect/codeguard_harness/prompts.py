"""Shared prompt-variant machinery for CodeGuard Inspect evaluations."""

from __future__ import annotations

BASELINE_VARIANT = "baseline"
CODEGUARD_VARIANT = "codeguard"
BOTH_VARIANT = "both"
PROMPT_VARIANTS = (BASELINE_VARIANT, CODEGUARD_VARIANT)


def build_prompt(base: str, guidance: str, variant: str) -> str:
    """Build a task prompt for the given variant, prepending guidance for CodeGuard."""
    if variant == BASELINE_VARIANT:
        return base
    if variant == CODEGUARD_VARIANT:
        return f"{guidance}\n{base}"
    raise ValueError(f"Unsupported prompt variant: {variant}")


def selected_prompt_variants(variant: str) -> tuple[str, ...]:
    """Expand a task variant into concrete prompt variants."""
    if variant == BOTH_VARIANT:
        return PROMPT_VARIANTS
    if variant in PROMPT_VARIANTS:
        return (variant,)
    raise ValueError(f"Unsupported task variant: {variant}")
