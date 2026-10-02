"""Small rule documents used by parser and validator tests."""


def rule_text(
    *,
    description: str = "Example",
    languages: str = "[python]",
    always_apply: str = "false",
    tags: str = "[web]",
    body: str = "# Title",
) -> str:
    """Build a minimal unified rule with configurable frontmatter and body."""
    return (
        "---\n"
        f"description: {description}\n"
        f"languages: {languages}\n"
        f"alwaysApply: {always_apply}\n"
        f"tags: {tags}\n"
        "---\n\n"
        f"{body}\n"
    )
