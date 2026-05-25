"""
Tag Mappings

Centralized list of known tags for categorizing security rules.

Tags are grouped by security domain to aid discoverability and filtering.
When adding a new tag, place it in the most appropriate domain group below.
"""

# Known tags used in rules
# Add new tags here as they are introduced in rules
KNOWN_TAGS = {
    # Identity and access
    "authentication",
    "authorization",
    "session-management",
    # Data protection
    "data-security",
    "cryptography",
    "privacy",
    "secrets",
    # Application security
    "web",
    "api-security",
    "input-validation",
    "injection-prevention",
    "client-side-security",
    "error-handling",
    # Infrastructure and operations
    "infrastructure",
    "cloud-security",
    "container-security",
    "network-security",
    "ci-cd",
    # Supply chain and dependencies
    "supply-chain",
    "dependency-management",
    # Platform-specific
    "mobile-security",
    # Compliance and governance
    "logging",
    "configuration",
    # Serialization and data formats
    "serialization",
    "xml-security",
}

