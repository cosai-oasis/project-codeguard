# 0001: Separate Guidance from Runtime and Scanning

- **Status:** Proposed
- **Date:** 2026-07-14
- **Owner:** Project CodeGuard maintainers

## Context

Project CodeGuard publishes model- and tool-agnostic security skills, rules, and
reviewer guidance. Two proposals exposed important boundaries around that
content:

- Incremental scanning requires changed-file tracking, cache invalidation, and
  a trusted record of prior work.
- Comprehensive secret detection requires repository-wide analysis and an
  evolving catalog of provider-specific patterns.

Those capabilities depend on runtime state and detection engines that CodeGuard
skills and rules do not control. Embedding them in guidance would make ownership
unclear and could imply detection guarantees that the project cannot provide.

## Considered Options

- Add persistent scan state and comprehensive detection to CodeGuard. This
  would require runtime authority the project's guidance does not have and
  would duplicate dedicated scanners.
- Implement orchestration separately for every supported host. Integrations may
  do this when useful, but making it the project default would fragment the
  model- and tool-agnostic guidance.
- Keep CodeGuard focused on guidance while hosts own orchestration and scanners
  own comprehensive detection. This preserves explicit trust boundaries and
  avoids duplicating specialized tools.

## Decision

CodeGuard owns model- and tool-agnostic security guidance and the tooling needed
to convert, validate, and package that guidance.

The consuming host or integration owns orchestration, including when guidance
is invoked, which files are selected, how changes and caches are tracked, what
invalidates prior results, and which state is trusted. A hook can provide an
invocation point, but it does not establish state ownership or a trust boundary.

Purpose-built scanners own comprehensive detection. CodeGuard may recommend
their use and provide secure guidance for findings, but it does not reproduce an
exhaustive secret or vulnerability scanner.

## Consequences

- CodeGuard skills, rules, and reviewer bundles do not maintain incremental scan
  state or decide which prior results are trustworthy.
- Host-specific integrations may implement incremental orchestration outside
  the model-agnostic guidance, with their trust and invalidation rules made
  explicit.
- Secret-handling guidance may address coherent gaps with representative
  examples, while exhaustive repository, history, and provider-pattern
  detection remains with dedicated scanners.
- The incremental scan proposal can close as outside CodeGuard's scope, while
  retaining this boundary for future proposals.

## Related Issues and Pull Requests

- [#78: Possible additional categories of secrets for rule codeguard-1-hardcoded-credentials](https://github.com/cosai-oasis/project-codeguard/issues/78)
- [#83: Design incremental scan scope for CodeGuard](https://github.com/cosai-oasis/project-codeguard/issues/83)
- [#84: Add lightweight decision records for CodeGuard](https://github.com/cosai-oasis/project-codeguard/issues/84)
