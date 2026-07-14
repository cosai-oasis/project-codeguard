# Project Decisions

Project decision records preserve choices that shape CodeGuard's scope,
architecture, or contributor expectations. They capture why a decision was made
so contributors do not need to reconstruct it from meetings or issue history.

## Decision Registry

| Record | Status | Date |
| --- | --- | --- |
| [0001: Separate Guidance from Runtime and Scanning](0001-separate-guidance-from-runtime-and-scanning.md) | Proposed | 2026-07-14 |

## When to Write a Decision Record

Create a record when a decision:

- establishes a project boundary or long-lived technical direction;
- affects multiple features or contributors; or
- is likely to be revisited without durable context.

Use issues and pull requests for routine implementation choices. Decision
records should add context, not duplicate those discussions.

## Workflow

1. Copy the [template](template.md) to the next available four-digit number.
2. Name the file `NNNN-short-title.md` using lowercase, hyphen-separated words.
3. Set the status to `Proposed`, identify an owner, add the record to this
   registry, and open a pull request with the relevant issue links.
4. Review the proposal through the repository's
   [contribution process](https://github.com/cosai-oasis/project-codeguard/blob/main/CONTRIBUTING.md).
   Before merging an approved proposal, change its status to `Accepted` and
   update its date. Close rejected proposals with the rationale recorded in the
   pull request.
5. Do not rewrite an accepted decision when the direction changes. Add a new
   record, mark the old one `Superseded`, and link the two records.

The supported statuses are:

- `Proposed`: under discussion and not yet authoritative.
- `Accepted`: the current project decision.
- `Superseded`: replaced by a newer decision record.
