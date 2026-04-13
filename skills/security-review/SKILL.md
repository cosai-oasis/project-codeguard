---
name: security-review
description: Comprehensive security code review workflow for a target repository, producing a markdown report with findings and recommendations.
metadata:
  short-description: Security code review report
  framework: Project CodeGuard
  codeguard-source: https://github.com/cosai-oasis/project-codeguard
---

# Security Review

## When to use

- Use for a full codebase security review with prioritized findings,
  remediation guidance, and a formal report.

## Inputs

- Target repository path (first argument after invocation).
  - Example: `$security-review /path/to/repo`
- Security knowledge base source:
  - Rules are sourced from [Project CodeGuard](https://github.com/cosai-oasis/project-codeguard),
    an open-source, model-agnostic security framework by CoSAI/OASIS.

If the repo path is missing or unclear, ask the user for it before proceeding.

## Workflow

1. Load the security knowledge base from Project CodeGuard
   - First read the `Security_Code_Reviewer_Guidelines.md` file bundled with
     this skill. Use its purpose and rule-loading strategy to guide the review.
   - Load all core security rules from Project CodeGuard:

     ```text
     https://github.com/cosai-oasis/project-codeguard/tree/main/sources/core
     ```

     These are mandatory foundational rules that must be loaded for every review.

   - Load relevant OWASP rules for the detected tech stack from:

     ```text
     https://github.com/cosai-oasis/project-codeguard/tree/main/sources/owasp
     ```

     Only load OWASP rules that match the target repository's technology stack.

2. Perform deep code analysis
   - Review the repository line by line.
   - Focus on: injection flaws, authn/authz, hardcoded secrets, crypto misuse,
     SSRF, path traversal, RCE vectors, XSS/CSRF, unsafe deserialization,
     insecure defaults/configuration, and supply chain issues.
3. Produce the report in markdown.

## Report requirements

- Executive Summary
  - Total findings by severity (Critical/High/Medium/Low/Info)
  - Top 5 most critical issues
  - Overall security posture
- Detailed Findings (for each issue)
  - Title, Severity, Rule Reference(s), Location, Code Snippet
  - Description, Impact, Remediation (with examples), References
- Findings by Category
- Recommendations
  - Immediate actions, short-term (1-3 months), long-term improvements,
    tooling/process suggestions
- Appendix
  - Files reviewed, rules applied/coverage, methodology notes

## Output

- Save the report to:
  - `./security_report/sec_review_<repo-name>_<YYYY-MM-DD_HH-mm-ss>.md`
  - Use the target repo folder name for `<repo-name>` and replace spaces
    with `-`.
  - Write to the `security_report` folder in the current working directory.
