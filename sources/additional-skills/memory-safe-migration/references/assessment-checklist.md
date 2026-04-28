# Migration assessment checklist

Use this checklist to evaluate whether a component should be migrated, its priority,
and its feasibility. Score each category and sum for an overall migration priority.

## Priority scoring

### Vulnerability history (0-10 points)

- [ ] Count of memory-related CVEs in this component
  - 0 CVEs: 0 points
  - 1-2 CVEs: 3 points
  - 3-5 CVEs: 6 points
  - 6+ CVEs: 10 points
- [ ] Severity of past CVEs
  - Mostly Low/Medium: no adjustment
  - Any Critical/High: +2 points
- [ ] Recurrence of same bug class (e.g., buffer overflow fixed, then reappears): +2 points

### Exposure surface (0-10 points)

- [ ] Network-facing (accepts data from network): +4 points
- [ ] Processes untrusted input (user files, external APIs, deserialization): +3 points
- [ ] Handles cryptographic material (keys, certificates, random): +2 points
- [ ] Runs with elevated privileges (root, SYSTEM, kernel): +2 points
- [ ] Internal-only utility with no external input: 0 points

### Risk acceleration from AI (0-5 points)

- [ ] Component uses patterns known to be easily discoverable by AI fuzzing
  (simple parsers, flat buffer handling): +3 points
- [ ] Component has limited exploit mitigations (no ASLR, no stack canaries,
  no CFI): +2 points

### Total priority score

- **20+**: Critical — migrate immediately
- **15-19**: High — schedule for next development cycle
- **8-14**: Medium — plan for migration within the roadmap period
- **0-7**: Low — migrate opportunistically or when component is modified

## Feasibility evaluation

### Blockers (any of these may prevent migration)

- [ ] Inline assembly that cannot be replaced
- [ ] Hard real-time constraint below 1μs with no MSL equivalent
- [ ] Platform with no MSL compiler support (rare embedded targets)
- [ ] Regulatory or certification requirement mandating specific language
- [ ] Component is scheduled for end-of-life/replacement — migration not worthwhile

### Complexity factors (affect timeline, not feasibility)

- [ ] Lines of code in the component
  - Under 1,000: Small — days to weeks
  - 1,000-10,000: Medium — weeks to months
  - 10,000-100,000: Large — months; consider incremental approach
  - 100,000+: Very large — must be incremental; full rewrite not recommended
- [ ] Number of external C/C++ library dependencies
  - Each dependency must have an MSL equivalent or be accessed via FFI
  - List each dependency and its MSL alternative status
- [ ] Platform-specific system call usage
  - List syscalls used; verify MSL support on all target platforms
- [ ] Existing test coverage
  - No tests: must write tests first (add to timeline)
  - Partial coverage: identify untested paths
  - Comprehensive coverage: ready for migration validation

### Team readiness

- [ ] Team expertise in target MSL
  - Expert: no training needed
  - Intermediate: minor ramp-up
  - Beginner: budget training time (2-4 weeks for productive Rust, 1-2 weeks for Go)
  - None: consider hiring or partnering; do not migrate without expertise
- [ ] Availability of code review expertise in target MSL
- [ ] CI/CD pipeline supports target MSL toolchain

## Output

After assessment, produce a migration recommendation:

```
Component: [name]
Priority score: [X] / 25
Feasibility: [Go / Go with caveats / Blocked]
Blockers: [list any]
Recommended target language: [language + rationale]
Estimated effort: [T-shirt size + calendar estimate]
Dependencies requiring FFI: [list]
Test coverage gap: [description]
Recommended migration order: [which functions/modules first]
```
