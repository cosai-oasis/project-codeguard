---
name: memory-safe-migration
description: >-
  Guide secure migration of code from memory-unsafe languages (C, C++, Assembly)
  to memory-safe languages (Rust, Go, Java, C#, Swift). Use when migrating or
  rewriting legacy C/C++ code, designing FFI boundaries between safe and unsafe
  code, writing new modules in existing C/C++ codebases, reviewing mixed-language
  projects, planning memory safety roadmaps, or when an AI agent is about to
  generate new C/C++ code that could be written in a memory-safe language instead.
  Also triggers on CISA/NSA memory safety compliance discussions.
license: CC-BY-4.0
metadata:
  author: codeguard-community
  version: "1.0"
  category: memory-safety
---

# Memory-safe language migration

## When this skill activates

- User asks to migrate, port, or rewrite C/C++ code to Rust, Go, Java, C#, or Swift
- User asks to add a new module or feature to an existing C/C++ project
- User asks to design an FFI boundary between safe and unsafe code
- User asks about memory safety roadmaps or CISA/NSA compliance
- User asks to review mixed-language code for safety issues
- AI agent is about to generate new C/C++ code — check if an MSL alternative is viable

## Decision: new code language selection

Before writing any new code, ask:

1. Is there an explicit constraint requiring C/C++? (bare-metal with no MSL runtime,
   hard real-time below 1μs, existing codebase policy)
2. If no constraint exists, default to a memory-safe language
3. Select the target language using the guide in [references/language-selection.md](references/language-selection.md)

If the project is predominantly C/C++, write the new module in an MSL and integrate
via FFI. See [references/ffi-security.md](references/ffi-security.md) for boundary rules.

## Migration workflow

Follow these steps for every migration task:

### Step 1: Assess the component

Run the assessment script to evaluate migration priority and feasibility:

```bash
python scripts/assess-migration.py --file <source_file>
```

Or manually evaluate using the checklist in [references/assessment-checklist.md](references/assessment-checklist.md).

Priority order for migration:
1. Network-facing code (parsers, protocol handlers, TLS)
2. Code handling untrusted input (file parsers, deserialization)
3. Cryptographic implementations
4. Privilege boundary code (auth enforcement)
5. Code with a history of memory-related CVEs
6. Internal utility code

### Step 2: Write tests first

Never migrate a component without test coverage. If no tests exist, write them
against the C/C++ implementation before touching anything. These tests become the
correctness oracle for the new implementation.

### Step 3: Migrate incrementally

One function or module at a time. Never rewrite an entire codebase in one pass.
Follow the Android model: new code in MSL, existing stable code stays in place,
proportion of unsafe code decreases over time.

For common migration patterns (buffers, strings, concurrency, error handling),
see [references/migration-patterns.md](references/migration-patterns.md).

### Step 4: Secure the FFI boundary

Every interface between safe and unsafe code is a security boundary. Follow all
rules in [references/ffi-security.md](references/ffi-security.md). Key rules:

- Validate all inputs from the unsafe side (null checks, bounds checks, type checks)
- Minimize `unsafe` blocks — wrap only the minimum necessary operation
- Document every `unsafe` block with a `// SAFETY:` comment
- The allocator that created memory must free it — never mix allocators
- Never panic across FFI boundaries
- Catch all panics with `std::panic::catch_unwind` at FFI entry points

### Step 5: Validate

After every migration unit, verify:

- All existing tests pass against the new implementation
- No new `unsafe` surface without documented safety invariants
- FFI boundaries fuzzed with malformed inputs, null pointers, extreme lengths
- Memory safety tools run clean (Miri for Rust, race detector for Go, ASan for C side)
- Performance benchmarked against the original — no unacceptable regression
- All new MSL dependencies audited for trustworthiness and active maintenance

### Step 6: Update build and CI

- Integrate the MSL toolchain (cargo, go build, etc.) into the existing build system
- Add MSL-specific linting (`clippy` for Rust, `go vet` for Go)
- Add formatting checks (`rustfmt`, `gofmt`)
- Add safety-specific CI checks (deny `unsafe` without annotation, dependency audit)

## Anti-patterns to prevent

Never do these during migration:

- **Wrapping unsafe C in a "safe" API without actual safety guarantees** — if the
  wrapper just passes through without validation, it provides false confidence
- **Using `unsafe` to replicate C-style patterns in Rust** — if extensive `unsafe`
  is needed, the approach should be redesigned or the code should remain in C
- **Migrating without tests** — write tests for C/C++ first, then validate MSL version
- **Ignoring error handling differences** — C uses return codes, Rust uses `Result`,
  Go uses multiple returns. Every error path must be explicitly mapped
- **Assuming GC languages need no resource discipline** — they prevent memory corruption
  but can still leak file handles, sockets, and connections. Use `defer`, `try-with-resources`,
  `using`, or `with` patterns
- **Migrating performance-critical loops without benchmarking** — verify first

## References

For detailed guidance on specific topics:

- [Language selection guide](references/language-selection.md)
- [FFI boundary security rules](references/ffi-security.md)
- [Common migration patterns](references/migration-patterns.md)
- [Assessment checklist](references/assessment-checklist.md)
