---
description: Memory-safe systems code (C, C++, unsafe Rust, FFI, bounds, ownership, lifetime)
languages:
- c
- cpp
- rust
alwaysApply: false
---

# Write Memory-Safe Systems Code

**Scope:** C, C++, unsafe Rust, FFI and native APIs, manual allocation, raw pointers, buffer and size arithmetic, variadics, unions, and attacker-controlled binary parsing; not memory-safe application code without an unsafe/native boundary, ordinary concurrency, or out-of-scope rewrites.

**Inputs:** The language/standard and compiler versions, target ABI and integer widths, ownership and lifetime model, buffer objects and extents, overlap possibilities, allocator/deallocator pairs, FFI contracts, attacker-controlled sizes, error/unwind behavior, and available native-code checks.

**Expected result:** New unsafe code is avoided where feasible; necessary native operations have explicit, locally maintained bounds, arithmetic, ownership, lifetime, initialization, overlap, ABI, and cleanup invariants.

## Preserve

Preserve ABI, wire/file format, performance requirements that are measured and material, platform support, and existing safe abstractions. Prefer a memory-safe language or safe library boundary for new/high-risk components when compatible with the task; do not promise that a mechanical rewrite alone preserves behavior or security.

## Required outcomes for applicable changes

- Derive copy/read/write lengths from the actual destination and source objects, validate them before pointer arithmetic or allocation, and reject integer overflow, truncation, sign conversion, underflow, and element-versus-byte confusion.
- Use `memcpy` only when the valid source and destination ranges do not overlap; use `memmove` when they may overlap. Neither function supplies bounds checking.
- Maintain a single explicit owner for every allocation/resource, pair allocators correctly, initialize values before use, and prevent use-after-free, double free, dangling references, invalid iterators, and cleanup omissions.
- Preserve string termination and encoding invariants explicitly. Do not treat `strncpy` as a generic safe replacement or assume truncation is acceptable.
- Document every unsafe/FFI boundary’s pointer validity, lengths, alignment, aliasing, lifetime, ownership transfer, thread, callback, ABI, unwind/exception, and error-return contract; expose a narrow safe wrapper where the language supports one.
- Check allocation, I/O, conversion, and system-call results before consuming outputs; leave objects in a valid state on error, cancellation, panic, exception, or partial initialization.
- **Context-dependent:** Annex K `_s` functions are usable only when the target implementation provides them and the project deliberately accepts their runtime-constraint semantics; they are not portable or inherently sufficient.
- **Context-dependent:** Compiler hardening, sanitizers, static analysis, and fuzzing improve evidence but do not prove absence of undefined behavior or memory defects.

## Procedure

1. **Shrink the unsafe boundary.** Reuse a maintained safe abstraction or move parsing/copying into a memory-safe component when feasible. If unsafe code remains, keep it private and make its preconditions explicit.
2. **Model every object and size.** Identify allocation extent, initialized extent, element size, terminator, maximum input, pointer provenance, alignment, and whether ranges can overlap. Perform checked arithmetic before allocation or access.
3. **Choose the operation by semantics.** Select bounded container/string APIs or explicit validated copy operations according to required truncation, termination, overlap, and error behavior. Do not substitute a banned-function list for reasoning about the actual object.
4. **Define ownership and lifetime.** Record who creates, borrows, transfers, invalidates, and releases each resource. Make partial construction and all failure exits clean up exactly what was acquired.
5. **Seal FFI and unsafe Rust.** Validate foreign values before constructing safe references or slices, preserve ABI/calling convention, prohibit unwinding across an incompatible boundary, and ensure safe callers cannot violate the wrapper’s invariants.
6. **Preserve concurrency invariants.** Synchronize shared mutable native state and confirm callbacks cannot outlive or race the objects they reference.
7. **Exercise boundary values.** Test zero, one, exact capacity, capacity minus/plus one, maximum supported size, overflow candidates, malformed/truncated input, overlap, allocation failure, and repeated cleanup using project-supported checks.

## Unsafe near-misses

- Blanket-banning `memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strcmp`, or `strstr` without analyzing object validity, bounds, overlap, termination, and timing requirements.
- Replacing `strcpy` with `strncpy` while losing termination, silently truncating, or padding unexpectedly.
- Assuming a destination array’s size survives pointer decay, or multiplying attacker-controlled counts without checked arithmetic.
- Calling `realloc` directly into the only owning pointer and losing the original allocation on failure.
- Returning a safe Rust reference whose lifetime, alignment, initialization, aliasing, or ownership cannot be upheld for every safe caller.
- Letting C++ exceptions or Rust panics cross an FFI boundary whose ABI does not permit unwinding.
- Treating a clean sanitizer or fuzzing run as proof of memory safety.

## Focused evidence

- Exercise boundary and malformed inputs under the project’s supported compiler warnings and sanitizer configuration where available.
- Run a focused fuzz target for an attacker-controlled native parser or unsafe wrapper when the repository already supports it or the scoped change includes such coverage.
- Review each changed allocation/copy/FFI site against the concrete object extents, checked arithmetic, ownership, and failure exits.
- For safe wrappers, attempt calls at the edge of every documented precondition and confirm safe callers cannot trigger undefined behavior.
