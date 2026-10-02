# Language selection guide

Choose the target memory-safe language based on the use case, performance requirements, and ecosystem constraints.

## Decision matrix

- **Systems programming, OS, embedded, drivers — Rust:** Zero-cost abstractions, no GC, C-level performance, and
  ownership that prevents data races at compile time.
- **Network services, microservices, CLI tools — Rust or Go:** Go offers simpler concurrency and faster compilation;
  Rust offers tighter memory control.
- **Enterprise applications, web backends — Java, C#, or Go:** Mature ecosystems, strong libraries, and automatic memory
  management through GC.
- **iOS / macOS applications — Swift:** Native platform support, ARC memory management, and Apple ecosystem integration.
- **Android applications — Kotlin or Java:** Native Android support, full memory safety, and mature tooling.
- **Scripting, automation, data processing — Python:** Rapid development and extensive libraries; use Rust/C FFI for
  performance-critical paths.
- **Real-time systems with GC constraints — Rust:** Ownership provides deterministic memory management without GC
  pauses.
- **WebAssembly targets — Rust or Go:** Both compile to WASM; Rust produces smaller binaries.

## Key factors in selection

### Performance requirements

- **Latency-sensitive / real-time**: Rust (no GC pauses)
- **Throughput-focused with simpler code**: Go (GC is fast, goroutines are lightweight)
- **Acceptable GC pauses**: Java, C#, Go, Kotlin

### Team expertise

- If the team knows Go well and the use case fits, use Go — a migration in a language the team understands beats a
  theoretically superior choice they cannot maintain
- Factor in hiring: Rust expertise is growing but still less common than Go or Java
- Consider training investment vs. migration urgency

### Ecosystem and library availability

- Check that equivalent libraries exist in the target MSL before committing
- Critical dependencies (TLS, crypto, protocol parsers) must have mature, audited implementations in the target language
- If a required library only exists in C, the FFI boundary cost may outweigh benefits for that specific component

### Interoperability with existing code

- **Rust ↔ C**: Excellent. `#[no_mangle]`, `extern "C"`, `bindgen`, `cbindgen` tooling is mature
- **Go ↔ C**: Good via cgo, but cgo has performance overhead and complicates cross-compilation
- **Java ↔ C**: Via JNI or Panama FFI (Java 22+); JNI is verbose but well-understood
- **Swift ↔ C**: Direct C interop built into the language
- **C# ↔ C**: Via P/Invoke or LibraryImport; well-supported on .NET

## Memory-safe languages recognized by CISA/NSA

The following languages are recognized as memory-safe in CISA/NSA guidance:

- Ada
- C#
- Delphi / Object Pascal
- Go
- Java
- Python
- Ruby
- Rust
- Swift

Note: C and C++ are explicitly classified as memory-unsafe. Assembly language is also memory-unsafe. Using C++ with
smart pointers and static analysis reduces risk but does not achieve the memory safety guarantees provided by MSLs.
