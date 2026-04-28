# FFI boundary security rules

The interface between memory-safe and memory-unsafe code is a critical attack surface.
Treat every FFI boundary with the same rigor as a network API at a trust boundary.

## Mandatory rules

### 1. Validate all inputs from the unsafe side

Every pointer, length, and value crossing from C/C++ into MSL code must be validated
before use.

```rust
// CORRECT: Full validation at the boundary
#[no_mangle]
pub extern "C" fn process_buffer(ptr: *const u8, len: usize) -> i32 {
    // Validate pointer is not null
    if ptr.is_null() {
        return -1;
    }

    // Validate length is reasonable
    if len == 0 || len > MAX_BUFFER_SIZE {
        return -2;
    }

    // Create a safe slice — this is the trust boundary crossing
    let data = unsafe { std::slice::from_raw_parts(ptr, len) };

    // From here on, all code is fully safe Rust
    match process_data_safely(data) {
        Ok(result) => result,
        Err(_) => -3,
    }
}
```

```go
// CORRECT: Go validation of C pointer via cgo
/*
#include <stdlib.h>
*/
import "C"
import "unsafe"

func ProcessBuffer(ptr *C.char, length C.int) C.int {
    if ptr == nil {
        return -1
    }
    if length <= 0 || length > maxBufferSize {
        return -2
    }

    // Convert to Go slice safely
    data := C.GoBytes(unsafe.Pointer(ptr), length)
    // data is now a Go-managed copy — safe to use
    return C.int(processDataSafely(data))
}
```

```java
// CORRECT: Java validation via Panama FFI (Java 22+)
public static int processBuffer(MemorySegment segment) {
    if (segment.equals(MemorySegment.NULL)) {
        return -1;
    }
    long size = segment.byteSize();
    if (size == 0 || size > MAX_BUFFER_SIZE) {
        return -2;
    }

    // Copy into a managed byte array
    byte[] data = segment.toArray(ValueLayout.JAVA_BYTE);
    return processDataSafely(data);
}
```

### 2. Minimize unsafe surface area

All `unsafe` blocks (Rust) or unsafe operations must be:

- **As small as possible** — wrap only the minimum necessary operation
- **Documented** with a `// SAFETY:` comment explaining the invariant being upheld
- **Isolated** behind safe abstractions that enforce the invariant via their API
- **Never used to silence the borrow checker** or bypass ownership rules

```rust
// CORRECT: Minimal, documented unsafe
fn read_c_string(ptr: *const c_char) -> Result<String, Error> {
    if ptr.is_null() {
        return Err(Error::NullPointer);
    }
    // SAFETY: We verified ptr is non-null. The caller guarantees it points
    // to a valid, null-terminated C string for the duration of this call.
    let c_str = unsafe { CStr::from_ptr(ptr) };
    c_str.to_str().map(|s| s.to_owned()).map_err(|_| Error::InvalidUtf8)
}

// WRONG: Large unsafe block doing everything
unsafe fn read_c_string_bad(ptr: *const c_char) -> String {
    CStr::from_ptr(ptr).to_str().unwrap().to_owned()
    // No null check, no error handling, entire function is unsafe
}
```

### 3. Memory ownership across FFI

The allocator that created the memory must free it. Never mix allocators.

```rust
// Correct pattern: Rust allocates, Rust provides the free function
#[no_mangle]
pub extern "C" fn create_resource() -> *mut Resource {
    Box::into_raw(Box::new(Resource::new()))
}

#[no_mangle]
pub extern "C" fn destroy_resource(ptr: *mut Resource) {
    if !ptr.is_null() {
        // SAFETY: ptr was created by create_resource via Box::into_raw.
        // Caller guarantees this is only called once per resource.
        unsafe { drop(Box::from_raw(ptr)) };
    }
}
```

Rules:
- Document who owns every pointer in every FFI function signature
- Provide paired allocate/free functions when exposing MSL allocations to C
- Never `free()` Rust-allocated memory or `drop()` C-allocated memory
- In Go, remember that cgo-allocated memory follows C rules, not Go GC rules

### 4. Error handling across FFI

- **Never panic across FFI boundaries** — this is undefined behavior in Rust
- Use C-compatible error codes or out-parameters
- Catch all panics at the FFI boundary

```rust
#[no_mangle]
pub extern "C" fn safe_entry_point(input: *const u8, len: usize) -> i32 {
    let result = std::panic::catch_unwind(|| {
        internal_logic(input, len)
    });

    match result {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => -1,    // Application error
        Err(_) => -99,       // Panic caught — return error, do not propagate
    }
}
```

In Go, panics do not cross cgo boundaries by default, but exported functions
should still use `defer/recover` for robustness:

```go
//export SafeEntryPoint
func SafeEntryPoint(input *C.char, length C.int) C.int {
    defer func() {
        if r := recover(); r != nil {
            // Log the panic, return error code
        }
    }()
    // ... processing logic
    return C.int(result)
}
```

### 5. Thread safety across FFI

- Document thread safety guarantees for every FFI function
- If the C side uses global state, protect it with synchronization on the MSL side
- In Rust, FFI functions are `unsafe` by default because the compiler cannot
  verify thread safety across language boundaries — the developer must ensure it
- In Go, be aware that goroutines may call C code concurrently; the C code must
  be thread-safe or protected by a mutex on the Go side

### 6. String encoding across FFI

- C strings are null-terminated byte sequences with no encoding guarantee
- Rust strings are UTF-8, Go strings are UTF-8, Java strings are UTF-16 internally
- Always validate encoding at the boundary
- Never assume a C string is valid UTF-8 — use fallible conversion functions
  (`CStr::to_str()` in Rust, explicit encoding conversion in Go/Java)

## Testing FFI boundaries

Every FFI boundary must be tested with:

1. **Null pointers** for every pointer parameter
2. **Zero-length** and **maximum-length** buffers
3. **Malformed input** (invalid UTF-8, truncated data, embedded nulls)
4. **Concurrent access** from multiple threads
5. **Fuzz testing** with tools like `cargo-fuzz`, `go-fuzz`, or AFL
6. **Memory sanitizers** (Miri for Rust, ASan/MSan for C side, race detector for Go)
