# Common migration patterns

Side-by-side patterns for migrating C/C++ code to memory-safe languages.

## Buffer operations

### C (vulnerable)
```c
void process(const char *input, size_t len) {
    char buffer[256];
    memcpy(buffer, input, len);  // Buffer overflow if len > 256
}
```

### Rust (safe)
```rust
fn process(input: &[u8]) {
    let mut buffer = vec![0u8; input.len()];
    buffer.copy_from_slice(input); // Panics if sizes mismatch — no silent overflow
}
```

### Go (safe)
```go
func process(input []byte) {
    buffer := make([]byte, len(input))
    copy(buffer, input) // copy is bounds-safe, copies min(dst, src) bytes
}
```

## String handling

### C (vulnerable)
```c
char *concat(const char *a, const char *b) {
    char *result = malloc(strlen(a) + strlen(b) + 1);
    if (!result) return NULL; // Often forgotten
    strcpy(result, a);   // Unsafe
    strcat(result, b);   // Unsafe
    return result;        // Caller must free — easy to forget
}
```

### Rust (safe)
```rust
fn concat(a: &str, b: &str) -> String {
    format!("{}{}", a, b) // Allocation, sizing, UTF-8 all handled
}
```

### Go (safe)
```go
func concat(a, b string) string {
    return a + b // Strings are immutable, concatenation allocates safely
}
// For many concatenations, use strings.Builder for performance
```

### Java (safe)
```java
String concat(String a, String b) {
    return a + b; // Or use StringBuilder for loops
}
```

## Linked data structures

### C (vulnerable)
```c
struct Node {
    int value;
    struct Node *next;  // Raw pointer — no ownership semantics
};
// Manual insert, delete, traversal — use-after-free, dangling pointers
```

### Rust (safe)
```rust
// Option 1: Ownership-based
enum List {
    Cons(i32, Box<List>),
    Nil,
}

// Option 2: Just use the standard library
use std::collections::VecDeque; // or LinkedList, but VecDeque is usually better
```

### Go (safe)
```go
// Use the standard library
import "container/list"

l := list.New()
l.PushBack(42)
// GC handles all memory — no dangling pointers possible
```

## Concurrency

### C (vulnerable — data race)
```c
static int counter = 0;
// Multiple threads increment — undefined behavior without locks
void increment() { counter++; }
```

### Rust (safe — compiler-enforced)
```rust
use std::sync::atomic::{AtomicI32, Ordering};

static COUNTER: AtomicI32 = AtomicI32::new(0);

fn increment() {
    COUNTER.fetch_add(1, Ordering::SeqCst);
}

// For complex shared state, Mutex<T> prevents access without holding the lock:
use std::sync::Mutex;
let shared = Mutex::new(vec![1, 2, 3]);
{
    let mut data = shared.lock().unwrap();
    data.push(4); // Lock held — safe
} // Lock automatically released
```

### Go (safe — channels or sync)
```go
import "sync/atomic"

var counter int64

func increment() {
    atomic.AddInt64(&counter, 1)
}

// Or use channels for CSP-style concurrency:
ch := make(chan int, 100)
go func() { ch <- computeResult() }()
result := <-ch
```

## Error handling

### C (easy to ignore)
```c
int result = do_something();
// Return code often unchecked — errors silently ignored
```

### Rust (compiler-enforced)
```rust
// Result<T, E> must be handled — compiler warns on unused Result
fn do_something() -> Result<Value, Error> {
    let data = read_file()?;  // ? propagates errors automatically
    let parsed = parse(data)?;
    Ok(parsed)
}
```

### Go (explicit but not enforced)
```go
result, err := doSomething()
if err != nil {
    return fmt.Errorf("do_something failed: %w", err) // Wrap for context
}
// Use result
```

## File and resource handling

### C (easy to leak)
```c
FILE *f = fopen("data.txt", "r");
// ... processing that might return early or throw
// fclose(f) might never execute — resource leak
```

### Rust (automatic via RAII)
```rust
// File is automatically closed when it goes out of scope
let contents = std::fs::read_to_string("data.txt")?;
// Or for explicit control:
{
    let file = File::open("data.txt")?;
    // use file
} // file.drop() called automatically — fd closed
```

### Go (defer pattern)
```go
f, err := os.Open("data.txt")
if err != nil {
    return err
}
defer f.Close() // Guaranteed to run when function returns
// ... processing
```

### Java (try-with-resources)
```java
try (var reader = new BufferedReader(new FileReader("data.txt"))) {
    // use reader
} // Automatically closed, even on exception
```

## Array/slice operations

### C (no bounds checking)
```c
int arr[10];
arr[15] = 42;  // Buffer overflow — undefined behavior, no error
```

### Rust (bounds checked)
```rust
let mut arr = [0i32; 10];
arr[15] = 42; // Panics at runtime with clear error message
// Or use .get() for recoverable bounds checking:
if let Some(val) = arr.get_mut(15) {
    *val = 42;
} else {
    // Handle out-of-bounds gracefully
}
```

### Go (bounds checked)
```go
arr := make([]int, 10)
arr[15] = 42 // Panics with "index out of range [15] with length 10"
```

## Dynamic memory

### C (manual, error-prone)
```c
int *data = malloc(n * sizeof(int));
if (!data) { /* handle OOM — often forgotten */ }
// ... use data
// Must remember to free at every exit path
free(data);
// data is now a dangling pointer if accessed again
```

### Rust (ownership system)
```rust
let data: Vec<i32> = vec![0; n]; // Allocation checked, zeroed
// ... use data
// Automatically freed when data goes out of scope
// Compiler prevents use-after-free at compile time
```

### Go (garbage collected)
```go
data := make([]int, n) // Allocation and zeroing handled
// ... use data
// GC frees when no references remain — no dangling pointers possible
```

## Network server pattern

### C (manual socket management)
```c
int server_fd = socket(AF_INET, SOCK_STREAM, 0);
struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(8080) };
bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
listen(server_fd, SOMAXCONN);
// Manual accept loop, buffer management, error handling for every syscall
// Thread management, connection cleanup — hundreds of lines
```

### Rust (safe, async)
```rust
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn(async move {
            handle_connection(socket).await;
        });
    }
}
```

### Go (safe, concurrent)
```go
func main() {
    listener, err := net.Listen("tcp", ":8080")
    if err != nil {
        log.Fatal(err)
    }
    defer listener.Close()

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        go handleConnection(conn) // Safe concurrent handling
    }
}
```
