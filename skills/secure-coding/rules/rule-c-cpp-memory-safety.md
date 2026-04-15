---
description: Memory-safe coding in C/C++ — banned functions, safer replacements, compiler flags, common pitfalls
languages:
  - c
  - cpp
alwaysApply: false
rule_id: rule-c-cpp-memory-safety
---

# C / C++ Memory & String Safety

C and C++ remain in use precisely because they let you do things no other language does. That includes the things you didn't mean to do — off-by-one, unbounded copy, use-after-free, type confusion. This rule is about reducing the blast radius of that fact: never generate code on the known-unsafe set, migrate to bounded functions when editing, and turn on the compiler-level mitigations that make the rest of the bugs loud.

## Banned string functions

Do not generate any of the following, and replace them during any edit that touches them:

| Banned | Why | Replacement |
|--------|-----|-------------|
| `gets()` | No bounds checking at all. The textbook overflow. | `fgets(buf, sizeof buf, stream)`. |
| `strcpy()` | Copies until NUL regardless of destination size. | `snprintf(dest, sizeof dest, "%s", src)` — portable, always null-terminates. Or `strcpy_s()` with C11 Annex K. |
| `strcat()` | Same problem as `strcpy`, in reverse. | `snprintf` building the full string in one call; or `strncat(dest, src, sizeof dest - strlen(dest) - 1)`; or `strcat_s()`. |
| `sprintf()` / `vsprintf()` | No output-size argument. | `snprintf()` / `vsnprintf()` with a correct size; always check the return value. |
| `strtok()` | Not reentrant, uses static state. | `strtok_r()` (POSIX) or `strtok_s()` (Annex K). |

`scanf("%s", ...)` is fine as long as every `%s` has a width: `scanf("%63s", buf)` for a 64-byte buffer. Even better: `fgets` + `sscanf`, which gives you a complete line to parse instead of a stream you might have misread.

## Bounded memory functions

`memcpy`, `memset`, `memmove`, `memcmp`, `bzero` are not inherently unsafe — they fail when the programmer miscalculates the size. For security-sensitive code, use the bounds-checked variants from C11 Annex K where your toolchain supports them:

- `memcpy_s(dest, dest_max, src, n)` — fails if `n > dest_max`.
- `memset_s(dest, dest_max, value, n)` — also required for guaranteed zeroing of sensitive buffers (the compiler cannot elide it).
- `memmove_s`, `memcmp_s` — same pattern.

Key point: pass the **destination buffer size** (not the source size), and check the return value. Most of the "I used `_s` so it's safe" bugs are a wrong first argument.

### Sensitive-data zeroization

To wipe a key or password buffer before free, use a function the compiler is required not to optimize away:

- C11 Annex K: `memset_s(buf, sizeof buf, 0, sizeof buf)`
- Linux: `explicit_bzero(buf, sizeof buf)`
- OpenSSL: `OPENSSL_cleanse(buf, sizeof buf)`
- Windows: `SecureZeroMemory(buf, sizeof buf)`

Plain `memset(buf, 0, sizeof buf)` before `free` or returning is often compiled away by dead-store elimination.

## Patterns — the right way

### `strcpy` → `snprintf`

```c
/* unsafe */
char dest[64];
strcpy(dest, src);                    /* overflow if strlen(src) >= 64 */

/* safe */
char dest[64];
int n = snprintf(dest, sizeof dest, "%s", src);
if (n < 0 || (size_t)n >= sizeof dest) {
    /* truncated or error — handle appropriately */
}
```

### `strncpy` — the common misuse

`strncpy` is *not* a drop-in safe replacement. It pads with NULs if the source is shorter, and it does **not** null-terminate if the source is as long as or longer than the destination. Either:

```c
char dest[10];
strncpy(dest, src, sizeof dest - 1);
dest[sizeof dest - 1] = '\0';
```

or, preferred, use `snprintf`.

### `scanf("%s", ...)` → `fgets` + parse

```c
char name[32];
if (!fgets(name, sizeof name, stdin)) { /* EOF / error */ return -1; }
name[strcspn(name, "\n")] = '\0';       /* strip newline */
```

### Safe `strcat_s` usage (C11 Annex K)

```c
char buf[256] = "prefix_";
errno_t rc = strcat_s(buf, sizeof buf, suffix);
if (rc != 0) { log_error("strcat_s failed: %d", rc); return -1; }
```

### `memcpy_s` with a separate function

```c
void copy_into(char *out, size_t out_size, const char *src, size_t n) {
    errno_t rc = memcpy_s(out, out_size, src, n);
    if (rc != 0) { log_error("memcpy_s failed: %d", rc); return; }
}
```

Note: `out_size` is passed explicitly. Inside the function, `sizeof(out)` is the size of a pointer, not the buffer. This is pitfall #3 below.

## Common pitfalls

### Pitfall 1 — wrong size parameter

```c
strcpy_s(dest, strlen(src), src);   /* WRONG — using src size */
strcpy_s(dest, sizeof dest, src);    /* correct */
```

### Pitfall 2 — ignored return value

```c
strcpy_s(dest, sizeof dest, src);    /* error silently swallowed */

errno_t rc = strcpy_s(dest, sizeof dest, src);
if (rc != 0) { /* handle */ }
```

### Pitfall 3 — `sizeof` on a pointer parameter

```c
void f(char *buf) {
    strcpy_s(buf, sizeof buf, src);  /* sizeof(char*) = 8, NOT the caller's buffer size */
}

void f(char *buf, size_t buf_size) {
    strcpy_s(buf, buf_size, src);    /* correct — caller passes the size */
}
```

### Pitfall 4 — integer overflow in size arithmetic

`malloc(n * sizeof(thing))` where `n` is attacker-controlled can wrap around, producing a tiny allocation that the code then overflows. Use `calloc(n, sizeof(thing))` (which checks internally) or validate `n` before multiplying.

## Compiler flags

Turn these on (see also `rule-ci-cd-containers.md` for the CI wiring):

- `-Wall -Wextra -Wconversion -Wshadow -Wstrict-prototypes` — warnings on many classes of common mistake.
- `-Werror` — warnings fail the build. This is the real lever; warnings that are not errors rot.
- `-fstack-protector-strong` or `-fstack-protector-all` — stack canaries.
- `-D_FORTIFY_SOURCE=2` (or `=3` on recent glibc) — compile-time + runtime bounds checks for `strcpy`, `memcpy`, `sprintf`, and friends.
- `-Wformat -Wformat-security` — format string abuse.
- `-fPIE -pie` — Position-Independent Executable, enables ASLR.
- `-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack` — RELRO/now, non-executable stack.
- `-fsanitize=cfi` with LTO — Control Flow Integrity.

Debug builds additionally:

- `-fsanitize=address` (ASan), `-fsanitize=undefined` (UBSan), `-fsanitize=thread` (TSan) when relevant.

## Pre-code-review checklist for developers

- [ ] No `gets`, `strcpy`, `strcat`, `sprintf`, `strtok` in the diff.
- [ ] No unbounded `scanf("%s", ...)`.
- [ ] Sensitive buffers zeroed with `explicit_bzero` / `memset_s` before free.
- [ ] All `_s` calls pass the destination buffer size, not the source size.
- [ ] `sizeof` is not applied to a pointer parameter expecting a buffer size.
- [ ] `errno_t` / return values checked.
- [ ] Size arithmetic guarded against overflow.

## Reviewer checklist

- [ ] Memory operations use safe variants or are justified where they don't.
- [ ] Buffer sizes match allocations (`sizeof(array)` for local arrays, explicit parameter otherwise).
- [ ] Error-handling branches tested or at least reachable.
- [ ] Strings are provably null-terminated after each operation.
- [ ] Source lengths are validated before indexing / copying.

## Static and runtime analysis

- Enable compiler warnings for unsafe function usage; treat as errors.
- Run a static analyzer in CI (Clang-Tidy with the `bugprone-*` and `cert-*` checks, PVS-Studio, Coverity).
- Pre-commit hook that greps for banned function names, with a suppression mechanism that requires a comment justifying the exception.
- Fuzz parsers, decoders, and anything that reads untrusted bytes. libFuzzer and AFL++ make this close to free once a harness exists.
