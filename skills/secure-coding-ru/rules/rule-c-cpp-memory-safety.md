---
description: Memory-safe программирование на C/C++ — запрещённые функции, безопасные замены, флаги компилятора, типовые ловушки
languages:
  - c
  - cpp
alwaysApply: false
rule_id: rule-c-cpp-memory-safety
---

# Memory- и string-safety для C / C++

C и C++ в ходу именно потому, что позволяют делать то, чего не даёт ни один другой язык. Сюда же входит то, чего вы делать не собирались: off-by-one, unbounded copy, use-after-free, type confusion. Это правило — про сокращение blast-радиуса этого факта: никогда не генерировать код на known-unsafe наборе, мигрировать на bounded-функции при правке, включать компиляторные митигации, делающие остальные баги громкими.

## Запрещённые строковые функции

Ничего из перечисленного не генерируем, заменяем при любой правке, касающейся этого кода:

| Запрещено | Почему | Замена |
|-----------|--------|--------|
| `gets()` | Нет bounds-check вообще. Хрестоматийный overflow. | `fgets(buf, sizeof buf, stream)`. |
| `strcpy()` | Копирует до NUL независимо от размера dest-а. | `snprintf(dest, sizeof dest, "%s", src)` — портативно, всегда null-term. Или `strcpy_s()` из C11 Annex K. |
| `strcat()` | Та же проблема, что у `strcpy`, с другой стороны. | `snprintf`, собирающий всю строку одним вызовом; или `strncat(dest, src, sizeof dest - strlen(dest) - 1)`; или `strcat_s()`. |
| `sprintf()` / `vsprintf()` | Нет аргумента размера вывода. | `snprintf()` / `vsnprintf()` с правильным размером; всегда проверяйте возврат. |
| `strtok()` | Не реентрантна, использует статическое состояние. | `strtok_r()` (POSIX) или `strtok_s()` (Annex K). |

`scanf("%s", ...)` допустим, если у каждой `%s` задана ширина: `scanf("%63s", buf)` для 64-байтного буфера. Ещё лучше — `fgets` + `sscanf`: вы получаете полную строку для разбора, а не поток, который можно неверно вычитать.

## Bounded memory-функции

`memcpy`, `memset`, `memmove`, `memcmp`, `bzero` по себе небезопасны не врождённо — они падают, когда программист неправильно посчитал размер. Для security-чувствительного кода — bounds-checked варианты из C11 Annex K, там, где их поддерживает тулчейн:

- `memcpy_s(dest, dest_max, src, n)` — падает, если `n > dest_max`.
- `memset_s(dest, dest_max, value, n)` — также нужен для гарантированного обнуления чувствительных буферов (компилятор не вправе его выбросить).
- `memmove_s`, `memcmp_s` — тот же шаблон.

Ключевое: передаём **размер буфера-приёмника** (не источника) и проверяем возврат. Большинство багов «я использовал `_s`, значит безопасно» — неверный первый аргумент.

### Обнуление чувствительных данных

Чтобы затереть буфер ключа или пароля перед free, используйте функцию, которую компилятор не имеет права выбросить:

- C11 Annex K: `memset_s(buf, sizeof buf, 0, sizeof buf)`
- Linux: `explicit_bzero(buf, sizeof buf)`
- OpenSSL: `OPENSSL_cleanse(buf, sizeof buf)`
- Windows: `SecureZeroMemory(buf, sizeof buf)`

Простой `memset(buf, 0, sizeof buf)` перед `free` или return-ом часто оптимизируется dead-store-elimination-ом.

## Паттерны — как правильно

### `strcpy` → `snprintf`

```c
/* небезопасно */
char dest[64];
strcpy(dest, src);                    /* overflow, если strlen(src) >= 64 */

/* безопасно */
char dest[64];
int n = snprintf(dest, sizeof dest, "%s", src);
if (n < 0 || (size_t)n >= sizeof dest) {
    /* обрезано или ошибка — обрабатывайте */
}
```

### `strncpy` — типовое неправильное использование

`strncpy` *не* drop-in-безопасная замена. Она добивает NUL-ами, если источник короче, и **не** null-терминирует, если источник не короче dest. Либо:

```c
char dest[10];
strncpy(dest, src, sizeof dest - 1);
dest[sizeof dest - 1] = '\0';
```

либо, предпочтительно, `snprintf`.

### `scanf("%s", ...)` → `fgets` + разбор

```c
char name[32];
if (!fgets(name, sizeof name, stdin)) { /* EOF / ошибка */ return -1; }
name[strcspn(name, "\n")] = '\0';       /* срезаем \n */
```

### Безопасный `strcat_s` (C11 Annex K)

```c
char buf[256] = "prefix_";
errno_t rc = strcat_s(buf, sizeof buf, suffix);
if (rc != 0) { log_error("strcat_s failed: %d", rc); return -1; }
```

### `memcpy_s` с отдельной функцией

```c
void copy_into(char *out, size_t out_size, const char *src, size_t n) {
    errno_t rc = memcpy_s(out, out_size, src, n);
    if (rc != 0) { log_error("memcpy_s failed: %d", rc); return; }
}
```

Замечание: `out_size` передаётся явно. Внутри функции `sizeof(out)` — это размер указателя, не буфера. Это ловушка #3 ниже.

## Типовые ловушки

### Ловушка 1 — неверный параметр размера

```c
strcpy_s(dest, strlen(src), src);   /* НЕВЕРНО — берём размер src */
strcpy_s(dest, sizeof dest, src);    /* корректно */
```

### Ловушка 2 — игнорируемый возврат

```c
strcpy_s(dest, sizeof dest, src);    /* ошибка молча проглотилась */

errno_t rc = strcpy_s(dest, sizeof dest, src);
if (rc != 0) { /* обработка */ }
```

### Ловушка 3 — `sizeof` на параметре-указателе

```c
void f(char *buf) {
    strcpy_s(buf, sizeof buf, src);  /* sizeof(char*) = 8, НЕ размер буфера у вызывающего */
}

void f(char *buf, size_t buf_size) {
    strcpy_s(buf, buf_size, src);    /* корректно — вызывающий передаёт размер */
}
```

### Ловушка 4 — integer overflow в арифметике размера

`malloc(n * sizeof(thing))`, где `n` контролирует атакующий, может обернуться, дав маленькую аллокацию, в которую код затем и переполняется. Используйте `calloc(n, sizeof(thing))` (он проверяет внутри) или валидируйте `n` до умножения.

## Флаги компилятора

Включайте (см. также `rule-ci-cd-containers.md` про CI-wiring):

- `-Wall -Wextra -Wconversion -Wshadow -Wstrict-prototypes` — предупреждения по классам типичных ошибок.
- `-Werror` — предупреждения валят сборку. Это и есть настоящий рычаг; варнинги-не-ошибки гниют.
- `-fstack-protector-strong` или `-fstack-protector-all` — stack-canaries.
- `-D_FORTIFY_SOURCE=2` (или `=3` на свежей glibc) — compile-time + runtime bounds-check для `strcpy`, `memcpy`, `sprintf` и родственников.
- `-Wformat -Wformat-security` — злоупотребление format-string.
- `-fPIE -pie` — Position-Independent Executable, включает ASLR.
- `-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack` — RELRO/now, non-executable stack.
- `-fsanitize=cfi` с LTO — Control Flow Integrity.

Дополнительно в debug-сборках:

- `-fsanitize=address` (ASan), `-fsanitize=undefined` (UBSan), `-fsanitize=thread` (TSan), где применимо.

## Чек-лист разработчика до code-review

- [ ] В диффе нет `gets`, `strcpy`, `strcat`, `sprintf`, `strtok`.
- [ ] Нет unbounded `scanf("%s", ...)`.
- [ ] Чувствительные буферы обнулены `explicit_bzero` / `memset_s` до free.
- [ ] Все `_s`-вызовы передают размер буфера-приёмника, не источника.
- [ ] `sizeof` не применён к параметру-указателю, ожидающему размер буфера.
- [ ] `errno_t` / возвраты проверены.
- [ ] Арифметика размера защищена от overflow.

## Чек-лист ревьюера

- [ ] Memory-операции используют безопасные варианты, либо обосновано обратное.
- [ ] Размеры буферов соответствуют аллокациям (`sizeof(array)` для локальных массивов, явный параметр иначе).
- [ ] Ветки обработки ошибок протестированы или по крайней мере достижимы.
- [ ] После каждой операции строка доказуемо null-терминирована.
- [ ] Длины источников валидируются до индексации / копирования.

## Статический и рантайм-анализ

- Включайте предупреждения компилятора про небезопасные функции; считайте их ошибками.
- Гоняйте статический анализатор в CI (Clang-Tidy с чеками `bugprone-*` и `cert-*`, PVS-Studio, Coverity).
- Pre-commit-хук, grep-ающий запрещённые имена функций, с механизмом suppress-а, требующим комментарий-обоснование.
- Фаззьте парсеры, декодеры, всё, что читает недоверенные байты. libFuzzer и AFL++ делают это практически бесплатным, как только есть harness.
