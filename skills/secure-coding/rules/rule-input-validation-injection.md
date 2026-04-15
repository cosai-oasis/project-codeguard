---
description: Input validation and defense against injection (SQL, NoSQL, LDAP, OS command, template, prototype pollution)
languages:
  - apex
  - c
  - go
  - html
  - java
  - javascript
  - php
  - powershell
  - python
  - ruby
  - shell
  - sql
  - typescript
alwaysApply: false
rule_id: rule-input-validation-injection
---

# Input Validation & Injection Defense

## Core idea

Every injection vulnerability has the same shape: a string produced by someone untrusted is handed to an interpreter (SQL engine, shell, LDAP server, template engine, JS runtime) that treats part of it as code rather than data. The defense has two layers:

1. **Validate at the trust boundary** — decide what shape the input is allowed to have, and reject anything else *before* it reaches any interpreter.
2. **Use APIs that keep data out of the code channel** — parameterized queries, structured command execution, allow-listed tokens. Escaping is a fallback, never the primary defense.

Both layers matter. Validation alone cannot rescue an unparameterized SQL string; parameterization alone cannot stop a caller from passing a 100 MB payload through.

## Validation playbook

### Positive (allow-list) validation

For every untrusted field, define what is valid and reject the rest. Do not try to enumerate what is invalid — that list is always incomplete.

- **Syntactic**: type, format (regex anchored with `^…$`), numeric range, string length, enumeration membership.
- **Semantic**: business rules that syntax cannot express (`start ≤ end`, order totals that match line items, the user owns the referenced object).
- **Normalization before validation**: canonicalize Unicode (NFKC), decode percent-encoding, unwrap equivalent representations. Validate the *normalized* value, then use it consistently.

### Free-form text

When the input genuinely is prose:
- Define an allowed character class (Unicode category ranges, not ASCII-only).
- Set a hard length bound.
- Normalize Unicode.
- Remember that "free-form" does not excuse XSS encoding when the value is later rendered.

### Regex watch-outs

- Always anchor (`^…$`) — an unanchored regex is almost never what you want.
- Beware ReDoS: nested quantifiers (`(a+)+`), alternation with common prefixes, and `.*` before a required match are the usual triggers. Prefer parser-based validators or atomic/possessive groups when the engine supports them.

### Files

Files are inputs too. Validate by content (magic-byte sniffing) and by size cap, in addition to extension. Generate a server-side filename rather than trusting the client's. See `rule-file-upload-handling.md` for the full checklist.

## SQL injection — parameterize, don't escape

The default must be parameterized queries / bound variables for 100% of data access. Concatenation of user input into SQL is never acceptable.

Java (JDBC):

```java
String query = "SELECT account_balance FROM user_data WHERE user_name = ?";
try (PreparedStatement pstmt = connection.prepareStatement(query)) {
    pstmt.setString(1, request.getParameter("customerName"));
    try (ResultSet rs = pstmt.executeQuery()) {
        // …
    }
}
```

Python (DB-API 2.0):

```python
cur.execute("SELECT balance FROM accounts WHERE user_id = %s", (user_id,))
```

Go (database/sql):

```go
row := db.QueryRowContext(ctx, "SELECT balance FROM accounts WHERE user_id = $1", userID)
```

Node.js (pg):

```js
const { rows } = await client.query(
  'SELECT balance FROM accounts WHERE user_id = $1',
  [userID]
);
```

### Dynamic identifiers (column/table names)

Placeholders bind *values*, not identifiers. If the column or table name must vary, validate it against an explicit allow-list of known strings. Never assemble an identifier from user input via string concatenation.

### Stored procedures

A stored procedure does not automatically prevent SQL injection. If the procedure concatenates its inputs into dynamic SQL internally, the hole is still there. Bind parameters inside the procedure, too.

### Privilege

Application database users must not have schema-modifying rights, superuser/root, or access to tables outside their scope. A SQL injection is far less dangerous when the compromised account can only read three tables.

## SOQL / SOSL (Salesforce Apex)

SOQL and SOSL do not have SQL's DDL/DML surface, but they can still be manipulated to exfiltrate data by bypassing filters — and if results are subsequently fed to DML, the blast radius grows.

- Prefer static queries with bind variables:
  - `[SELECT Id FROM Account WHERE Name = :userInput]`
  - `FIND :term IN ALL FIELDS RETURNING Account`
- Dynamic SOQL → `Database.queryWithBinds()`; dynamic SOSL → `Search.query()`.
- Any dynamic identifier (field, object, order-by) must pass an allow-list check.
- Fall back to `String.escapeSingleQuotes()` only when concatenation is truly unavoidable.
- Enforce CRUD/FLS with `WITH USER_MODE` or `WITH SECURITY_ENFORCED` (pick one, don't combine). Use `with sharing` or user-mode DML. Run `Security.stripInaccessible()` before DML to remove fields the caller cannot see.

## LDAP injection

LDAP has two injection contexts that need separate escaping:

- **Distinguished Name (DN) context** — escape `\  #  +  <  >  ,  ;  "  =` and leading/trailing spaces.
- **Filter context** — escape `*  (  )  \  NUL`.

Validate with an allow-list before building the query, and use a library that exposes proper DN/filter encoding (for example `javax.naming.ldap.LdapName`, Python's `ldap3.utils.dn.escape_rdn`). Bind as the least-privileged account that works.

## OS command injection

Default answer: do not shell out. The standard library almost always has a function for what the shell command does.

If a subprocess is genuinely required:

- Use structured execution that keeps the command and its arguments in separate slots — not a single concatenated string. `ProcessBuilder` in Java, `subprocess.run([...], shell=False)` in Python, `exec.Command(name, args...)` in Go.
- Do **not** invoke a shell (`/bin/sh -c`, `cmd.exe /c`). The moment a shell is in the chain, metacharacters become active.
- Allow-list the command itself and validate every argument against an allow-list regex (no `&  |  ;  $  >  <  \` ``  !  "  '  (  )`, no whitespace unless intentional).
- Use `--` where supported to separate options from positional arguments, preventing flag injection.

Java (ProcessBuilder, safe pattern):

```java
ProcessBuilder pb = new ProcessBuilder("/usr/bin/trusted_tool", "--mode", modeArg, "--", fileArg);
pb.directory(new File("/var/app/work"));
pb.redirectErrorStream(true);
Process p = pb.start();
```

Python:

```python
subprocess.run(
    ["/usr/bin/trusted_tool", "--mode", mode_arg, "--", file_arg],
    shell=False,
    check=True,
    timeout=30,
)
```

## Template / expression-language injection

Many template engines (Jinja2, Freemarker, Velocity, Handlebars, Twig, ERB) happily execute code if you hand them untrusted templates. Treat these as dangerous:

- Never render a template whose source string came from user input.
- If user input must be substituted into a template, pass it as a variable in the render context — not concatenated into the template body.
- Disable runtime eval features where possible (sandbox mode, `StrictUndefined`, etc.).

## Prototype pollution (JavaScript / TypeScript)

JavaScript's prototype chain means assignments to `__proto__`, `constructor.prototype`, and `prototype` on shared objects leak into every sibling object.

Patterns:

- Prefer `new Map()` / `new Set()` over plain objects for dictionaries.
- When an object is required as a lookup, create it without a prototype: `Object.create(null)` or `{ __proto__: null }`.
- Freeze or seal objects that should not change (`Object.freeze`, `Object.seal`).
- Avoid unvetted deep-merge utilities. If you must merge, validate keys against an allow-list and explicitly block `__proto__`, `constructor`, `prototype`.
- Run Node.js with `--disable-proto=delete` in hardened environments as defense in depth.

## NoSQL injection (MongoDB, etc.)

A BSON object parsed from JSON is *still* structured input. If the client can send `{"$ne": null}` where a string was expected, operator injection is in play.

- Validate that query-filter fields have the expected scalar types before passing them to the driver.
- Disable operator parsing in ORMs where possible (Mongoose `sanitizeFilter`, e.g.).
- Use parameterized query builders rather than hand-constructed filter objects.

## XPath / XQuery injection

Parameterize via the API (`javax.xml.xpath.XPath.setXPathVariableResolver`, `lxml.etree.XPath(expr, variable_dict)`), do not concatenate user input into the expression.

## Caching and transport

- Responses containing validated-but-sensitive data should carry `Cache-Control: no-store`. A validator does not help if a shared cache already returned someone else's row.
- Enforce HTTPS for every endpoint that handles untrusted input — an on-path attacker can rewrite input before your validator sees it.

## Implementation checklist

- Central validators exist for each input type (and are actually used, not bypassed for "simple" endpoints).
- 100% parameterization for SQL and SOQL; dynamic identifiers go through allow-lists.
- LDAP DN and filter encoding is performed by a library call, not ad-hoc string replacement.
- No shell is invoked with untrusted input; if a subprocess is used, command + args are structured and allow-listed.
- JavaScript dictionaries use safe constructors; prototype paths blocked in any merge utility.
- Template engines never render user-supplied templates.
- Every file upload goes through `rule-file-upload-handling.md`'s checks.

## Test plan

- Static scan for string concatenation in query/command sinks (`Statement.executeQuery(".."+x)`, `exec.Command("sh", "-c", ...)` etc.).
- Fuzzing with classic payloads: `' OR 1=1--`, `${jndi:ldap:...}`, `$(id)`, `{{7*7}}`, `__proto__`.
- Unit tests for validator edge cases — boundary lengths, Unicode homoglyphs, mixed encodings.
- Negative tests that exercise each blocked prototype key and each rejected file shape.
