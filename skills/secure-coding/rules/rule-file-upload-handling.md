---
description: Secure file upload and file handling — validation, storage isolation, scanning, safe delivery
languages:
  - c
  - go
  - java
  - javascript
  - php
  - python
  - ruby
  - typescript
alwaysApply: false
rule_id: rule-file-upload-handling
---

# File Handling & Uploads

## Threat model

A file upload endpoint accepts untrusted binary content from the network and writes it to the server's filesystem. Every detail matters — the filename, the extension, the declared content type, the actual bytes, the storage location, the URL that eventually serves it, and who can reach that URL.

The defense is *layered*: no single check is sufficient. A malicious PNG can carry a valid magic number, a benign extension, and still execute if served from a location that treats it as code.

## Extension validation

- **Allow-list** the small set of extensions the feature needs. Deny-listing `.exe` misses `.pif`, `.bat`, `.sh`, `.jsp`, `.jspx`, `.phar`, `.phtml`, etc.
- Validate after decoding the filename — `.php%00.jpg` turns into `.php\0.jpg` and may truncate back to `.php` depending on the consumer.
- Reject double extensions (`avatar.jpg.php`) unless the application explicitly expects them.
- Apply this check after general input validation (length, character class).

## Content-Type and magic byte validation

- The `Content-Type` header in the upload is client-supplied. Never trust it as the sole source of truth.
- Sniff the actual magic bytes and compare to the allow-listed MIME types. Libraries: `file-type` (Node), `python-magic`, Apache Tika, Go `net/http.DetectContentType` (as a baseline — it only sniffs the first 512 bytes, which is not always enough).
- Accept the upload only if (declared MIME, sniffed MIME, extension) all agree and all are in the allow-list.
- Magic-byte sniffing is necessary, not sufficient — polyglot files (valid PNG + valid JAR, for example) defeat sniffing alone.

## Filename handling

- **Default choice**: generate a new filename (UUID v4 or similar) server-side and use it everywhere. The original filename is metadata, not a path component.
- If the original filename must be preserved:
  - Enforce a maximum length (255 bytes for most filesystems, 260 on Windows paths).
  - Restrict to `[A-Za-z0-9._-]` plus spaces. Reject everything else.
  - Disallow leading `.` (hidden files, `.htaccess`) and leading `-` (breaks many CLI tools).
  - Collapse runs of `.` (the user's `screenshot...png` becomes `screenshot.png`) and explicitly block `..`.

## Content validation

- For images: **re-encode** via a library (`Pillow`, `libvips`, `ImageMagick` with restricted policies). Re-encoding preserves the picture and drops anything parasitic hiding in metadata or between chunks. This is by far the most effective defense for image uploads.
- For Microsoft Office / PDF documents: validate with the vendor-tested parser (Apache POI, PDFBox); run through a Content Disarm & Reconstruction (CDR) step if the threat model justifies it.
- For archives (ZIP, tar): treat as dangerous. Numerous attack classes live here — zip-slip path traversal, zip bombs, nested archive depth, symlink entries. If the feature allows archives, enforce:
  - Extracted path stays under the target directory (validate after joining).
  - Total uncompressed size cap *and* compression-ratio cap (a 10 KB file expanding to 10 GB is a zip bomb).
  - Reject entries with absolute paths or `..` components.
  - Reject symlink and device-node entries outright.
- When the threat model allows delay, run uploads through an AV / sandboxed analyzer before they become visible to other users.

## Storage

- Store uploaded files **outside the web root**. The web application serves them through a controlled download endpoint, not by direct URL.
- Ideally, store on a separate server or object storage (S3 and equivalents). If stored locally, set filesystem permissions so the web server process cannot execute files in the upload directory (no `+x`; disable `Options ExecCGI`; `php_admin_flag engine off` in an `.htaccess` or equivalent).
- Use an application-layer mapping: `GET /files/<opaque-id>` resolves to `<uuid>` on disk. Users never see storage filenames or paths.
- For databases: storing small files in the database can be reasonable for specific use cases (attachments tied tightly to a row), but it usually doesn't scale and complicates backup/restore. Consider object storage as the default.

## Access control

- Authentication is required before upload.
- Authorization decides who can upload which type of file and into which "folder" / context. See `rule-authorization-access-control.md`.
- **Every download** checks authorization. Do not rely on filename opacity — that's security through obscurity. An opaque filename plus an authorization check is correct.
- Filesystem permissions follow least privilege — the web worker cannot write outside the upload tree; the upload tree cannot be read by anyone else.

## Size and rate limits

- Hard per-file size limit (web server and application layer; both, not only one).
- Per-request and per-user aggregate size / count limits.
- Post-decompression size cap for compressed uploads (see archive handling above).
- For downloads: rate-limit to prevent bandwidth exhaustion and scraping.

## Safe delivery

- Set `Content-Disposition: attachment; filename="..."` to force the browser to treat the response as a download, not as something to render in-page. This kills most of the "uploaded HTML becomes stored XSS" class of bugs.
- Set `X-Content-Type-Options: nosniff` so the browser does not second-guess the declared MIME.
- Set `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` on the download response to hem in anything that does render.
- Serve from a **different origin** than the application, when feasible. Even if a malicious SVG ends up rendered, it is in a throwaway sandbox origin, not in the origin that holds user session cookies.

## Additional controls

- CSRF-protect the upload endpoint — same rules as any state-changing request (`rule-client-web-browser.md`).
- Log every upload: who, when, size, declared type, sniffed type, resulting opaque ID. Dashboards on that log catch unusual patterns.
- Keep parsing libraries up to date (`rule-supply-chain-dependencies.md`). Image libraries and document parsers are a common CVE source.
- Where the domain permits, offer a user-reporting mechanism for abusive content.

## Implementation checklist

1. Extension, content-type, and magic-byte checks all pass and all agree with an allow-list.
2. Server-generated filenames; original names only used as metadata if at all.
3. Images re-encoded; documents validated; archives size- and path-checked.
4. Storage outside the web root; web server cannot execute within upload tree.
5. Authenticated upload, authorized download, no direct URL exposure.
6. Size limits at multiple layers; compression-ratio cap for archives.
7. `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and ideally a sandbox origin for delivery.
8. CSRF protection on upload; structured logging of events.
