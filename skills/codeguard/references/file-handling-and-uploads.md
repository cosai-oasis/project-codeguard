---
description: Secure file handling & uploads (validation, storage isolation, scanning, safe delivery)
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
---

rule_id: codeguard-0-file-handling-and-uploads

## File Handling & Uploads

Accept user files with defense-in-depth: multi-layered validation, safe generated filenames, isolated storage, proper access controls, size limits, and comprehensive monitoring. Never rely on a single validation method.

### Extension Validation
- List allowed extensions only for business-critical functionality.
- Ensure input validation is applied before validating extensions.
- Avoid double extensions (e.g., `.jpg.php`) and null byte injection (e.g., `.php%00.jpg`).
- Use allowlist approach rather than denylist for file extensions.
- Validate extensions after decoding filename to prevent bypass attempts.

### Content Type and File Signature Validation
- Never trust client-supplied Content-Type headers as they can be spoofed.
- Validate file signatures (magic numbers) in conjunction with Content-Type checking.
- Implement allowlist approach for MIME types as a quick protection layer.
- Use file signature validation but not as a standalone security measure.

### Filename Security
- Generate random filenames (UUID/GUID) instead of using user-supplied names.
- If user filenames are required, implement maximum length limits.
- Restrict characters to alphanumeric, hyphens, spaces, and periods only.
- Prevent leading periods (hidden files) and sequential periods (directory traversal).
- When a path must include user input, canonicalize it and verify it stays within the intended base directory before opening it (path traversal).
- Avoid leading hyphens or spaces for safer shell script processing.

### File Content Validation
- For images, apply image rewriting techniques to destroy malicious content.
- For Microsoft documents, validate with a maintained parser for your platform (e.g., Apache POI).
- Avoid ZIP files due to numerous attack vectors.
- If archives must be extracted, resolve each entry's path and confirm it stays inside the destination directory (zip slip), reject symlinks and hard links, and cap total size, file count, and compression ratio.
- Implement manual file review in sandboxed environments when resources allow.
- Integrate antivirus scanning and Content Disarm & Reconstruct (CDR) for applicable file types.

### Storage Security
- Store files on different servers for complete segregation when possible.
- Store files outside webroot with administrative access only.
- If storing in webroot, set write-only permissions with proper access controls.
- Use application handlers that map IDs to filenames for public access.
- Serve uploads with a server-chosen `Content-Type`, `X-Content-Type-Options: nosniff`, and `Content-Disposition: attachment` (or serve from a separate origin); treat SVG and HTML as active content that can carry stored XSS.
- Consider database storage for specific use cases with DBA expertise.

### Access Control and Authentication
- Require user authentication before allowing file uploads.
- Implement proper authorization levels for file access and modification.
- Set filesystem permissions on principle of least privilege.
- Scan files before execution if execution permission is required.

### Upload and Download Limits
- Set proper file size limits for upload protection.
- Consider post-decompression size limits for compressed files.
- Implement request limits for download services to prevent DoS attacks.
- Use secure methods to calculate ZIP file sizes safely.

### Additional Security Measures
- Protect file upload endpoints from CSRF attacks.
- Keep all file processing libraries securely configured and updated.
- Implement logging and monitoring for upload activities.
- Provide user reporting mechanisms for illegal content.
- Use secure extraction methods for compressed files.

### Implementation Checklist
- Allow-listed extensions validated after filename decoding; double extensions and null bytes rejected.
- Content-Type never trusted alone; file signatures checked alongside a MIME type allow-list.
- Filenames generated server-side (UUID/GUID); any user-supplied names length- and character-restricted.
- File content rewritten, scanned (antivirus/CDR), or reviewed in a sandbox as appropriate for the type.
- Files stored outside webroot or on separate servers and served through ID-to-filename handlers.
- Uploads require authentication and authorization; filesystem permissions follow least privilege.
- Upload size, post-decompression size, and download request limits enforced.
- Upload endpoints CSRF-protected, processing libraries current, and upload activity logged and monitored.
