---
description: Resource allocation limits and denial-of-service prevention (rate limiting, quotas, memory bounds, connection management)
languages:
- c
- go
- java
- javascript
- python
- ruby
- rust
- typescript
- yaml
alwaysApply: false
---

rule_id: codeguard-0-resource-limits-dos-prevention

## Resource Limits & Denial-of-Service Prevention

Bound every resource that external input can influence. Unbounded allocation is the root cause of most denial-of-service conditions in application code.

### Rate Limiting

- Apply rate limits to all public-facing endpoints. Use token bucket or sliding window algorithms.
- Enforce stricter limits on authentication endpoints (login, password reset, MFA verification) to prevent credential brute-forcing.
- Rate limit by multiple dimensions: source IP, authenticated user, API key, and endpoint.
- Return HTTP 429 with a `Retry-After` header when limits are exceeded. Do not disclose internal rate limit configuration in response bodies.
- For distributed systems, use a shared rate limit store (Redis, Memcached) to prevent per-instance bypass.

### Request Size and Payload Limits

- Set maximum request body sizes at the web server, reverse proxy, and application layers.
- Limit individual field lengths, array sizes, and object nesting depth in parsed input (JSON, XML, multipart).
- Reject requests that exceed limits early, before allocating buffers or performing parsing.
- For file uploads, enforce maximum file size and total upload size per request.
- For streaming endpoints, enforce maximum stream duration and total bytes transferred.

### Memory and Buffer Management

- Pre-allocate fixed-size buffers where possible. Avoid unbounded dynamic allocation driven by user input.
- Cap in-memory collection sizes (lists, maps, queues) when populated from external data.
- Set JVM heap limits (`-Xmx`), container memory limits (`memory` in Docker/K8s), and language-runtime memory caps.
- Monitor memory usage and trigger graceful degradation (rejecting new requests, shedding load) before OOM conditions.

### Connection and Concurrency Limits

- Configure maximum concurrent connections at the load balancer, reverse proxy, and application server.
- Set connection timeouts (connect, read, write, idle) at every layer. Drop idle connections aggressively.
- Limit connection pool sizes for databases, caches, and external service clients. Configure pool exhaustion behavior (fail-fast vs. bounded wait).
- Use thread pool or worker pool sizing with hard upper bounds. Queue excess work with bounded queue depths and reject overflow.

### Compute and Recursion Limits

- Set maximum execution time for request handlers. Kill or abort requests that exceed the deadline.
- Limit recursion depth for any recursive processing of user-supplied data (JSON parsing, XML entity expansion, graph traversal).
- For regular expression processing, use engines that guarantee linear-time matching or enforce match timeout limits to prevent ReDoS.
- Limit iteration counts for loops driven by external input.

### Disk and Storage Quotas

- Enforce per-user and per-tenant storage quotas for file uploads, generated artifacts, and log output.
- Set maximum log file sizes with rotation policies. Prevent log flooding from filling disk.
- Use temporary directories with size limits for intermediate processing. Clean up temp files on request completion or timeout.

### Database and Query Limits

- Set query execution timeouts at the database connection level.
- Limit result set sizes with `LIMIT` clauses or pagination. Never return unbounded result sets.
- Cap the number of concurrent queries per user or tenant.
- For search endpoints, limit query complexity (number of terms, wildcard usage, join depth).

### Queue and Background Job Limits

- Set maximum queue depth for message queues and job queues. Reject or dead-letter messages when queues are full.
- Limit the number of concurrent background jobs per user or tenant.
- Enforce maximum job execution time with hard kill after deadline.
- Implement backpressure mechanisms to slow producers when consumers fall behind.

### Network and External Call Limits

- Set timeouts on all outbound HTTP calls, DNS lookups, and external service requests.
- Use circuit breakers to stop calling failing downstream services. Configure failure thresholds and recovery windows.
- Limit the number of concurrent outbound connections per downstream dependency.
- Cap retry attempts with exponential backoff and jitter. Never retry indefinitely.

### Kubernetes and Container Specific

- Set CPU and memory `requests` and `limits` on all containers.
- Configure Horizontal Pod Autoscaler (HPA) with maximum replica counts.
- Use `LimitRange` and `ResourceQuota` objects to enforce per-namespace resource ceilings.
- Set `terminationGracePeriodSeconds` to bound shutdown time.

### Implementation Checklist

- Rate limits applied to all public endpoints, with stricter limits on auth endpoints
- Maximum request body size configured at server and application layers
- Connection pool sizes bounded for all external dependencies (database, cache, APIs)
- Request handler timeouts configured
- Container memory and CPU limits set
- Queue depths bounded with overflow handling
- Outbound call timeouts and circuit breakers configured
- Pagination enforced on all list/search endpoints
- Disk quotas and log rotation configured
- Recursion and iteration depth limits set for user-input-driven processing

### Test Plan

- Load test endpoints to verify rate limits trigger correctly
- Send oversized payloads and confirm rejection before full parsing
- Exhaust connection pools and verify fail-fast or bounded-wait behavior
- Trigger compute-intensive operations and verify timeout enforcement
- Fill queues to capacity and verify overflow rejection or dead-lettering
- Verify container resource limits are enforced by orchestrator
