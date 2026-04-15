---
description: Authorization and access control — least privilege, IDOR prevention, mass assignment, step-up authorization
languages:
  - c
  - go
  - java
  - javascript
  - php
  - python
  - ruby
  - typescript
  - yaml
alwaysApply: false
rule_id: rule-authorization-access-control
---

# Authorization & Access Control

## Mental model

Authentication answers *"who is this?"*. Authorization answers *"is this particular action on this particular object allowed right now?"*. The two must be separate — and authorization must be checked on every request, not just at the login step or at the gateway.

## Four principles, in priority order

1. **Default deny.** If no rule explicitly allows the action, the answer is `403 Forbidden`. Adding a rule is always an intentional decision.
2. **Least privilege.** Grant the minimum permissions required. Permissions expand silently over time; budget ongoing pruning, not a one-time grant.
3. **Check on every request.** Do not assume a caller who reached this endpoint is authorized for it. Middleware, route filters, or explicit checks at the top of every handler — something consistent.
4. **ABAC / ReBAC over RBAC when the resource model has relationships.** Roles break down as soon as "this user can edit this document because they are a collaborator on the parent project." A role cannot express that; an attribute or relationship can.

## Systemic patterns

- Centralize the decision point. A scattered `if user.role == 'admin':` across 40 handlers drifts out of sync. Put the policy in middleware, a filter, or a PDP (policy decision point) that every handler consults.
- Scope data queries by the subject. `currentUser.documents.find(id)` is safer than `Document.find(id)` because the database enforces the boundary.
- Return the same response for "not authorized" and "does not exist" (often `404` for GET, `403` on unsafe methods) so the API doesn't enumerate resource IDs.
- Log every denial with `user_id`, action, resource type + ID (or a stable hash), and a short rationale code. Dashboards on that data reveal both attacks and bugs.

## Preventing IDOR (Insecure Direct Object Reference)

IDOR happens when an endpoint accepts a caller-supplied identifier and looks up the object *without* verifying the caller's relationship to it.

Broken:

```python
# POST /api/orders/{order_id}/cancel
order = Order.objects.get(pk=order_id)  # cancels anyone's order
order.cancel()
```

Fixed:

```python
order = Order.objects.get(pk=order_id, customer=request.user)  # raises DoesNotExist otherwise
order.cancel()
```

### Guidelines

- Always resolve the object through a user-scoped query, or fetch by ID and then check ownership *before* any side effect.
- Use non-enumerable identifiers (UUID v4, random tokens) as defense in depth. Sequential integer IDs are a gift to attackers.
- Object-level checks must happen at the *service* layer, not only at the gateway — other code paths can reach the object without going through that gateway.

## Preventing mass assignment

Do not bind a request body directly to a domain object. Fields that are meant to be server-controlled (`role`, `is_admin`, `balance`, `created_at`, `user_id`) will silently accept attacker input.

Use DTOs or explicit field lists:

Java (Jackson):

```java
public class UpdateProfileRequest {
    @JsonProperty("display_name") public String displayName;
    @JsonProperty("bio")          public String bio;
}
```

Python (Django serializer):

```python
class UpdateProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['display_name', 'bio']  # explicit — never "__all__"
```

Ruby on Rails:

```ruby
params.require(:profile).permit(:display_name, :bio)
```

Deny-list approaches (`.except(:role)`) are brittle — any new sensitive field added later is exposed by default. Allow-list every time.

## Step-up / transaction authorization

For high-impact operations — wire transfer, export of all data, role grants, disabling MFA — require a second, transaction-specific approval:

- Show the user the exact critical fields they are approving (amount, recipient, scope). This is "What You See Is What You Sign" — the confirmation must reflect the transaction that will actually be performed.
- Generate a unique, short-lived, single-use authorization token bound to the transaction. Any change to the transaction data invalidates the token.
- Enforce the step-up on the server, not in the UI. A request without a valid step-up token is rejected regardless of what the UI did.
- On failure, restart the whole flow — do not let the attacker retry the approval step alone.

## Testing and automation

Maintain an authorization matrix as data — YAML or JSON listing endpoints × roles × expected outcomes. An excerpt:

```yaml
- path: /api/admin/users
  method: GET
  expected:
    admin: allow
    editor: deny
    viewer: deny
    unauthenticated: deny

- path: /api/orders/{id}
  method: DELETE
  expected:
    admin: allow
    owner_of_order: allow
    other_customer: deny
    unauthenticated: deny
```

A test suite iterates the matrix, mints a token for each role, fires the request, and asserts allow/deny. Negative tests (ID swapping, role downgrade, missing scope, token replay after rotation) are required.

## Implementation checklist

- Every route has an authorization check — no route is implicitly allowed.
- The check happens at the service layer, not only at the gateway.
- Queries are scoped by owner/tenant; direct-by-ID lookups always verify relationship before any side effect.
- Request-to-model binding uses DTOs or explicit allow-lists; sensitive fields are not bindable.
- Step-up authorization is wired in for privileged operations with unique, short-lived, single-use tokens.
- Authorization matrix exists as data and is exercised in CI; failures block merges.
- Denials are logged and surfaced in dashboards.
