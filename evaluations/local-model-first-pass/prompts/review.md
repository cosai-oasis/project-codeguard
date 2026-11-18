Review this Python function for actionable security problems. It belongs to a
service where an authenticated user may read only their own notes.

Assumptions: `conn` is an existing standard-library SQLite connection with the
default tuple row factory. `current_user_id` is supplied by a trusted
authentication layer. `note_id` is untrusted request input and may be a string;
no earlier validation or authorization check is present. The table has columns
`id`, `owner_id`, and `body`. Authentication is performed before this function.

Line numbers are relative to this supplied snippet:

```python
def get_note(conn, current_user_id, note_id):
    query = f"SELECT id, owner_id, body FROM notes WHERE id = '{note_id}'"
    return conn.execute(query).fetchone()
```

For each finding, cite the line, explain the data flow or missing check, and
give a concrete remediation. Do not execute the code. Distinguish confirmed
problems from possibilities not supported by these assumptions.

After the answer, identify any supplied guidance rule IDs you used and the
specific finding supported by each. If none was supplied or used, say so.
Do not invent rule IDs.
