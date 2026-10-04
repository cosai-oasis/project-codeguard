"""Intentionally insecure evaluation fixture for issue #73; do not execute.

Its defects are review targets, not production bugs to repair in this file.
Only the function body is supplied to the model; this header and the assessment
rubric are excluded from the model prompt.
"""


def get_note(conn, current_user_id, note_id):
    query = f"SELECT id, owner_id, body FROM notes WHERE id = '{note_id}'"
    return conn.execute(query).fetchone()
