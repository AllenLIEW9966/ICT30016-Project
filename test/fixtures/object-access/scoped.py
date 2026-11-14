# Expected: safe for this rule, A01:2025, CWE-639. Synthetic.
def lookup(request, cursor, authenticated_owner):
    record = request.args.get("id")
    sql = "SELECT title FROM notes WHERE id = ? AND owner_id = ?"
    return cursor.execute(sql, (record, authenticated_owner))
