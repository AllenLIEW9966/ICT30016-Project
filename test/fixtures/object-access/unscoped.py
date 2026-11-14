# Expected: vulnerable (potential unscoped lookup), A01:2025, CWE-639. Synthetic.
def lookup(request, cursor):
    record = request.args.get("id")
    sql = "SELECT title FROM notes WHERE id = ?"
    return cursor.execute(sql, (record,))
