"""O-02 fallback: deterministic templates when the local LLM is down.

Each entry returns an applicable patch for the finding's rule_id.
Used by suggest_fix when the AI call fails, but only when a narrow,
context-checked replacement can be derived safely.
Language-aware: only returns a template when the language matches.
"""
from __future__ import annotations

import ast
import json
import re
import shlex

_TEMPLATES: dict[tuple[str, str], dict] = {
    ("python", "PY-SQLI-001"): {
        "explanation": "Replace interpolated SQL values with placeholders and pass the values separately.",
        "secure_code": "",
    },
    ("python", "PY-SECRETS-001"): {
        "explanation": "Hardcoded credential in source. Load it from the environment instead.",
        "secure_code": "",
    },
    ("python", "PY-CMD-001"): {
        "explanation": "Shell string built from input allows command injection. Avoid shell=True and pass argv list.",
        "secure_code": "import subprocess\nsubprocess.run([\"ls\", path], shell=False, check=True)",
    },
    ("python", "PY-PATH-001"): {
        "explanation": "Dynamic path may escape the data dir. Resolve and allowlist the prefix.",
        "secure_code": (
            "import os\nbase = os.path.abspath('/data')\n"
            "p = os.path.abspath(os.path.join(base, path))\n"
            "assert p.startswith(base + os.sep), 'path traversal blocked'"
        ),
    },
    ("python", "PY-SSRF-001"): {
        "explanation": "User-controlled URL may hit internal hosts. Allowlist scheme+host before requesting.",
        "secure_code": (
            "from urllib.parse import urlparse\n"
            "u = urlparse(url)\n"
            "assert u.scheme in {'http', 'https'} and u.hostname in ALLOWED_HOSTS\n"
            "requests.get(url, timeout=10)"
        ),
    },
    ("python", "PY-SERIAL-001"): {
        "explanation": "pickle/yaml load can execute code. Use a safe loader for untrusted data.",
        "secure_code": "import yaml\ndata = yaml.safe_load(payload)",
    },
    ("python", "PY-CODE-EXEC-001"): {
        "explanation": "eval() runs arbitrary code. Parse data with a safe parser instead.",
        "secure_code": "import ast, json\nvalue = ast.literal_eval(text)  # or json.loads(text)",
    },
    ("python", "PY-CODE-EXEC-002"): {
        "explanation": "exec()/compile() run arbitrary code. Dispatch to explicit handlers instead.",
        "secure_code": "# replace exec(name) with explicit handler map\nHANDLERS[name]()",
    },
    ("python", "PY-CRYPTO-001"): {
        "explanation": "MD5 is broken. Use SHA-256 for integrity.",
        "secure_code": "import hashlib\ndigest = hashlib.sha256(data).hexdigest()",
    },
    ("python", "PY-CRYPTO-002"): {
        "explanation": "SHA1 is deprecated. Use SHA-256 for integrity.",
        "secure_code": "import hashlib\ndigest = hashlib.sha256(data).hexdigest()",
    },
    ("javascript", "JS-SQLI-001"): {
        "explanation": "Query built with concat/template lets input alter SQL. Use placeholders.",
        "secure_code": "db.query('SELECT * FROM users WHERE id = ?', [userId])",
    },
    ("javascript", "JS-XSS-001"): {
        "explanation": "innerHTML with untrusted data enables XSS. Use textContent or sanitize.",
        "secure_code": "el.textContent = msg; // or: el.innerHTML = DOMPurify.sanitize(msg)",
    },
    ("javascript", "JS-SECRETS-001"): {
        "explanation": "Hardcoded secret in source. Load from environment.",
        "secure_code": "const API_KEY = process.env.API_KEY;",
    },
    ("javascript", "JS-RANDOM-001"): {
        "explanation": "Math.random is predictable. Use Web Crypto for security values.",
        "secure_code": "const buf = new Uint32Array(1); crypto.getRandomValues(buf);",
    },
    ("javascript", "JS-JWT-001"): {
        "explanation": "jwt.decode skips signature checks. Verify with a trusted key.",
        "secure_code": "jsonwebtoken.verify(token, secretOrPublicKey);",
    },
    ("javascript", "JS-CODE-EXEC-001"): {
        "explanation": "eval() runs arbitrary code. Parse data safely instead.",
        "secure_code": "const value = JSON.parse(text);",
    },
    ("javascript", "JS-CODE-EXEC-002"): {
        "explanation": "new Function() runs arbitrary code. Use explicit functions instead.",
        "secure_code": "const fn = handlers[name];",
    },
}


def _contextual_sql_fix(code_snippet: str, full_source: str, line: int) -> str | None:
    """Build a parameterized replacement only for simple, understood f-string SQL."""
    if not full_source:
        return None
    try:
        tree = ast.parse(full_source)
    except SyntaxError:
        return None

    target_call: ast.Call | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "execute" or node.lineno != line or not node.args:
            continue
        segment = ast.get_source_segment(full_source, node)
        if segment and code_snippet.strip() and segment.strip() != code_snippet.strip():
            # Allow the diagnostic to cover only the call expression with different spacing.
            if not segment.strip().startswith(code_snippet.strip()):
                continue
        target_call = node
        break
    if target_call is None:
        return None

    query_expr = target_call.args[0]
    if isinstance(query_expr, ast.Name):
        assignments = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            and node.lineno < target_call.lineno
            and any(isinstance(t, ast.Name) and t.id == query_expr.id for t in (node.targets if isinstance(node, ast.Assign) else [node.target]))
        ]
        if not assignments:
            return None
        assignment = max(assignments, key=lambda item: item.lineno)
        query_expr = assignment.value
    if not isinstance(query_expr, ast.JoinedStr):
        return None

    chunks: list[str | None] = []
    params: list[str] = []
    for part in query_expr.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            chunks.append(part.value)
        elif isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name):
            chunks.append(None)
            params.append(part.value.id)
        else:
            return None
    if not params:
        return None

    sql = ""
    for index, chunk in enumerate(chunks):
        if chunk is not None:
            sql += chunk
            continue
        if sql.endswith(("'", '"')):
            sql = sql[:-1]
        sql += "?"
        next_chunk = chunks[index + 1] if index + 1 < len(chunks) else None
        if isinstance(next_chunk, str) and next_chunk.startswith(("'", '"')):
            chunks[index + 1] = next_chunk[1:]
    if not re.match(r"(?is)^\s*(select|insert|update|delete)\b", sql):
        return None

    function = ast.get_source_segment(full_source, target_call.func)
    if not function:
        return None
    tuple_values = ", ".join(params)
    if len(params) == 1:
        tuple_values += ","
    return f"{function}({sql!r}, ({tuple_values}))"


def _contextual_command_fix(code_snippet: str, full_source: str, line: int) -> str | None:
    """Replace a subprocess.run(shell=True) call only for a simple fixed f-string command."""
    if not full_source:
        return None
    try:
        tree = ast.parse(full_source)
    except SyntaxError:
        return None

    target: ast.Call | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno != line:
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "run":
            continue
        if not isinstance(node.func.value, ast.Name) or node.func.value.id != "subprocess":
            continue
        shell_true = any(
            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            for keyword in node.keywords
        )
        if shell_true and node.args and isinstance(node.args[0], ast.Name):
            target = node
            break
    if target is None:
        return None

    command_name = target.args[0].id
    assignments: list[ast.AST] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.lineno >= target.lineno:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(item, ast.Name) and item.id == command_name for item in targets):
            assignments.append(node)
    if len(assignments) != 1:
        return None
    assignment = max(assignments, key=lambda item: item.lineno)
    command_value = assignment.value
    if not isinstance(command_value, ast.JoinedStr):
        return None

    markers: dict[str, str] = {}
    pieces: list[str] = []
    for part in command_value.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            pieces.append(part.value)
        elif isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name) and part.format_spec is None:
            marker = f"CODESHIELD_ARG_{len(markers)}_TOKEN"
            markers[marker] = part.value.id
            pieces.append(marker)
        else:
            return None
    if not markers:
        return None
    try:
        tokens = shlex.split("".join(pieces), posix=True)
    except ValueError:
        return None
    if not tokens or any(marker in token and token != marker for token in tokens for marker in markers):
        return None

    argv = [markers.get(token, json.dumps(token)) for token in tokens]
    original_call = ast.get_source_segment(full_source, target)
    selected = code_snippet.strip()
    if not original_call or selected and original_call.strip() != selected:
        return None
    function = ast.get_source_segment(full_source, target.func)
    if not function:
        return None
    args = [f"[{', '.join(argv)}]"]
    for argument in target.args[1:]:
        segment = ast.get_source_segment(full_source, argument)
        if not segment:
            return None
        args.append(segment)
    shell_keyword_seen = False
    for keyword in target.keywords:
        if keyword.arg == "shell":
            args.append("shell=False")
            shell_keyword_seen = True
            continue
        segment = ast.get_source_segment(full_source, keyword.value)
        if not segment:
            return None
        args.append(f"{keyword.arg}={segment}" if keyword.arg else f"**{segment}")
    if not shell_keyword_seen:
        return None
    return f"{function}({', '.join(args)})"


def template_fix(
    language: str,
    rule_id: str,
    *,
    code_snippet: str = "",
    full_source: str = "",
    line: int = 1,
) -> dict | None:
    key = ((language or "").lower(), (rule_id or "").upper())
    # normalise 'js' -> 'javascript'
    if key[0] == "js":
        key = ("javascript", key[1])
    # Only context-aware, single-range templates are safe to offer automatically.
    if key not in {("python", "PY-SQLI-001"), ("python", "PY-SECRETS-001"), ("python", "PY-CMD-001")}:
        return None
    tpl = _TEMPLATES.get(key)
    if tpl is None:
        return None
    secure_code = tpl["secure_code"]
    if key == ("python", "PY-SQLI-001"):
        secure_code = _contextual_sql_fix(code_snippet, full_source, line) or ""
        if not secure_code:
            return None
    elif key == ("python", "PY-SECRETS-001"):
        if not re.search(r"\bimport\s+os\b|\bfrom\s+os\s+import\s+environ\b", full_source):
            return None
        match = re.match(r"\s*([A-Za-z_]\w*)\s*=", code_snippet)
        if not match:
            return None
        variable = match.group(1)
        secure_code = f'{variable} = os.environ["{variable}"]'
    elif key == ("python", "PY-CMD-001"):
        secure_code = _contextual_command_fix(code_snippet, full_source, line) or ""
    if not secure_code:
        return None
    return {
        "explanation": tpl["explanation"] + " (context-checked rule-based fallback)",
        "secure_code": secure_code,
        "references": [],
    }
