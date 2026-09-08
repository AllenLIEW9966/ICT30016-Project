from __future__ import annotations

import ast

PYTHON_RULES: list[dict] = []


def _rule(**kwargs):
    PYTHON_RULES.append(kwargs)


# A03:2021 Injection — SQL string concatenation via cursor.execute with f-string / format / + concat
def _sql_injection_fstring(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr != "execute":
        return False
    if not node.args:
        return False
    arg = node.args[0]
    if isinstance(arg, ast.JoinedStr):
        return True
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        return True
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
        return True
    return False


# A03:2021 Injection — os.system / subprocess with string concat
def _cmd_injection(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in {"system", "popen", "call", "run"}:
        return False
    if not node.args:
        return False
    arg = node.args[0]
    return isinstance(arg, (ast.JoinedStr, ast.BinOp))


# A02:2021 Cryptographic Failures — MD5 / SHA1 usage
def _md5_usage(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute) and node.func.attr == "md5":
        return True
    if isinstance(node.func, ast.Call) and getattr(node.func.func, "id", None) == "md5":
        return True
    return False


def _sha1_usage(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute) and node.func.attr == "sha1":
        return True
    if isinstance(node.func, ast.Call) and getattr(node.func.func, "id", None) == "sha1":
        return True
    return False


# A05:2021 Security Misconfiguration — debug=True
def _debug_true(node: ast.Assign) -> bool:
    return any(
        isinstance(t, ast.Name) and t.id == "DEBUG" for t in node.targets
    ) and isinstance(node.value, ast.Constant) and node.value.value is True


# A03:2021 — eval() usage
def _eval_usage(node: ast.Expr) -> bool:
    return (
        isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "eval"
    )


# A04:2021 — hardcoded secret
_SECRET_KEYWORDS = {"PASSWORD", "SECRET", "API_KEY", "TOKEN", "CREDENTIAL"}


def _hardcoded_secret(node: ast.Assign) -> bool:
    for target in node.targets:
        if isinstance(target, ast.Name):
            if any(kw in target.id.upper() for kw in _SECRET_KEYWORDS):
                return True
    return False


# A03:2021 — exec() / compile() arbitrary code execution
def _exec_usage(node: ast.Expr) -> bool:
    return (
        isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id in {"exec", "compile"}
    )


# A08:2021 — pickle.loads / yaml.load unsafe deserialization
def _unsafe_deserialize(node: ast.Call) -> bool:
    if isinstance(node.func, ast.Attribute) and node.func.attr in {"loads", "load"}:
        return True
    if isinstance(node.func, ast.Call) and getattr(node.func.func, "id", None) in {"loads", "load"}:
        return True
    return False


# A01:2021 — open() with user-controlled path
def _open_user_path(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Name) or node.func.id != "open":
        return False
    if not node.args:
        return False
    first = node.args[0]
    if isinstance(first, ast.JoinedStr):
        return True
    if isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
        return True
    return False


# A10:2021 — requests.get/post with user-controlled URL
def _ssrf_requests(node: ast.Call) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in {"get", "post", "put", "delete", "head"}:
        return False
    if not node.args:
        return False
    first = node.args[0]
    if isinstance(first, (ast.JoinedStr, ast.BinOp)):
        return True
    return False


# ---- rule declarations ----

_rule(
    id="PY-SQLI-001",
    title="Potential SQL Injection",
    severity="critical",
    confidence="high",
    cwe_id="CWE-89",
    owasp_ref="A03:2021-Injection",
    message="Dynamic SQL query built with user-controlled input. Use parameterized queries.",
    suggestion="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (user_id,))",
    checker="call",
    matches=_sql_injection_fstring,
)

_rule(
    id="PY-CMD-001",
    title="Potential Command Injection",
    severity="critical",
    confidence="medium",
    cwe_id="CWE-78",
    owasp_ref="A03:2021-Injection",
    message="Shell command constructed with dynamic input. Use shlex.split() or subprocess list form.",
    suggestion="Use list form: subprocess.run(['ls', user_path], check=True)",
    checker="call",
    matches=_cmd_injection,
)

_rule(
    id="PY-CRYPTO-001",
    title="Weak Hashing Algorithm (MD5)",
    severity="high",
    confidence="high",
    cwe_id="CWE-328",
    owasp_ref="A02:2021-Cryptographic-Failures",
    message="MD5 is cryptographically broken. Use SHA-256 or better.",
    suggestion="Use hashlib.sha256() or secrets.compare_digest()",
    checker="call",
    matches=_md5_usage,
)

_rule(
    id="PY-CRYPTO-002",
    title="Weak Hashing Algorithm (SHA1)",
    severity="high",
    confidence="high",
    cwe_id="CWE-328",
    owasp_ref="A02:2021-Cryptographic-Failures",
    message="SHA1 is deprecated for security-sensitive uses. Use SHA-256+.",
    suggestion="Use hashlib.sha256() or secrets.compare_digest()",
    checker="call",
    matches=_sha1_usage,
)

_rule(
    id="PY-CONFIG-001",
    title="Debug Mode Enabled",
    severity="medium",
    confidence="high",
    cwe_id="CWE-489",
    owasp_ref="A05:2021-Security-Misconfiguration",
    message="Debug mode should be disabled in production.",
    suggestion="Set debug=False and use environment-based config.",
    checker="assign",
    matches=_debug_true,
)

_rule(
    id="PY-CODE-EXEC-001",
    title="Dangerous eval() Usage",
    severity="critical",
    confidence="high",
    cwe_id="CWE-95",
    owasp_ref="A03:2021-Injection",
    message="eval() executes arbitrary code and is a major security risk.",
    suggestion="Use ast.literal_eval() or parse with json.loads() for data.",
    checker="eval",
    matches=_eval_usage,
)

_rule(
    id="PY-CODE-EXEC-002",
    title="Dangerous exec()/compile() Usage",
    severity="critical",
    confidence="high",
    cwe_id="CWE-94",
    owasp_ref="A03:2021-Injection",
    message="exec()/compile() can execute arbitrary code. Avoid with untrusted input.",
    suggestion="Use safer parsing or explicit handlers instead of dynamic execution.",
    checker="eval",
    matches=_exec_usage,
)

_rule(
    id="PY-SECRETS-001",
    title="Potential Hardcoded Secret",
    severity="high",
    confidence="medium",
    cwe_id="CWE-798",
    owasp_ref="A04:2021-Insecure-Design",
    message="Assignment name suggests a secret. Use environment variables or secret managers.",
    suggestion="Load from os.environ or a secrets manager: os.environ['DB_PASSWORD']",
    checker="assign",
    matches=_hardcoded_secret,
)

_rule(
    id="PY-SERIAL-001",
    title="Unsafe Deserialization (pickle/yaml)",
    severity="critical",
    confidence="high",
    cwe_id="CWE-502",
    owasp_ref="A08:2021-Software-and-Data-Integrity-Failures",
    message="Unsafe deserialization can lead to arbitrary code execution.",
    suggestion="Use yaml.safe_load() or avoid pickle.loads() with untrusted data.",
    checker="call",
    matches=_unsafe_deserialize,
)

_rule(
    id="PY-PATH-001",
    title="Potential Path Traversal",
    severity="high",
    confidence="medium",
    cwe_id="CWE-22",
    owasp_ref="A01:2021-Broken-Access-Control",
    message="File path appears to be built with dynamic input. Validate and sanitize paths.",
    suggestion="Use os.path.abspath() and check the resolved path is within an allowed directory.",
    checker="call",
    matches=_open_user_path,
)

_rule(
    id="PY-SSRF-001",
    title="Potential SSRF via requests",
    severity="high",
    confidence="medium",
    cwe_id="CWE-918",
    owasp_ref="A10:2021-Server-Side-Request-Forgery-(SSRF)",
    message="HTTP request made with user-controlled URL. Validate URL scheme and host.",
    suggestion="Allowlist domains and reject private/internal IP ranges before requests.",
    checker="call",
    matches=_ssrf_requests,
)
