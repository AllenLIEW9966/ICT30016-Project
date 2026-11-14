from __future__ import annotations

import ast
import re

PYTHON_RULES: list[dict] = []


def _rule(**kwargs):
    PYTHON_RULES.append(kwargs)


# A03:2021 Injection — SQL string concatenation via cursor.execute with f-string / format / + concat
# O-03 extension: also flag tainted Name (variable holding dynamic query) so
# q = "..." + u; cursor.execute(q) is caught, not just inline concat.
def _assigned_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_assigned_names(item) for item in target.elts))
    return set()


def _expression_is_dynamic(expr: ast.AST, tainted: set[str]) -> bool:
    if isinstance(expr, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in expr.values)
    if isinstance(expr, ast.Name):
        return expr.id in tainted
    if isinstance(expr, ast.BinOp):
        return _expression_is_dynamic(expr.left, tainted) or _expression_is_dynamic(expr.right, tainted)
    if isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Name) and expr.func.id in {"input", "getenv", "getattr"}:
            return True
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "get":
            return True
        if isinstance(expr.func, ast.Attribute) and expr.func.attr in {"format", "format_map"}:
            return True
        return any(_expression_is_dynamic(arg, tainted) for arg in expr.args)
    return False


def _mark_tainted(tree: ast.AST) -> set[str]:
    """Track variables assigned dynamically, including simple alias chains."""
    assignments: list[tuple[set[str], ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = set().union(*(_assigned_names(t) for t in node.targets))
            assignments.append((targets, node.value))
        elif isinstance(node, ast.AnnAssign):
            assignments.append((_assigned_names(node.target), node.value or ast.Constant(None)))
    tainted: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
            tainted.update(arg.arg for arg in args)
    changed = True
    while changed:
        changed = False
        for names, value in assignments:
            if names and _expression_is_dynamic(value, tainted):
                before = len(tainted)
                tainted.update(names)
                changed |= len(tainted) != before
    return tainted


def _sql_injection_fstring(node: ast.Call, tainted_names: set[str]) -> bool:
    if not isinstance(node.func, ast.Attribute) or node.func.attr not in {"execute", "executemany", "executescript"}:
        return False
    if not node.args:
        return False
    arg = node.args[0]
    if isinstance(arg, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in arg.values)
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
        return _expression_is_dynamic(arg, tainted_names)
    if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr in {"format", "format_map"}:
        return bool(arg.args) or bool(arg.keywords)
    if isinstance(arg, ast.Name) and arg.id in tainted_names:
        return True
    return False


# A03:2021 Injection — os.system / subprocess with string concat
def _cmd_injection(node: ast.Call, tainted_names: set[str]) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in {"system", "popen", "call", "run", "Popen", "check_call", "check_output"}:
        return False
    if not node.args:
        return False
    arg = node.args[0]
    is_command_api = (
        isinstance(node.func.value, ast.Name) and node.func.value.id in {"os", "subprocess"}
    )
    if not is_command_api:
        return False
    dynamic = _expression_is_dynamic(arg, tainted_names) or (
        isinstance(arg, ast.Name) and arg.id in tainted_names
    )
    shell_true = any(
        keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
        for keyword in node.keywords
    )
    return dynamic and (shell_true or node.func.value.id == "os")


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
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return any(isinstance(t, ast.Name) and t.id == "DEBUG" for t in targets) \
        and isinstance(node.value, ast.Constant) and node.value.value is True


def _tls_verification_disabled(node: ast.Call) -> bool:
    """Flag common HTTP client calls that explicitly disable TLS verification."""
    clients = {"requests", "httpx", "urllib3"}
    if not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Name):
        return False
    if node.func.value.id not in clients or node.func.attr not in {"get", "post", "put", "delete", "request"}:
        return False
    return any(
        keyword.arg in {"verify", "cert_reqs"}
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value in {False, "CERT_NONE"}
        for keyword in node.keywords
    )


def _flask_debug_enabled(node: ast.Call) -> bool:
    """Catch Flask's common app.run(debug=True) production misconfiguration."""
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "run"
        and any(
            keyword.arg == "debug"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )
    )


def _permissive_cors(node: ast.Call) -> bool:
    """Flag wildcard CORS combined with credentialed requests."""
    function = node.func
    is_cors = (
        isinstance(function, ast.Name) and function.id.lower() in {"cors", "cross_origin"}
    ) or (
        isinstance(function, ast.Attribute) and function.attr.lower() in {"cors", "cross_origin"}
    )
    if not is_cors:
        return False
    values = {keyword.arg: keyword.value for keyword in node.keywords}
    origin = values.get("origins") or values.get("origin")
    credentials = values.get("supports_credentials") or values.get("allow_credentials")
    wildcard = isinstance(origin, ast.Constant) and origin.value == "*"
    credentialed = isinstance(credentials, ast.Constant) and credentials.value is True
    return wildcard and credentialed


def _sensitive_value_logged(node: ast.Call) -> bool:
    """Flag obvious secret-named values passed directly to common log APIs."""
    method = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
    if method not in {"debug", "info", "warning", "error", "exception", "critical", "print"}:
        return False
    for arg in node.args:
        for child in ast.walk(arg):
            if isinstance(child, ast.Name) and any(
                token in child.id.lower() for token in ("password", "passwd", "secret", "api_key", "token", "credential")
            ):
                return True
            if isinstance(child, ast.Attribute) and any(
                token in child.attr.lower() for token in ("password", "passwd", "secret", "api_key", "token", "credential")
            ):
                return True
    return False


def _untrusted_value_logged(node: ast.Call, request_names: set[str]) -> bool:
    """Flag request-derived values sent directly to logs (possible CWE-117)."""
    method = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
    if method not in {"debug", "info", "warning", "error", "exception", "critical", "print"}:
        return False
    for argument in node.args:
        if any(
            isinstance(child, ast.Name) and child.id in request_names
            or isinstance(child, ast.Attribute)
            and child.attr.lower() in {"args", "form", "json", "data", "query", "params", "body", "headers"}
            and any(isinstance(descendant, ast.Name) and descendant.id == "request" for descendant in ast.walk(child))
            for child in ast.walk(argument)
        ):
            return True
    return False


def _empty_exception_handler(node: ast.ExceptHandler) -> bool:
    """Flag exception handlers that silently discard errors (A10)."""
    return len(node.body) == 1 and isinstance(node.body[0], ast.Pass)


def _exception_swallowed_as_success(node: ast.ExceptHandler) -> bool:
    """Catch common broad-exception handlers that return success-like defaults."""
    if node.type is not None and not (
        isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
    ):
        return False
    if len(node.body) != 1 or not isinstance(node.body[0], ast.Return):
        return False
    value = node.body[0].value
    if value is None or isinstance(value, ast.Constant) and value.value in {None, False, ""}:
        return True
    if isinstance(value, ast.Dict):
        return not value.keys
    return isinstance(value, (ast.List, ast.Tuple, ast.Set)) and not value.elts


_PRIVILEGE_FIELDS = {"role", "admin", "is_admin", "is_staff", "is_superuser", "permissions", "permission", "access_level", "privilege", "privileges"}


def _request_source_names(tree: ast.AST) -> set[str]:
    """Track simple request-data aliases for privileged-field assignment checks."""
    names: set[str] = set()

    def request_derived(value: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Name) and child.id in names
            or isinstance(child, ast.Attribute)
            and child.attr.lower() in {"args", "form", "json", "values", "data", "query", "params", "body", "get_json", "query_params"}
            and any(isinstance(descendant, ast.Name) and descendant.id == "request" for descendant in ast.walk(child))
            for child in ast.walk(value)
        )

    changed = True
    assignments = [node for node in ast.walk(tree) if isinstance(node, (ast.Assign, ast.AnnAssign))]
    while changed:
        changed = False
        for node in assignments:
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if value is None or not request_derived(value):
                continue
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name) and child.id not in names:
                        names.add(child.id)
                        changed = True
    return names


def _client_controlled_privilege(node: ast.Assign | ast.AnnAssign, request_names: set[str]) -> bool:
    value = node.value
    if value is None:
        return False
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    privilege_target = any(
        isinstance(child, ast.Attribute) and child.attr.lower() in _PRIVILEGE_FIELDS
        or isinstance(child, ast.Name) and child.id.lower() in _PRIVILEGE_FIELDS
        or isinstance(child, ast.Subscript) and isinstance(child.slice, ast.Constant)
        and isinstance(child.slice.value, str) and child.slice.value.lower() in _PRIVILEGE_FIELDS
        for target in targets for child in ast.walk(target)
    )
    request_input = any(
        isinstance(child, ast.Name) and child.id in request_names
        or isinstance(child, ast.Attribute)
        and child.attr.lower() in {"args", "form", "json", "values", "data", "query", "params", "body", "get_json", "query_params"}
        and any(isinstance(descendant, ast.Name) and descendant.id == "request" for descendant in ast.walk(child))
        for child in ast.walk(value)
    )
    return privilege_target and request_input


def _mass_assignment(node: ast.Call, request_names: set[str]) -> bool:
    """Catch common direct request-object mass assignment/update calls."""
    method = node.func.attr.lower() if isinstance(node.func, ast.Attribute) else (
        node.func.id.lower() if isinstance(node.func, ast.Name) else ""
    )
    if method not in {"update", "setattr"}:
        return False
    if not node.args:
        return False
    return any(
        isinstance(child, ast.Name) and child.id in request_names
        or isinstance(child, ast.Attribute) and child.attr.lower() in {
            "json", "form", "data", "body", "values", "query_params"
        }
        for child in ast.walk(node.args[-1])
    )


def _auth_secret_comparison(node: ast.If) -> bool:
    """Flag login branches comparing a password input to a credential-like name.

    This is deliberately name-based: it detects patterns such as
    `if password == DB_ADMIN_PASSWORD`, including an imported constant, without
    claiming that every password comparison is insecure.
    """
    credential_words = ("password", "passwd", "secret", "credential", "admin_key")
    input_words = ("password", "passwd", "passphrase")
    for comparison in (item for item in ast.walk(node.test) if isinstance(item, ast.Compare)):
        operands = [comparison.left, *comparison.comparators]
        names = [
            child.id.lower()
            for operand in operands
            for child in ast.walk(operand)
            if isinstance(child, ast.Name)
        ]
        has_input = any(any(word in name for word in input_words) for name in names)
        has_secret = any(any(word in name for word in credential_words) for name in names)
        if has_input and has_secret:
            return True
    return False


def _potential_idor(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Flag a narrow request-id -> unscoped SQL SELECT pattern (potential IDOR)."""
    def request_id_read(expression: ast.AST) -> bool:
        return any(
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Attribute)
            and child.func.attr == "get"
            and child.args
            and isinstance(child.args[0], ast.Constant)
            and isinstance(child.args[0].value, str)
            and child.args[0].value.lower() in {"id", "record_id", "account_id", "document_id", "invoice_id"}
            and any(isinstance(part, ast.Name) and part.id == "request" for part in ast.walk(child))
            for child in ast.walk(expression)
        )

    request_ids: set[str] = set()
    for item in ast.walk(node):
        if not isinstance(item, (ast.Assign, ast.AnnAssign)) or item.value is None:
            continue
        targets = item.targets if isinstance(item, ast.Assign) else [item.target]
        if request_id_read(item.value):
            request_ids.update(target.id for target in targets if isinstance(target, ast.Name))
    function_names = {
        child.id.lower() for child in ast.walk(node) if isinstance(child, ast.Name)
    } | {
        child.attr.lower() for child in ast.walk(node) if isinstance(child, ast.Attribute)
    }
    if function_names.intersection({"owner_id", "tenant_id", "authorize", "can_access", "check_permission", "current_user"}):
        return False

    assigned_sql = {
        target.id: item.value.value
        for item in ast.walk(node)
        if isinstance(item, ast.Assign) and isinstance(item.value, ast.Constant) and isinstance(item.value.value, str)
        for target in item.targets if isinstance(target, ast.Name)
    }
    for call in (item for item in ast.walk(node) if isinstance(item, ast.Call)):
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in {"execute", "query", "fetchone", "fetchall"}:
            continue
        if not call.args:
            continue
        statement = call.args[0].value if isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str) else (
            assigned_sql.get(call.args[0].id, "") if isinstance(call.args[0], ast.Name) else ""
        )
        if not re.search(r"\bselect\b", statement, re.IGNORECASE):
            continue
        if not re.search(r"\bwhere\s+[\w.]*id\s*=", statement, re.IGNORECASE):
            continue
        if re.search(r"\b(?:owner_id|user_id|tenant_id|account_owner)\s*=", statement, re.IGNORECASE):
            continue
        if any(
            isinstance(child, ast.Name) and child.id in request_ids
            for argument in call.args[1:] for child in ast.walk(argument)
        ) or any(request_id_read(argument) for argument in call.args[1:]):
            return True
    return False


def _weak_random_for_secret(node: ast.Assign | ast.AnnAssign) -> bool:
    value = node.value
    if not isinstance(value, ast.Call):
        return False
    function = value.func
    weak_random = (
        isinstance(function, ast.Attribute)
        and isinstance(function.value, ast.Name)
        and function.value.id == "random"
        and function.attr in {"random", "randint", "randrange", "choice", "getrandbits"}
    )
    if not weak_random:
        return False
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    security_name = any(
        isinstance(child, ast.Name)
        and any(word in child.id.lower() for word in ("token", "secret", "password", "session", "nonce", "key"))
        for target in targets for child in ast.walk(target)
    )
    return security_name


def _dynamic_template_string(node: ast.Call, tainted_names: set[str]) -> bool:
    """Detect user-controlled values interpolated into server-side templates."""
    if not isinstance(node.func, ast.Name) or node.func.id != "render_template_string" or not node.args:
        return False
    template = node.args[0]
    return (
        isinstance(template, ast.JoinedStr)
        or isinstance(template, ast.BinOp) and _expression_is_dynamic(template, tainted_names)
        or isinstance(template, ast.Name) and template.id in tainted_names
        or isinstance(template, ast.Call) and isinstance(template.func, ast.Attribute)
        and template.func.attr in {"format", "format_map"}
    )


def _unsafe_deserializer_imports(tree: ast.AST) -> dict[str, str]:
    """Find module and function aliases for common unsafe deserializers."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = alias.name.split(".", 1)[0]
                if module in {"pickle", "marshal", "yaml"}:
                    aliases[alias.asname or module] = module
        if isinstance(node, ast.ImportFrom) and node.module in {"pickle", "marshal", "yaml"}:
            for alias in node.names:
                if alias.name in {"load", "loads"}:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


# A03:2021 — eval() usage. Match the Call node so eval() is detected in any
# expression context, including `return eval(...)` and assignments.
def _eval_usage(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Name)
        and node.func.id == "eval"
    )


# A04:2021 — hardcoded secret
_SECRET_KEYWORDS = {"PASSWORD", "SECRET", "API_KEY", "TOKEN", "CREDENTIAL"}


def _hardcoded_secret(node: ast.Assign | ast.AnnAssign) -> bool:
    # Secret-like variable names are not sufficient evidence by themselves:
    # assignments from os.environ/secrets managers are expected secure patterns.
    if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
        return False
    if not node.value.value.strip():
        return False
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for target in targets:
        if isinstance(target, ast.Name):
            if any(kw in target.id.upper() for kw in _SECRET_KEYWORDS):
                return True
    return False


# A03:2021 — exec() / compile() arbitrary code execution
def _exec_usage(node: ast.Call) -> bool:
    return (
        isinstance(node.func, ast.Name)
        and node.func.id in {"exec", "compile"}
    )


def _password_hash_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Catch fast general-purpose hashes applied to password input in a password flow."""
    password_names = {
        arg.arg for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        if any(token in arg.arg.lower() for token in ("password", "passwd", "passphrase"))
    }
    if not password_names and not any(token in node.name.lower() for token in ("password", "passwd", "passphrase")):
        return False
    if not password_names:
        password_names = {
            arg.arg for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        }
    fast_hashes = {"sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"}
    for call in (item for item in ast.walk(node) if isinstance(item, ast.Call)):
        function = call.func
        algorithm = None
        if isinstance(function, ast.Attribute) and function.attr in fast_hashes:
            algorithm = function.attr
            if isinstance(function.value, ast.Name) and function.value.id != "hashlib":
                continue
        elif isinstance(function, ast.Name) and function.id in fast_hashes:
            algorithm = function.id
        if algorithm and any(
            isinstance(child, ast.Name) and child.id in password_names
            for arg in call.args for child in ast.walk(arg)
        ):
            return True
    return False


# A08:2021 — pickle.loads / yaml.load unsafe deserialization
def _unsafe_deserialize(node: ast.Call, imported_aliases: dict[str, str] | None = None) -> bool:
    imported_aliases = imported_aliases or {}
    if isinstance(node.func, ast.Attribute) and node.func.attr in {"loads", "load"}:
        module = node.func.value
        if isinstance(module, ast.Name) and imported_aliases.get(module.id, module.id) in {"pickle", "marshal", "yaml"}:
            return True
        # yaml.load can be imported as a direct function.
        if isinstance(module, ast.Name) and module.id in {"load", "loads"}:
            return True
    if isinstance(node.func, ast.Name):
        return imported_aliases.get(node.func.id, "") in {
            "pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "yaml.load", "yaml.loads"
        }
    return False


# A01:2021 — open() with user-controlled path
def _open_user_path(node: ast.Call, tainted_names: set[str] | None = None) -> bool:
    """Detect unvalidated dynamic paths at common Python file read sinks.

    Flask's send_file is a security-sensitive sink too; the existing rule only
    covered open(), which missed the common request.args -> join -> send_file flow.
    """
    is_open = isinstance(node.func, ast.Name) and node.func.id == "open"
    is_send_file = isinstance(node.func, ast.Name) and node.func.id == "send_file"
    is_path_reader = (
        isinstance(node.func, ast.Attribute)
        and node.func.attr in {"open", "read_text", "read_bytes"}
    )
    if not (is_open or is_send_file or is_path_reader):
        return False
    # Path.open/read_* use the receiver as the path; open/send_file use arg 0.
    if is_path_reader and isinstance(node.func, ast.Attribute):
        first = node.func.value
    elif node.args:
        first = node.args[0]
    else:
        return False
    return _expression_is_dynamic(first, tainted_names or set())


# A10:2021 — requests.get/post with user-controlled URL
# O-03 extension: bare Name is user-controlled unless plainly CONSTANT
# (constant URLs like "https://api.example.com" must NOT fire).
def _mark_url_constants(tree: ast.AST) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Name) and isinstance(node.value, ast.Constant):
                out.add(t.id)
    return out


def _ssrf_requests(node: ast.Call, url_constants: set[str]) -> bool:
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr not in {"get", "post", "put", "delete", "head"}:
        return False
    if not isinstance(node.func.value, ast.Name) or node.func.value.id not in {
        "requests", "httpx", "aiohttp", "urllib", "urlopen", "session", "client"
    }:
        return False
    if not node.args:
        return False
    first = node.args[0]
    if isinstance(first, (ast.JoinedStr, ast.BinOp)):
        return True
    if isinstance(first, ast.Call) and isinstance(first.func, ast.Attribute):
        return first.func.attr == "format"
    if isinstance(first, ast.Name) and first.id not in url_constants:
        return True
    return False


# ---- rule declarations ----

_rule(
    id="PY-SQLI-001",
    title="Potential SQL Injection",
    severity="critical",
    confidence="high",
    cwe_id="CWE-89",
    owasp_ref="A05:2025-Injection",
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
    owasp_ref="A05:2025-Injection",
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
    owasp_ref="A04:2025-Cryptographic-Failures",
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
    owasp_ref="A04:2025-Cryptographic-Failures",
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
    owasp_ref="A02:2025-Security-Misconfiguration",
    message="Debug mode should be disabled in production.",
    suggestion="Set debug=False and use environment-based config.",
    checker="assign",
    matches=_debug_true,
)

_rule(
    id="PY-TLS-001",
    title="TLS Certificate Verification Disabled",
    severity="high",
    confidence="high",
    cwe_id="CWE-295",
    owasp_ref="A02:2025-Security-Misconfiguration",
    message="The HTTP request disables TLS certificate verification, allowing interception of the connection.",
    suggestion="Keep certificate verification enabled. Configure a trusted CA bundle if the service uses a private CA.",
    checker="call",
    matches=_tls_verification_disabled,
)

_rule(
    id="PY-LOG-001",
    title="Potential Sensitive Data in Logs",
    severity="medium",
    confidence="medium",
    cwe_id="CWE-532",
    owasp_ref="A09:2025-Security-Logging-and-Alerting-Failures",
    message="A value with a secret-like name is passed to a logging or print call.",
    suggestion="Redact credentials and tokens before logging; log a safe identifier or event instead.",
    checker="call",
    matches=_sensitive_value_logged,
)

_rule(
    id="PY-EXCEPT-001",
    title="Exception Silently Ignored",
    severity="medium",
    confidence="high",
    cwe_id="CWE-390",
    owasp_ref="A10:2025-Mishandling-of-Exceptional-Conditions",
    message="This exception handler silently discards the error, which can leave the application in an unsafe or inconsistent state.",
    suggestion="Handle expected exceptions explicitly and fail safely; record a sanitized diagnostic when appropriate.",
    checker="except",
    matches=_empty_exception_handler,
)

_rule(
    id="PY-DESIGN-001",
    title="Client-Controlled Authorization Field",
    severity="high",
    confidence="medium",
    cwe_id="CWE-602",
    owasp_ref="A06:2025-Insecure-Design",
    message="Request data is assigned to a privileged role or permission field. A client must not decide its own authorization level.",
    suggestion="Derive privileges from the authenticated server-side identity and enforce authorization and ownership checks on the server.",
    checker="design",
    matches=None,
)

_rule(
    id="PY-CODE-EXEC-001",
    title="Dangerous eval() Usage",
    severity="critical",
    confidence="high",
    cwe_id="CWE-95",
    owasp_ref="A05:2025-Injection",
    message="eval() executes arbitrary code and is a major security risk.",
    suggestion="Use ast.literal_eval() or parse with json.loads() for data.",
    checker="call",
    matches=_eval_usage,
)

_rule(
    id="PY-CODE-EXEC-002",
    title="Dangerous exec()/compile() Usage",
    severity="critical",
    confidence="high",
    cwe_id="CWE-94",
    owasp_ref="A05:2025-Injection",
    message="exec()/compile() can execute arbitrary code. Avoid with untrusted input.",
    suggestion="Use safer parsing or explicit handlers instead of dynamic execution.",
    checker="call",
    matches=_exec_usage,
)

_rule(
    id="PY-PASSWORD-HASH-001",
    title="Fast Hash Used for Password Storage",
    severity="high",
    confidence="medium",
    cwe_id="CWE-916",
    owasp_ref="A04:2025-Cryptographic-Failures",
    message="Fast general-purpose hashes such as SHA-256 are unsuitable for password storage. Use a password-hashing scheme with a salt and work factor, and plan migration for existing hashes.",
    suggestion="Use the project's established Argon2id, scrypt, bcrypt, or PBKDF2 password-hashing library; do not replace stored password hashes without a migration plan.",
    checker="function",
    matches=_password_hash_function,
)

_rule(
    id="PY-SECRETS-001",
    title="Potential Hardcoded Secret",
    severity="high",
    confidence="medium",
    cwe_id="CWE-798",
    owasp_ref="A07:2025-Authentication-Failures",
    message="CodeShield detected a possible hard-coded secret. Move the value to an environment variable or secret manager.",
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
    owasp_ref="A08:2025-Software-or-Data-Integrity-Failures",
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
    owasp_ref="A01:2025-Broken-Access-Control",
    message="User-controlled path reaches a file-reading sink. Resolve it and reject paths outside the allowed directory.",
    suggestion="Resolve the trusted base and requested path with os.path.realpath(), then verify os.path.commonpath((base, path)) equals the base before reading or sending the file.",
    checker="call",
    matches=_open_user_path,
)

_rule(
    id="PY-SSRF-001",
    title="Potential SSRF via requests",
    severity="high",
    confidence="medium",
    cwe_id="CWE-918",
    owasp_ref="A01:2025-Broken-Access-Control",
    message="HTTP request made with user-controlled URL. Validate URL scheme and host.",
    suggestion="Allowlist domains and reject private/internal IP ranges before requests.",
    checker="call",
    matches=_ssrf_requests,
)

# Additional targeted patterns across the 2025 categories. These checks favor
# high-signal source patterns and intentionally do not claim category coverage.
_rule(
    id="PY-AUTH-001",
    title="Password Compared with a Credential Constant",
    severity="critical",
    confidence="medium",
    cwe_id="CWE-287",
    owasp_ref="A07:2025-Authentication-Failures",
    message="An authentication branch compares a password input with a credential-like constant. This can create a shared-password backdoor, including when the constant is imported from another module.",
    suggestion="Remove shared or hard-coded password bypasses. Verify the submitted password against the individual account's salted password hash and enforce the normal authentication flow.",
    checker="if",
    matches=_auth_secret_comparison,
)

_rule(
    id="PY-ACCESS-001",
    title="Potential Unscoped Object Lookup",
    severity="high",
    confidence="low",
    cwe_id="CWE-639",
    owasp_ref="A01:2025-Broken-Access-Control",
    message="A request-sourced object identifier appears to reach a SQL lookup without a visible owner or tenant constraint. Verify authorization before returning the record.",
    suggestion="Scope the lookup to the authenticated user's ownership or tenant and enforce authorization on the server for every request.",
    checker="function",
    matches=_potential_idor,
)

_rule(
    id="PY-CONFIG-002",
    title="Credentialed Wildcard CORS",
    severity="high",
    confidence="high",
    cwe_id="CWE-942",
    owasp_ref="A02:2025-Security-Misconfiguration",
    message="CORS is configured to allow every origin while also allowing credentials.",
    suggestion="Use an explicit allowlist of trusted origins and enable credentials only for origins that require them.",
    checker="call",
    matches=_permissive_cors,
)

_rule(
    id="PY-CONFIG-003",
    title="Flask Debug Server Enabled",
    severity="high",
    confidence="high",
    cwe_id="CWE-489",
    owasp_ref="A02:2025-Security-Misconfiguration",
    message="Flask is started with debug=True, which can expose interactive debugging and detailed diagnostics.",
    suggestion="Disable debug mode outside local development and configure production settings separately.",
    checker="call",
    matches=_flask_debug_enabled,
)

_rule(
    id="PY-CRYPTO-003",
    title="Weak Randomness Used for a Security Value",
    severity="high",
    confidence="high",
    cwe_id="CWE-338",
    owasp_ref="A04:2025-Cryptographic-Failures",
    message="The random module is used to create a token, key, password, session identifier, or nonce; its output is predictable.",
    suggestion="Use secrets.token_urlsafe(), secrets.token_bytes(), or another cryptographically secure generator appropriate to the value.",
    checker="assign-extra",
    matches=_weak_random_for_secret,
)

_rule(
    id="PY-DESIGN-002",
    title="Request Data Passed to Model Update",
    severity="high",
    confidence="medium",
    cwe_id="CWE-915",
    owasp_ref="A06:2025-Insecure-Design",
    message="Request data appears to be passed directly into an object update operation, which can allow mass assignment of privileged fields.",
    suggestion="Allowlist editable fields and set authorization-sensitive properties from trusted server-side policy.",
    checker="call",
    matches=_mass_assignment,
)

_rule(
    id="PY-INJECT-001",
    title="Dynamic Server-Side Template",
    severity="high",
    confidence="medium",
    cwe_id="CWE-1336",
    owasp_ref="A05:2025-Injection",
    message="User-controlled or dynamically formatted content is passed as a server-side template source.",
    suggestion="Keep templates in trusted files and pass user values as template data; do not build template source from request input.",
    checker="call",
    matches=_dynamic_template_string,
)

_rule(
    id="PY-LOG-002",
    title="Request Data Written Directly to Logs",
    severity="medium",
    confidence="low",
    cwe_id="CWE-117",
    owasp_ref="A09:2025-Security-Logging-and-Alerting-Failures",
    message="Request-derived text is passed directly to a logging call and may forge or corrupt log entries if it contains control characters.",
    suggestion="Use structured logging, escape or normalize control characters, and avoid recording unnecessary user-supplied content.",
    checker="call",
    matches=_untrusted_value_logged,
)

_rule(
    id="PY-EXCEPT-002",
    title="Broad Exception Converted to Success-Like Result",
    severity="medium",
    confidence="low",
    cwe_id="CWE-755",
    owasp_ref="A10:2025-Mishandling-of-Exceptional-Conditions",
    message="A broad exception handler returns a success-like empty value, which can hide a failed security-sensitive operation.",
    suggestion="Catch expected exceptions specifically and return an explicit failure result or propagate the error safely.",
    checker="except",
    matches=_exception_swallowed_as_success,
)
