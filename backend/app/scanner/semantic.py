"""O-03 semantic validation via variable-origin tracing (Python AST).

Goal: prune false positives from raw rule matching without losing
true positives. Each validator returns True = keep finding,
False = suppress as likely false positive.
"""
from __future__ import annotations
import ast


_USER_INPUT_FUNCS = {"input"}
_USER_INPUT_ATTRS = {"args", "form", "values", "cookies", "headers", "data", "GET", "POST"}
_SANITIZE_FUNCS = {"escape", "sanitize", "quote", "escape_string"}


def _is_environ_access(expr: ast.AST) -> bool:
    """Check if expr is os.environ[...] or os.environ.get(...)."""
    if isinstance(expr, ast.Call):
        f = expr.func
        if isinstance(f, ast.Attribute) and f.attr in {"getenv", "get"}:
            if isinstance(f.value, ast.Attribute) and f.value.attr == "environ":
                if isinstance(f.value.value, ast.Name) and f.value.value.id == "os":
                    return True
    if isinstance(expr, ast.Subscript):
        if isinstance(expr.value, ast.Attribute) and expr.value.attr == "environ":
            if isinstance(expr.value.value, ast.Name) and expr.value.value.id == "os":
                return True
    return False


def _origin_of(expr: ast.AST, assignments: dict[str, str]) -> str:
    """Classify expression origin: CONSTANT, USER_INPUT, SANITIZED, DYNAMIC, UNKNOWN."""
    if isinstance(expr, ast.Constant):
        return "CONSTANT"
    if isinstance(expr, ast.Name):
        return assignments.get(expr.id, "UNKNOWN")
    if isinstance(expr, ast.Call):
        f = expr.func
        if isinstance(f, ast.Name) and f.id in _USER_INPUT_FUNCS:
            return "USER_INPUT"
        if isinstance(f, ast.Name) and f.id in _SANITIZE_FUNCS:
            return "SANITIZED"
        if isinstance(f, ast.Attribute) and f.attr in _SANITIZE_FUNCS:
            return "SANITIZED"
        # os.environ.get / os.getenv -> not hardcoded, safe source
        if isinstance(f, ast.Attribute) and f.attr in {"getenv", "get"}:
            return "ENV"
        return "DYNAMIC"
    if isinstance(expr, ast.Subscript):
        # os.environ["KEY"] -> not hardcoded, safe source
        if _is_environ_access(expr):
            return "ENV"
        return "DYNAMIC"
    if isinstance(expr, (ast.JoinedStr, ast.BinOp)):
        return "DYNAMIC"
    return "UNKNOWN"


def _collect_assignments(tree: ast.AST) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Name):
                out[t.id] = _origin_of(node.value, out)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for arg in list(node.args.args) + list(node.args.kwonlyargs):
                # function params are user-controlled by default
                out.setdefault(arg.arg, "USER_INPUT")
    return out


def _is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    return v in {"", "xxx", "todo", "changeme", "example", "test", "***", "none", "null"}


def _enclosing_function(node: ast.AST, tree: ast.AST) -> ast.AST | None:
    candidates = [
        item for item in ast.walk(tree)
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.lineno <= getattr(node, "lineno", 0)
        and getattr(item, "end_lineno", item.lineno) >= getattr(node, "end_lineno", getattr(node, "lineno", 0))
    ]
    return min(candidates, key=lambda item: getattr(item, "end_lineno", item.lineno) - item.lineno) if candidates else None


def _raises_in_body(node: ast.If) -> bool:
    return any(isinstance(item, ast.Raise) for statement in node.body for item in ast.walk(statement))


def _has_path_containment_guard(node: ast.Call, tree: ast.AST) -> bool:
    function = _enclosing_function(node, tree)
    if function is None or not node.args or not isinstance(node.args[0], ast.Name):
        return False
    path_name = node.args[0].id
    for item in ast.walk(function):
        if not isinstance(item, ast.If) or not _raises_in_body(item):
            continue
        test_calls_commonpath = any(
            isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr == "commonpath"
            and any(isinstance(part, ast.Name) and part.id == path_name for arg in child.args for part in ast.walk(arg))
            for child in ast.walk(item.test)
        )
        if test_calls_commonpath:
            return True
    return False


def _has_ssrf_allowlist_guard(node: ast.Call, tree: ast.AST) -> bool:
    function = _enclosing_function(node, tree)
    if function is None or not node.args or not isinstance(node.args[0], ast.Name):
        return False
    request_url = node.args[0].id
    parsed_names = {
        target.id
        for assignment in ast.walk(function)
        if isinstance(assignment, ast.Assign) and isinstance(assignment.value, ast.Call)
        and isinstance(assignment.value.func, ast.Name) and assignment.value.func.id == "urlparse"
        and assignment.value.args and isinstance(assignment.value.args[0], ast.Name)
        and assignment.value.args[0].id == request_url
        for target in assignment.targets if isinstance(target, ast.Name)
    }
    if not parsed_names:
        return False
    for item in ast.walk(function):
        if not isinstance(item, ast.If) or not _raises_in_body(item):
            continue
        checked_url_attributes = {
            child.attr for child in ast.walk(item.test)
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name)
            and child.value.id in parsed_names
        }
        names = {child.id for child in ast.walk(item.test) if isinstance(child, ast.Name)}
        if {"scheme", "hostname"}.issubset(checked_url_attributes) and "allowed_hosts" in names:
            return True
    return False


def validate_finding(rule_id: str, node: ast.AST, tree: ast.AST) -> tuple[bool, str]:
    """Return (keep, reason). keep=False means suppress as false positive."""
    try:
        assignments = _collect_assignments(tree)
    except Exception:
        return True, "validator-error-keep"

    # --- SQLi / CMD / PATH / SSRF: need dynamic input, not constants ---
    if rule_id in {"PY-SQLI-001", "PY-CMD-001", "PY-PATH-001", "PY-SSRF-001"}:
        if rule_id == "PY-PATH-001" and isinstance(node, ast.Call) and _has_path_containment_guard(node, tree):
            return False, "resolved-path-contained"
        if rule_id == "PY-SSRF-001" and isinstance(node, ast.Call) and _has_ssrf_allowlist_guard(node, tree):
            return False, "https-host-allowlist-guard"
        if isinstance(node, ast.Call) and node.args:
            origin = _origin_of(node.args[0], assignments)
            if origin == "CONSTANT":
                return False, "constant-query-no-taint"
            if origin == "SANITIZED":
                return False, "sanitized-input"
            return True, f"origin-{origin.lower()}"
        return True, "no-args-keep"

    # --- Hardcoded secrets: suppress placeholders and env lookups ---
    if rule_id == "PY-SECRETS-001":
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if _is_placeholder(str(node.value.value)):
                return False, "placeholder-value"
        if isinstance(node, ast.Assign):
            origin = _origin_of(node.value, assignments)
            if origin in {"ENV", "USER_INPUT", "DYNAMIC"}:
                return False, f"not-hardcoded-{origin.lower()}"
        return True, "literal-secret"

    # --- Deserialization: safe_load / loads of constants are safer ---
    if rule_id == "PY-SERIAL-001":
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr in {"safe_load", "safe_loads"}:
                return False, "safe-loader"
            if node.args:
                origin = _origin_of(node.args[0], assignments)
                if origin == "CONSTANT":
                    return False, "constant-payload"
        return True, "unsafe-loader"

    return True, "no-validator-keep"

