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


def validate_finding(rule_id: str, node: ast.AST, tree: ast.AST) -> tuple[bool, str]:
    """Return (keep, reason). keep=False means suppress as false positive."""
    try:
        assignments = _collect_assignments(tree)
    except Exception:
        return True, "validator-error-keep"

    # --- SQLi / CMD / PATH / SSRF: need dynamic input, not constants ---
    if rule_id in {"PY-SQLI-001", "PY-CMD-001", "PY-PATH-001", "PY-SSRF-001"}:
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

