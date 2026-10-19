"""
Tests for the Secure Coding Assistant scanner.
"""

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.scanner.python_scanner import scan
from app.scanner import js_scanner


# ---- Python tests ----
VULNERABLE_SQLI = """
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
"""

VULNERABLE_EVAL = """
eval("__import__('os').system('echo pwned')")
"""

VULNERABLE_EXEC = """
exec("malicious_code")
"""

VULNERABLE_CMD = """
import subprocess
subprocess.call(f"rm -rf {path}")
"""

VULNERABLE_SECRET = """
PASSWORD = "super_secret"
"""

VULNERABLE_PICKLE = """
import pickle
data = pickle.loads(user_input)
"""

VULNERABLE_OPEN = """
path = input("path: ")
open(f"/data/{path}")
"""

CLEAN_CODE = """
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
"""


def test_sqli_detection():
    findings = scan(VULNERABLE_SQLI, "test.py")
    assert any(f["rule_id"] == "PY-SQLI-001" for f in findings), findings


def test_eval_detection():
    findings = scan(VULNERABLE_EVAL, "test.py")
    assert any(f["rule_id"] == "PY-CODE-EXEC-001" for f in findings), findings


def test_exec_detection():
    findings = scan(VULNERABLE_EXEC, "test.py")
    assert any(f["rule_id"] == "PY-CODE-EXEC-002" for f in findings), findings


def test_cmd_injection_detection():
    findings = scan(VULNERABLE_CMD, "test.py")
    assert any(f["rule_id"] == "PY-CMD-001" for f in findings), findings


def test_hardcoded_secret_detection():
    findings = scan(VULNERABLE_SECRET, "test.py")
    assert any(f["rule_id"] == "PY-SECRETS-001" for f in findings), findings


def test_unsafe_deserialization_detection():
    findings = scan(VULNERABLE_PICKLE, "test.py")
    assert any(f["rule_id"] == "PY-SERIAL-001" for f in findings), findings


def test_path_traversal_detection():
    findings = scan(VULNERABLE_OPEN, "test.py")
    assert any(f["rule_id"] == "PY-PATH-001" for f in findings), findings


def test_clean_code_no_findings():
    findings = scan(CLEAN_CODE, "test.py")
    assert findings == []


# ---- JavaScript tests ----
JS_EVAL = """
function calc(expr) {
  return eval(expr);
}
"""

JS_INNERHTML = """
function render(msg) {
  document.getElementById('out').innerHTML = msg;
}
"""

JS_MATH_RANDOM = """
function token() {
  return Math.random().toString(36);
}
"""

JS_SECRET = """
const API_KEY = "abc123";
"""

JS_DEBUGGER = """
debugger;
function foo() {}
"""

JS_JWT = """
function decode(token) {
  return jwt.decode(token);
}
"""

JS_SAFE = """
function greet(name) {
  console.log("Hello, " + name);
}
"""


def test_js_eval_detection():
    findings = js_scanner.scan(JS_EVAL, "test.js")
    assert any(f["rule_id"] == "JS-CODE-EXEC-001" for f in findings), findings


def test_js_xss_detection():
    findings = js_scanner.scan(JS_INNERHTML, "test.js")
    assert any(f["rule_id"] == "JS-XSS-001" for f in findings), findings


def test_js_weak_random_detection():
    findings = js_scanner.scan(JS_MATH_RANDOM, "test.js")
    assert any(f["rule_id"] == "JS-RANDOM-001" for f in findings), findings


def test_js_secret_detection():
    findings = js_scanner.scan(JS_SECRET, "test.js")
    assert any(f["rule_id"] == "JS-SECRETS-001" for f in findings), findings


def test_js_debugger_detection():
    findings = js_scanner.scan(JS_DEBUGGER, "test.js")
    assert any(f["rule_id"] == "JS-CONFIG-001" for f in findings), findings


def test_js_jwt_detection():
    findings = js_scanner.scan(JS_JWT, "test.js")
    assert any(f["rule_id"] == "JS-JWT-001" for f in findings), findings


def test_js_safe_code_no_findings():
    findings = js_scanner.scan(JS_SAFE, "test.js")
    assert findings == []


# ---- O-01: @babel/parser AST precision (no paren/regex false alarms) ----
JS_AST_PARENS = """
function ok(cond) {
  if (cond) { return cond; } // must not fire JS-SQLI-001
  return "no (execute|query) call here";
}
"""

JS_AST_SQLI_TPL = """
function getUser(userId) {
  return db.query(`SELECT * FROM users WHERE id = ${userId}`);
}
"""

JS_AST_NEWFUNC = """
const add = new Function("a", "b", "return a + b");
"""

JS_AST_HASH = """
const crypto = require("crypto");
const h = crypto.createHash("md5").update(x).digest("hex");
"""

JS_AST_DOCWRITE = """
function out(s) { document.write(s); }
"""


def test_js_ast_no_false_positive_on_parens():
    findings = js_scanner.scan(JS_AST_PARENS, "t.js")
    assert findings == [], findings


def test_js_ast_sqli_template_literal():
    findings = js_scanner.scan(JS_AST_SQLI_TPL, "t.js")
    assert any(f["rule_id"] == "JS-SQLI-001" for f in findings), findings


def test_js_ast_new_function():
    findings = js_scanner.scan(JS_AST_NEWFUNC, "t.js")
    assert any(f["rule_id"] == "JS-CODE-EXEC-002" for f in findings), findings


def test_js_ast_createhash_md5():
    findings = js_scanner.scan(JS_AST_HASH, "t.js")
    assert any(f["rule_id"] == "JS-CRYPTO-001" for f in findings), findings


def test_js_ast_document_write():
    findings = js_scanner.scan(JS_AST_DOCWRITE, "t.js")
    assert any(f["rule_id"] == "JS-XSS-001" for f in findings), findings


# ---- O-03: semantic validation FP suppression + TP retention ----
FP_CONST_SQL = 'cursor.execute("SELECT * FROM t")'
FP_PLACEHOLDER = 'PASSWORD = "xxx"'
FP_ENV_SECRET = 'import os\nPASSWORD = os.environ.get("X")'
TP_SQLI = 'cursor.execute(f"SELECT * FROM t WHERE id={x}")'


def test_o03_const_query_suppressed():
    assert scan(FP_CONST_SQL, "t.py") == []


def test_o03_placeholder_secret_suppressed():
    assert scan(FP_PLACEHOLDER, "t.py") == []


def test_o03_env_secret_suppressed():
    assert scan(FP_ENV_SECRET, "t.py") == []


def test_o03_true_positive_retained():
    findings = scan(TP_SQLI, "t.py")
    assert any(f["rule_id"] == "PY-SQLI-001" for f in findings), findings


# ---- O-02: context bounding + template fallback ----
def test_o02_context_window():
    from app.ai.context import extract_context
    src = "\n".join("print(%d)" % i for i in range(1, 101))
    ctx = extract_context(src, 50)
    assert ctx["start_line"] == 35 and ctx["end_line"] == 65, ctx
    assert ctx["total_lines"] == 100


def test_o02_template_fallback():
    from app.ai.templates import template_fix
    tpl = template_fix("python", "PY-SQLI-001")
    assert tpl and "?" in tpl["secure_code"], tpl
    tpl2 = template_fix("javascript", "JS-XSS-001")
    assert tpl2 and "textContent" in tpl2["secure_code"], tpl2
    assert template_fix("python", "NOPE-000") is None


if __name__ == "__main__":
    tests = [
        test_sqli_detection,
        test_eval_detection,
        test_exec_detection,
        test_cmd_injection_detection,
        test_hardcoded_secret_detection,
        test_unsafe_deserialization_detection,
        test_path_traversal_detection,
        test_clean_code_no_findings,
        test_js_eval_detection,
        test_js_xss_detection,
        test_js_weak_random_detection,
        test_js_secret_detection,
        test_js_debugger_detection,
        test_js_jwt_detection,
        test_js_safe_code_no_findings,
        test_js_ast_no_false_positive_on_parens,
        test_js_ast_sqli_template_literal,
        test_js_ast_new_function,
        test_js_ast_createhash_md5,
        test_js_ast_document_write,
        test_o03_const_query_suppressed,
        test_o03_placeholder_secret_suppressed,
        test_o03_env_secret_suppressed,
        test_o03_true_positive_retained,
        test_o02_context_window,
        test_o02_template_fallback,
    ]

    for test in tests:
        test()
        print(f"PASS: {test.__name__}")

    print(f"\nAll {len(tests)} tests passed!")
