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
    ]

    for test in tests:
        test()
        print(f"PASS: {test.__name__}")

    print(f"\nAll {len(tests)} tests passed!")
