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
subprocess.call(f"rm -rf {path}", shell=True)
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
    source = 'def g(uid):\n query=f"SELECT * FROM users WHERE id={uid}"\n cursor.execute(query)\n'
    tpl = template_fix(
        "python", "PY-SQLI-001", code_snippet="cursor.execute(query)", full_source=source, line=3,
    )
    assert tpl and "?" in tpl["secure_code"], tpl
    # JS fixes are range/context specific in the extension; backend must not
    # fabricate a context-free replacement.
    assert template_fix("javascript", "JS-XSS-001") is None
    assert template_fix("python", "NOPE-000") is None


def test_python_ssrf_avatar_parameter():
    source = 'import requests\ndef fetch_avatar(avatar_url):\n return requests.get(avatar_url, timeout=5).content\n'
    findings = scan(source, "avatar.py")
    assert any(f["rule_id"] == "PY-SSRF-001" for f in findings), findings


def test_python_path_traversal_joined_filename():
    source = 'import os\nBASE_DIR="/var/www/uploads"\ndef download_user_file(filename):\n filepath=os.path.join(BASE_DIR, filename)\n with open(filepath, "r") as f: return f.read()\n'
    findings = scan(source, "download.py")
    assert any(f["rule_id"] == "PY-PATH-001" for f in findings), findings


def test_flask_send_file_path_traversal():
    source = '''import os
from flask import request, send_file
BASE_DIR = "/var/www/uploads"
def download_file():
    filename = request.args.get("file")
    file_path = os.path.join(BASE_DIR, filename)
    return send_file(file_path)
'''
    findings = scan(source, "download.py")
    assert any(f["rule_id"] == "PY-PATH-001" for f in findings), findings


def test_python_tls_verification_disabled():
    findings = scan('import requests\nrequests.get(url, verify=False)\n', "tls.py")
    assert any(f["rule_id"] == "PY-TLS-001" for f in findings), findings


def test_python_sensitive_log_detected():
    findings = scan('def login(password):\n    logger.info("password=%s", password)\n', "logging.py")
    assert any(f["rule_id"] == "PY-LOG-001" for f in findings), findings


def test_python_empty_except_detected():
    findings = scan('try:\n    do_work()\nexcept Exception:\n    pass\n', "errors.py")
    assert any(f["rule_id"] == "PY-EXCEPT-001" for f in findings), findings


def test_python_path_allowlist_suppresses_path_finding():
    source = ('import os\ndef read_file(name):\n base=os.path.realpath(BASE_DIR)\n'
              ' path=os.path.realpath(os.path.join(base, name))\n'
              ' if os.path.commonpath([base, path]) != base: raise ValueError("outside base")\n'
              ' return open(path).read()\n')
    findings = scan(source, "safe_path.py")
    assert not any(f["rule_id"] == "PY-PATH-001" for f in findings), findings


def test_python_ssrf_allowlist_suppresses_ssrf_finding():
    source = ('from urllib.parse import urlparse\ndef fetch(url, allowed_hosts):\n'
              ' parsed=urlparse(url)\n'
              ' if parsed.scheme != "https" or parsed.hostname not in allowed_hosts: raise ValueError("blocked")\n'
              ' return requests.get(url, allow_redirects=False)\n')
    findings = scan(source, "safe_fetch.py")
    assert not any(f["rule_id"] == "PY-SSRF-001" for f in findings), findings


def test_python_password_uses_slow_hash_finding():
    source = 'import hashlib\ndef store_password(raw_password):\n return hashlib.sha256(raw_password.encode()).hexdigest()\n'
    findings = scan(source, "passwords.py")
    assert any(f["rule_id"] == "PY-PASSWORD-HASH-001" for f in findings), findings


def test_js_sql_injection_through_query_alias():
    source = 'const userId=process.argv[2];\nconst query=`SELECT * FROM users WHERE id = ${userId}`;\ndb.query(query);\n'
    findings = js_scanner.scan(source, "query.js")
    assert any(f["rule_id"] == "JS-SQLI-001" for f in findings), findings


def test_js_safe_text_content_is_not_xss():
    source = 'const output=document.getElementById("output");\noutput.textContent=message;\n'
    findings = js_scanner.scan(source, "safe_dom.js")
    assert not any(f["rule_id"] == "JS-XSS-001" for f in findings), findings


def test_js_tls_verification_disabled():
    findings = js_scanner.scan('const agent = { rejectUnauthorized: false };', "tls.js")
    assert any(f["rule_id"] == "JS-TLS-001" for f in findings), findings


def test_js_sensitive_log_detected():
    findings = js_scanner.scan('console.info("token", accessToken);', "logging.js")
    assert any(f["rule_id"] == "JS-LOG-001" for f in findings), findings


def test_js_empty_catch_detected():
    findings = js_scanner.scan('try { run(); } catch (error) {}', "errors.js")
    assert any(f["rule_id"] == "JS-EXCEPT-001" for f in findings), findings


def test_sensitive_context_redaction():
    from app.ai.context import redact_sensitive_text
    source = 'API_KEY = "sk-live-example-secret"\nPASSWORD = os.environ.get("DB_PASSWORD")\n'
    result = redact_sensitive_text(source)
    assert "sk-live-example-secret" not in result, result
    assert 'API_KEY = "[REDACTED]"' in result, result
    assert 'PASSWORD = os.environ.get("DB_PASSWORD")' in result, result


def test_sensitive_context_redacts_key_blocks_and_url_credentials():
    from app.ai.context import redact_sensitive_text
    source = ('service_url = "https://demo:pw-value@example.invalid/path"\n'
              '-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----\n')
    result = redact_sensitive_text(source)
    assert "pw-value" not in result, result
    assert "private-material" not in result, result


def test_rule_owasp_mappings():
    py = scan('PASSWORD = "real-secret-value"\n', "secret.py")
    js_xss = js_scanner.scan('document.getElementById("x").innerHTML = input;\n', "x.js")
    js_jwt = js_scanner.scan('jwt.decode(token);\n', "jwt.js")
    js_random = js_scanner.scan('function createSessionToken(){ return Math.random().toString(36); }\n', "random.js")
    assert next(f for f in py if f["rule_id"] == "PY-SECRETS-001")["owasp_ref"].startswith("A07:2025-")
    assert next(f for f in js_xss if f["rule_id"] == "JS-XSS-001")["owasp_ref"] == "A05:2025-Injection"
    assert next(f for f in js_jwt if f["rule_id"] == "JS-JWT-001")["owasp_ref"].startswith("A07:2025-")
    assert next(f for f in js_random if f["rule_id"] == "JS-RANDOM-001")["owasp_ref"] == "A04:2025-Cryptographic-Failures"


def test_a06_python_client_controls_role():
    findings = scan('def update_user(request, user):\n    user.role = request.json.get("role")\n', "roles.py")
    result = next(f for f in findings if f["rule_id"] == "PY-DESIGN-001")
    assert result["owasp_ref"] == "A06:2025-Insecure-Design"


def test_a06_python_authenticated_server_role_not_flagged():
    findings = scan('def update_user(request, user):\n    user.role = request.user.role\n', "roles.py")
    assert not any(f["rule_id"] == "PY-DESIGN-001" for f in findings), findings


def test_a06_javascript_client_controls_admin():
    findings = js_scanner.scan('user.isAdmin = req.body.isAdmin;\n', "roles.js")
    result = next(f for f in findings if f["rule_id"] == "JS-DESIGN-001")
    assert result["owasp_ref"] == "A06:2025-Insecure-Design"


def test_a03_unpinned_python_requirements():
    from app.scanner.dependency_scanner import scan as scan_dependencies
    findings = scan_dependencies("requests\nflask==3.0.0\n", "requirements.txt")
    assert len(findings) == 1 and findings[0]["rule_id"] == "DEP-UNPINNED-001", findings
    assert findings[0]["owasp_ref"].startswith("A03:2025-")


def test_a03_wildcard_package_json_dependency():
    from app.scanner.dependency_scanner import scan as scan_dependencies
    findings = scan_dependencies('{\n  "dependencies": {\n    "demo": "*"\n  }\n}', "package.json")
    assert len(findings) == 1 and findings[0]["rule_id"] == "DEP-UNPINNED-001", findings


def test_a03_exact_package_json_dependency_is_not_flagged():
    from app.scanner.dependency_scanner import scan as scan_dependencies
    findings = scan_dependencies('{"dependencies":{"demo":"1.2.3"}}', "package.json")
    assert findings == [], findings


def test_a03_mutable_python_vcs_dependency_detected():
    from app.scanner.dependency_scanner import scan as scan_dependencies
    findings = scan_dependencies("git+https://example.invalid/team/lib.git#main\n", "requirements.txt")
    assert len(findings) == 1 and findings[0]["rule_id"] == "DEP-SOURCE-001", findings


def test_a06_ai_fix_guidance_does_not_invent_authorization_policy():
    from app.ai.ai_client import _design_fix_guidance
    guidance = _design_fix_guidance("PY-DESIGN-001")
    assert "invent a role/ownership policy" in guidance.lower(), guidance
    assert "return can_fix=false" in guidance.lower(), guidance


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
        test_python_ssrf_avatar_parameter,
        test_python_path_traversal_joined_filename,
        test_flask_send_file_path_traversal,
        test_python_tls_verification_disabled,
        test_python_sensitive_log_detected,
        test_python_empty_except_detected,
        test_python_path_allowlist_suppresses_path_finding,
        test_python_ssrf_allowlist_suppresses_ssrf_finding,
        test_python_password_uses_slow_hash_finding,
        test_js_sql_injection_through_query_alias,
        test_js_safe_text_content_is_not_xss,
        test_js_tls_verification_disabled,
        test_js_sensitive_log_detected,
        test_js_empty_catch_detected,
        test_sensitive_context_redaction,
        test_sensitive_context_redacts_key_blocks_and_url_credentials,
        test_rule_owasp_mappings,
        test_a06_python_client_controls_role,
        test_a06_python_authenticated_server_role_not_flagged,
        test_a06_javascript_client_controls_admin,
        test_a03_unpinned_python_requirements,
        test_a03_wildcard_package_json_dependency,
        test_a03_exact_package_json_dependency_is_not_flagged,
        test_a03_mutable_python_vcs_dependency_detected,
        test_a06_ai_fix_guidance_does_not_invent_authorization_policy,
    ]

    for test in tests:
        test()
        print(f"PASS: {test.__name__}")

    print(f"\nAll {len(tests)} tests passed!")
