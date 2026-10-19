"""O-02 fallback: deterministic templates when the local LLM is down.

Each entry returns an applicable patch for the finding's rule_id.
Used by suggest_fix when the AI call fails (report fallback:
Tier 1 + rule-based patch templates if M2.5 inference is unavailable).
Language-aware: only returns a template when the language matches.
"""
from __future__ import annotations

_TEMPLATES: dict[tuple[str, str], dict] = {
    ("python", "PY-SQLI-001"): {
        "explanation": (
            "SQL query built with f-string/format/concat lets input alter the query. "
            "Use a parameterized placeholder and pass values separately."
        ),
        "secure_code": 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
    },
    ("python", "PY-SECRETS-001"): {
        "explanation": "Hardcoded credential in source. Load it from the environment instead.",
        "secure_code": 'import os\nPASSWORD = os.environ["DB_PASSWORD"]',
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


def template_fix(language: str, rule_id: str) -> dict | None:
    key = ((language or "").lower(), (rule_id or "").upper())
    # normalise 'js' -> 'javascript'
    if key[0] == "js":
        key = ("javascript", key[1])
    tpl = _TEMPLATES.get(key)
    if tpl is None:
        return None
    return {
        "explanation": tpl["explanation"] + " (rule-based fallback, LLM unavailable)",
        "secure_code": tpl["secure_code"],
        "references": [],
    }
