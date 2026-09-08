import re
from typing import Any

# rule format: id, title, severity, confidence, cwe/owasp,
# message, suggestion, regex pattern + flags


JS_RULES = [
    # A03:2021 Injection — eval() is basically open door for attackers
    {
        "id": "JS-CODE-EXEC-001",
        "title": "Dangerous eval() Usage",
        "severity": "critical",
        "confidence": "high",
        "cwe_id": "CWE-95",
        "owasp_ref": "A03:2021-Injection",
        "message": "eval() executes arbitrary code and is a major security risk.",
        "suggestion": "Use JSON.parse() for data or avoid dynamic execution entirely.",
        "pattern": re.compile(r"\beval\s*\("),
    },
    # A03:2021 — new Function() also risky
    {
        "id": "JS-CODE-EXEC-002",
        "title": "Dangerous Function Constructor",
        "severity": "critical",
        "confidence": "high",
        "cwe_id": "CWE-94",
        "owasp_ref": "A03:2021-Injection",
        "message": "new Function() executes dynamic code and is risky with user input.",
        "suggestion": "Use named functions or arrow functions instead.",
        "pattern": re.compile(r"new\s+Function\s*\("),
    },
    # A02:2021 — MD5/SHA1 very weak already
    {
        "id": "JS-CRYPTO-001",
        "title": "Weak Hashing Algorithm (MD5/SHA1)",
        "severity": "high",
        "confidence": "high",
        "cwe_id": "CWE-328",
        "owasp_ref": "A02:2021-Cryptographic-Failures",
        "message": "MD5/SHA1 are cryptographically broken or deprecated.",
        "suggestion": "Use SHA-256+ via Web Crypto API or a modern library.",
        "pattern": re.compile(r"\b(md5|sha1)\b", re.IGNORECASE),
    },
    # A03:2021 — SQLi via template literals / string concat
    {
        "id": "JS-SQLI-001",
        "title": "Potential SQL Injection",
        "severity": "critical",
        "confidence": "medium",
        "cwe_id": "CWE-89",
        "owasp_ref": "A03:2021-Injection",
        "message": "SQL query appears built with string concatenation or template literals.",
        "suggestion": "Use parameterized queries: db.query('SELECT * FROM t WHERE id=?', [userId])",
        "pattern": re.compile(r"(execute|query)\s*\([^)]*(`|\"+).*(\$\{|\\\\+).*"),
    },
    # A07:2021 — XSS via innerHTML / document.write
    {
        "id": "JS-XSS-001",
        "title": "Potential XSS via innerHTML / document.write",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-79",
        "owasp_ref": "A07:2021-Identification-and-Authentication-Failures",
        "message": "Assigning user-controlled content to innerHTML or document.write may cause XSS.",
        "suggestion": "Use textContent for text, or sanitize with DOMPurify before innerHTML.",
        "pattern": re.compile(r"\.innerHTML\s*=|document\.write\s*\("),
    },
    # A08:2021 — Math.random not for security use
    {
        "id": "JS-RANDOM-001",
        "title": "Insecure Randomness (Math.random)",
        "severity": "medium",
        "confidence": "high",
        "cwe_id": "CWE-338",
        "owasp_ref": "A08:2021-Software-and-Data-Integrity-Failures",
        "message": "Math.random() is not cryptographically secure.",
        "suggestion": "Use crypto.getRandomValues() for security-sensitive random values.",
        "pattern": re.compile(r"Math\.random\s*\("),
    },
    # A04:2021 — hardcoded secret pattern
    {
        "id": "JS-SECRETS-001",
        "title": "Potential Hardcoded Secret",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-798",
        "owasp_ref": "A04:2021-Insecure-Design",
        "message": "Assignment name suggests a secret. Use environment variables.",
        "suggestion": "Load secrets from process.env, a .env file, or a secrets manager.",
        "pattern": re.compile(
            r"(const|let|var)\s+(PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIAL)\b",
            re.IGNORECASE,
        ),
    },
    # A05:2021 — debugger left in code
    {
        "id": "JS-CONFIG-001",
        "title": "Debugger Statement Present",
        "severity": "low",
        "confidence": "high",
        "cwe_id": "CWE-489",
        "owasp_ref": "A05:2021-Security-Misconfiguration",
        "message": "debugger statements should be removed before production deployment.",
        "suggestion": "Remove debugger statements or wrap them behind a dev-only flag.",
        "pattern": re.compile(r"^\s*debugger\s*;", re.MULTILINE),
    },
    # A10:2021 — jwt.decode doesn't verify signature
    {
        "id": "JS-JWT-001",
        "title": "Potential Insecure JWT Verification",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-345",
        "owasp_ref": "A10:2021-Server-Side-Request-Forgery-(SSRF)",
        "message": "JWT decode() does not verify signature. Use verify() with a trusted secret/public key.",
        "suggestion": "Use jsonwebtoken.verify(token, secretOrPublicKey) or jose.verify().",
        "pattern": re.compile(r"jwt\.decode\s*\("),
    },
]


def _collect_findings(source: str, filename: str) -> list[dict]:
    findings = []
    lines = source.splitlines()

    # simple line-by-line regex scan for JS
    for lineno, line in enumerate(lines, start=1):
        for rule in JS_RULES:
            if rule["pattern"].search(line):
                findings.append(
                    {
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "confidence": rule["confidence"],
                        "cwe_id": rule["cwe_id"],
                        "owasp_ref": rule["owasp_ref"],
                        "message": rule["message"],
                        "line": lineno,
                        "column": 1,
                        "end_line": lineno,
                        "end_column": len(line) + 1,
                        "suggestion": rule["suggestion"],
                        "code_snippet": line.strip(),
                        "context": {"filename": filename},
                    }
                )

    return findings


def scan(source: str, filename: str = "untitled") -> list[dict]:
    # JS scanner is regex-based for now; proper AST can come later
    return _collect_findings(source, filename)
