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
        "pattern": re.compile(r"(?:execute|query)\s*\(\s*(?:`[^`]*\$\{|[\"'][^\n]*[\"']\s*\+\s*[A-Za-z_$])"),
    },
    {
        "id": "JS-CMD-001",
        "title": "Potential Command Injection",
        "severity": "critical",
        "confidence": "high",
        "cwe_id": "CWE-78",
        "owasp_ref": "A03:2021-Injection",
        "message": "Dynamic input may reach a shell command. Avoid shell execution and pass validated arguments separately.",
        "suggestion": "Use a fixed executable and an argument array with shell disabled.",
        "pattern": re.compile(r"(?:child_process|cp)\.(?:exec|execSync)\s*\("),
    },
    {
        "id": "JS-SSRF-001",
        "title": "Potential Server-Side Request Forgery",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-918",
        "owasp_ref": "A10:2021-Server-Side-Request-Forgery-(SSRF)",
        "message": "A request URL appears to come from request-controlled data. Validate its scheme, host, and resolved IP before requesting.",
        "suggestion": "Allowlist trusted hosts and reject loopback, private, and link-local destinations.",
        "pattern": re.compile(r"(?:fetch|axios\.(?:get|post|put|delete)|request)\s*\(\s*(?:req|request|ctx)\.(?:query|params|body|url)"),
    },
    # A03:2021 — XSS is included under Injection in the 2021 Top 10.
    {
        "id": "JS-XSS-001",
        "title": "Potential XSS via innerHTML / document.write",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-79",
        "owasp_ref": "A03:2021-Injection",
        "message": "Assigning user-controlled content to innerHTML or document.write may cause XSS.",
        "suggestion": "Use textContent for text, or sanitize with DOMPurify before innerHTML.",
        "pattern": re.compile(r"\.innerHTML\s*=|document\.write\s*\("),
    },
    # A02:2021 — predictable randomness used for security tokens is a cryptographic failure.
    {
        "id": "JS-RANDOM-001",
        "title": "Insecure Randomness (Math.random)",
        "severity": "medium",
        "confidence": "high",
        "cwe_id": "CWE-338",
        "owasp_ref": "A02:2021-Cryptographic-Failures",
        "message": "Math.random() is not cryptographically secure.",
        "suggestion": "Use crypto.getRandomValues() for security-sensitive random values.",
        "pattern": re.compile(r"Math\.random\s*\("),
    },
    # A07:2021 — hardcoded credentials can undermine authentication.
    {
        "id": "JS-SECRETS-001",
        "title": "Potential Hardcoded Secret",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-798",
        "owasp_ref": "A07:2021-Identification-and-Authentication-Failures",
        "message": "CodeShield detected a possible hard-coded secret. Move the value to an environment variable or secret manager.",
        "suggestion": "Load secrets from process.env, a .env file, or a secrets manager.",
        "pattern": re.compile(
            r"(?:const|let|var)\s+[A-Za-z_$]*?(?:PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIAL)[A-Za-z_$]*\s*=\s*[\"'`][^\"'`]+[\"'`]",
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
    # A07:2021 — accepting an unverified JWT can bypass authentication.
    {
        "id": "JS-JWT-001",
        "title": "Potential Insecure JWT Verification",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-345",
        "owasp_ref": "A07:2021-Identification-and-Authentication-Failures",
        "message": "JWT decode() does not verify signature. Use verify() with a trusted secret/public key.",
        "suggestion": "Use jsonwebtoken.verify(token, secretOrPublicKey) or jose.verify().",
        "pattern": re.compile(r"jwt\.decode\s*\("),
    },
]


def _collect_findings(source: str, filename: str) -> list[dict]:
    findings = []
    lines = source.splitlines()
    code_lines = _mask_comments(source).splitlines()
    dynamic_sql_names = set()
    for line in code_lines:
        assignment = re.search(
            r"\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(?:`[^`]*\$\{|[\"'][^\n]*(?:[\"']\s*\+\s*[A-Za-z_$]|\$\{))",
            line,
        )
        if assignment and re.search(r"\b(select|insert|update|delete)\b", line, re.IGNORECASE):
            dynamic_sql_names.add(assignment.group(1))

    for lineno, line in enumerate(lines, start=1):
        for rule in JS_RULES:
            match = rule["pattern"].search(code_lines[lineno - 1])
            if not match and rule["id"] == "JS-SQLI-001":
                variable_use = re.search(r"(?:execute|query)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)", code_lines[lineno - 1])
                if variable_use and variable_use.group(1) in dynamic_sql_names:
                    match = variable_use
            if match:
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
                        "column": match.start(),
                        "end_line": lineno,
                        "end_column": match.end(),
                        "suggestion": rule["suggestion"],
                        "code_snippet": line.strip(),
                        "context": {"filename": filename},
                    }
                )

    return findings


def _mask_comments(source: str) -> str:
    """Blank JavaScript comments without shifting any source offsets."""
    chars = list(source)
    quote = ""
    escaped = line_comment = block_comment = False
    i = 0
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
            else:
                chars[i] = " "
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                block_comment = False
                i += 2
                continue
            if ch != "\n":
                chars[i] = " "
            i += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            i += 1
            continue
        if ch == "/" and nxt == "/":
            chars[i] = chars[i + 1] = " "
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            chars[i] = chars[i + 1] = " "
            block_comment = True
            i += 2
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
        i += 1
    return "".join(chars)


def scan(source: str, filename: str = "untitled") -> list[dict]:
    """O-01: @babel/parser AST via sidecar, regex fallback if Node missing."""
    try:
        from app.scanner.js_ast_bridge import scan_with_ast
        findings = scan_with_ast(source, filename)
        if findings is not None:
            return findings
    except Exception:
        pass
    return _collect_findings(source, filename)
