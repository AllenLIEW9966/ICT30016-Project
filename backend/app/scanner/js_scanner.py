import re
from typing import Any
from app.scanner.owasp_mapping import owasp_2021_ref

# rule format: id, title, severity, confidence, cwe/owasp,
# message, suggestion, regex pattern + flags


JS_RULES = [
    # A05:2025 Injection — eval() is basically open door for attackers
    {
        "id": "JS-CODE-EXEC-001",
        "title": "Dangerous eval() Usage",
        "severity": "critical",
        "confidence": "high",
        "cwe_id": "CWE-95",
        "owasp_ref": "A05:2025-Injection",
        "message": "eval() executes arbitrary code and is a major security risk.",
        "suggestion": "Use JSON.parse() for data or avoid dynamic execution entirely.",
        "pattern": re.compile(r"\beval\s*\("),
    },
    # A05:2025 — new Function() also risky
    {
        "id": "JS-CODE-EXEC-002",
        "title": "Dangerous Function Constructor",
        "severity": "critical",
        "confidence": "high",
        "cwe_id": "CWE-94",
        "owasp_ref": "A05:2025-Injection",
        "message": "new Function() executes dynamic code and is risky with user input.",
        "suggestion": "Use named functions or arrow functions instead.",
        "pattern": re.compile(r"new\s+Function\s*\("),
    },
    # A04:2025 — MD5/SHA1 very weak already
    {
        "id": "JS-CRYPTO-001",
        "title": "Weak Hashing Algorithm (MD5/SHA1)",
        "severity": "high",
        "confidence": "high",
        "cwe_id": "CWE-328",
        "owasp_ref": "A04:2025-Cryptographic-Failures",
        "message": "MD5/SHA1 are cryptographically broken or deprecated.",
        "suggestion": "Use SHA-256+ via Web Crypto API or a modern library.",
        "pattern": re.compile(r"\b(md5|sha1)\b", re.IGNORECASE),
    },
    # A05:2025 — SQLi via template literals / string concat
    {
        "id": "JS-SQLI-001",
        "title": "Potential SQL Injection",
        "severity": "critical",
        "confidence": "medium",
        "cwe_id": "CWE-89",
        "owasp_ref": "A05:2025-Injection",
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
        "owasp_ref": "A05:2025-Injection",
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
        "owasp_ref": "A01:2025-Broken-Access-Control",
        "message": "A request URL appears to come from request-controlled data. Validate its scheme, host, and resolved IP before requesting.",
        "suggestion": "Allowlist trusted hosts and reject loopback, private, and link-local destinations.",
        "pattern": re.compile(r"(?:fetch|axios\.(?:get|post|put|delete)|request)\s*\(\s*(?:req|request|ctx)\.(?:query|params|body|url)"),
    },
    # A05:2025 — XSS remains an injection concern.
    {
        "id": "JS-XSS-001",
        "title": "Potential XSS via innerHTML / document.write",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-79",
        "owasp_ref": "A05:2025-Injection",
        "message": "Assigning user-controlled content to innerHTML or document.write may cause XSS.",
        "suggestion": "Use textContent for text, or sanitize with DOMPurify before innerHTML.",
        "pattern": re.compile(r"\.innerHTML\s*=|document\.write\s*\("),
    },
    # A04:2025 — predictable randomness used for security tokens is a cryptographic failure.
    {
        "id": "JS-RANDOM-001",
        "title": "Insecure Randomness (Math.random)",
        "severity": "medium",
        "confidence": "high",
        "cwe_id": "CWE-338",
        "owasp_ref": "A04:2025-Cryptographic-Failures",
        "message": "Math.random() is not cryptographically secure.",
        "suggestion": "Use crypto.getRandomValues() for security-sensitive random values.",
        "pattern": re.compile(r"Math\.random\s*\("),
    },
    # A07:2025 — hardcoded credentials can undermine authentication.
    {
        "id": "JS-SECRETS-001",
        "title": "Potential Hardcoded Secret",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-798",
        "owasp_ref": "A07:2025-Authentication-Failures",
        "message": "CodeShield detected a possible hard-coded secret. Move the value to an environment variable or secret manager.",
        "suggestion": "Load secrets from process.env, a .env file, or a secrets manager.",
        "pattern": re.compile(
            r"(?:const|let|var)\s+[A-Za-z_$]*?(?:PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIAL)[A-Za-z_$]*\s*=\s*[\"'`][^\"'`]+[\"'`]",
            re.IGNORECASE,
        ),
    },
    # A02:2025 — debugger left in code
    {
        "id": "JS-CONFIG-001",
        "title": "Debugger Statement Present",
        "severity": "low",
        "confidence": "high",
        "cwe_id": "CWE-489",
        "owasp_ref": "A02:2025-Security-Misconfiguration",
        "message": "debugger statements should be removed before production deployment.",
        "suggestion": "Remove debugger statements or wrap them behind a dev-only flag.",
        "pattern": re.compile(r"^\s*debugger\s*;", re.MULTILINE),
    },
    # A07:2025 — accepting an unverified JWT can bypass authentication.
    {
        "id": "JS-JWT-001",
        "title": "Potential Insecure JWT Verification",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-345",
        "owasp_ref": "A07:2025-Authentication-Failures",
        "message": "JWT decode() does not verify signature. Use verify() with a trusted secret/public key.",
        "suggestion": "Use jsonwebtoken.verify(token, secretOrPublicKey) or jose.verify().",
        "pattern": re.compile(r"jwt\.decode\s*\("),
    },
    {
        "id": "JS-TLS-001",
        "title": "TLS Certificate Verification Disabled",
        "severity": "high",
        "confidence": "high",
        "cwe_id": "CWE-295",
        "owasp_ref": "A02:2025-Security-Misconfiguration",
        "message": "TLS certificate verification is disabled, allowing interception of the connection.",
        "suggestion": "Keep certificate verification enabled and configure a trusted CA when needed.",
        "pattern": re.compile(r"\brejectUnauthorized\s*:\s*false\b|\bstrictSSL\s*:\s*false\b"),
    },
    {
        "id": "JS-LOG-001",
        "title": "Potential Sensitive Data in Logs",
        "severity": "medium",
        "confidence": "medium",
        "cwe_id": "CWE-532",
        "owasp_ref": "A09:2025-Security-Logging-and-Alerting-Failures",
        "message": "A secret-like value appears to be written to a log or console output.",
        "suggestion": "Redact credentials and tokens before logging; log a safe identifier or event instead.",
        "pattern": re.compile(r"(?:console\.(?:log|info|warn|error|debug)|logger\.(?:info|warn|error|debug))\s*\([^\n]*(?:password|passwd|secret|api[_-]?key|token|credential)", re.IGNORECASE),
    },
    {
        "id": "JS-EXCEPT-001",
        "title": "Exception Silently Ignored",
        "severity": "medium",
        "confidence": "medium",
        "cwe_id": "CWE-390",
        "owasp_ref": "A10:2025-Mishandling-of-Exceptional-Conditions",
        "message": "An empty catch block silently discards an error and may hide an unsafe failure state.",
        "suggestion": "Handle expected errors explicitly and fail safely; record sanitized diagnostics where appropriate.",
        "pattern": re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"),
    },
    {
        "id": "JS-SERIAL-001",
        "title": "Unsafe JavaScript Deserialization",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-502",
        "owasp_ref": "A08:2025-Software-or-Data-Integrity-Failures",
        "message": "An unserialize() call may reconstruct executable or unsafe objects from untrusted data.",
        "suggestion": "Avoid unsafe object deserializers for untrusted input. Use a data-only format such as JSON only when it matches the existing data contract, validate its schema, and plan any required data migration.",
        "pattern": re.compile(r"\bunserialize\s*\("),
    },
    {
        "id": "JS-DESIGN-001",
        "title": "Client-Controlled Authorization Field",
        "severity": "high",
        "confidence": "medium",
        "cwe_id": "CWE-602",
        "owasp_ref": "A06:2025-Insecure-Design",
        "message": "Request data is assigned directly to a privileged role or permission field. A client must not decide its own authorization level.",
        "suggestion": "Derive privileges from the authenticated server-side identity and enforce authorization and ownership checks on the server.",
        "pattern": re.compile(r"(?:[A-Za-z_$][\w$]*\.)?(?:role|admin|isAdmin|is_admin|isStaff|is_staff|isSuperuser|is_superuser|permissions?|accessLevel|access_level)\s*=\s*(?:req|request|ctx)\.(?:body|query|params)\.", re.IGNORECASE),
    },
]


def _collect_findings(source: str, filename: str) -> list[dict]:
    findings = []
    lines = source.splitlines()
    masked_source = _mask_comments(source)
    code_lines = masked_source.splitlines()
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
                        "owasp_2021_ref": owasp_2021_ref(rule["id"]),
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

    # Empty catch blocks commonly span multiple lines. The per-line rule above
    # cannot see the opening and closing braces together, so scan the masked
    # source as a whole as well. Masking comments first avoids treating a
    # comment-only catch body as meaningful handling.
    exception_rule = next((rule for rule in JS_RULES if rule["id"] == "JS-EXCEPT-001"), None)
    if exception_rule:
        empty_catch = re.compile(r"\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}", re.DOTALL)
        for match in empty_catch.finditer(masked_source):
            line_no = masked_source.count("\n", 0, match.start()) + 1
            line_start = masked_source.rfind("\n", 0, match.start()) + 1
            end_line = masked_source.count("\n", 0, match.end()) + 1
            end_line_start = masked_source.rfind("\n", 0, match.end()) + 1
            column = match.start() - line_start
            end_column = match.end() - end_line_start
            if any(
                finding["rule_id"] == exception_rule["id"]
                and finding["line"] == line_no
                and finding["column"] == column
                for finding in findings
            ):
                continue
            source_line = lines[line_no - 1] if line_no <= len(lines) else ""
            findings.append({
                "rule_id": exception_rule["id"],
                "title": exception_rule["title"],
                "severity": exception_rule["severity"],
                "confidence": exception_rule["confidence"],
                "cwe_id": exception_rule["cwe_id"],
                "owasp_ref": exception_rule["owasp_ref"],
                "owasp_2021_ref": owasp_2021_ref(exception_rule["id"]),
                "message": exception_rule["message"],
                "line": line_no,
                "column": column,
                "end_line": end_line,
                "end_column": end_column,
                "suggestion": exception_rule["suggestion"],
                "code_snippet": source_line.strip(),
                "context": {"filename": filename},
            })

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
            # A parse error (for example, JSON pasted into a .js file) must not
            # suppress independent high-confidence security findings elsewhere
            # in the buffer. Keep the parser diagnostic, then supplement it
            # with the comment-masked regex scan below.
            if any(finding.get("rule_id") == "PARSE-ERROR" for finding in findings):
                fallback_findings = _collect_findings(source, filename)
                merged = list(findings)
                for finding in fallback_findings:
                    if not any(
                        existing.get("rule_id") == finding.get("rule_id")
                        and existing.get("line") == finding.get("line")
                        and existing.get("column") == finding.get("column")
                        for existing in merged
                    ):
                        merged.append(finding)
                return merged
            # Keep newly-added lightweight rules active when the AST sidecar is
            # available. The regex fallback alone would otherwise make their
            # behavior depend on whether Node/Babel could be started.
            supplemental_ids = {"JS-TLS-001", "JS-LOG-001", "JS-EXCEPT-001", "JS-DESIGN-001", "JS-SERIAL-001"}
            supplemental = [
                finding for finding in _collect_findings(source, filename)
                if finding["rule_id"] in supplemental_ids
                and not any(
                    existing["rule_id"] == finding["rule_id"]
                    and existing["line"] == finding["line"]
                    for existing in findings
                )
            ]
            return findings + supplemental
    except Exception:
        pass
    return _collect_findings(source, filename)
