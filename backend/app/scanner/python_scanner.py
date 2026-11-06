import ast
import io
import re
import tokenize
from dataclasses import dataclass, field, asdict
from typing import List

from app.scanner.rules.python_rules import PYTHON_RULES


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    cwe_id: str
    owasp_ref: str
    message: str
    line: int
    column: int
    end_line: int
    end_column: int
    suggestion: str
    code_snippet: str = ""
    context: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


class _RuleVisitor(ast.NodeVisitor):
    def __init__(self, source: str, tree: ast.AST | None = None, validate: bool = True,
                 tainted_names: set[str] | None = None, url_constants: set[str] | None = None):
        # keep source lines so we can grab the exact code snippet later
        self.source = source.splitlines()
        self.findings: List[Finding] = []
        self._tree = tree
        self._validate = validate
        self._tainted_names = tainted_names or set()
        self._url_constants = url_constants or set()

    def _editor_column(self, line: int, utf8_column: int) -> int:
        """Convert CPython AST UTF-8 byte columns to VS Code UTF-16 columns."""
        if not 1 <= line <= len(self.source):
            return max(0, utf8_column)
        prefix_bytes = self.source[line - 1].encode("utf-8")[:max(0, utf8_column)]
        prefix = prefix_bytes.decode("utf-8", errors="ignore")
        return len(prefix.encode("utf-16-le")) // 2

    def _snippet(self, node: ast.AST) -> str:
        # get the lines involved in this AST node
        start = node.lineno
        end = getattr(node, "end_lineno", start)
        return "\n".join(self.source[start - 1 : end])

    def _check(self, node: ast.AST, rule: dict, tree: ast.AST | None = None):
        # O-03: semantic validation prunes likely false positives
        reason = "no-validator-keep"
        if tree is not None and self._validate:
            try:
                from app.scanner.semantic import validate_finding
                keep, reason = validate_finding(rule["id"], node, tree)
                if not keep:
                    return
            except Exception:
                pass
        # record a finding when a rule matches
        self.findings.append(
            Finding(
                rule_id=rule["id"],
                title=rule["title"],
                severity=rule["severity"],
                confidence=rule["confidence"],
                cwe_id=rule["cwe_id"],
                owasp_ref=rule["owasp_ref"],
                message=rule["message"],
                line=node.lineno,
                column=self._editor_column(node.lineno, node.col_offset),
                end_line=getattr(node, "end_lineno", node.lineno),
                end_column=self._editor_column(
                    getattr(node, "end_lineno", node.lineno),
                    getattr(node, "end_col_offset", node.col_offset),
                ),
                suggestion=rule["suggestion"],
                code_snippet=self._snippet(node),
                context={"validation": reason},
            )
        )

    def visit_Call(self, node: ast.Call):
        # check all call-based rules, e.g. eval(), exec(), os.system()
        for rule in PYTHON_RULES:
            if rule.get("checker") != "call":
                continue
            rule_id = rule["id"]
            if rule_id == "PY-SQLI-001":
                matched = rule["matches"](node, self._tainted_names)
            elif rule_id == "PY-CMD-001":
                matched = rule["matches"](node, self._tainted_names)
            elif rule_id == "PY-SSRF-001":
                matched = rule["matches"](node, self._url_constants)
            elif rule_id == "PY-PATH-001":
                matched = rule["matches"](node, self._tainted_names)
            else:
                matched = rule["matches"](node)
            if matched:
                self._check(node, rule, self._tree)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # check assignment-based rules, e.g. hardcoded secrets, weak hash
        for rule in PYTHON_RULES:
            if rule.get("checker") == "assign" and rule["matches"](node):
                self._check(node, rule, self._tree)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            for rule in PYTHON_RULES:
                if rule.get("checker") == "assign" and rule["matches"](node):
                    self._check(node, rule, self._tree)
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr):
        # check standalone expressions like eval(...)
        for rule in PYTHON_RULES:
            if rule.get("checker") == "eval" and rule["matches"](node):
                self._check(node, rule, self._tree)
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        # future-proofing: for-loop rules go here if needed
        for rule in PYTHON_RULES:
            if rule.get("checker") == "for" and rule["matches"](node):
                self._check(node, rule, self._tree)
        self.generic_visit(node)


def scan(source: str, filename: str = "untitled", validate: bool = True) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        # if code cannot parse, return one friendly PARSE-ERROR finding
        findings = [
            {
                "rule_id": "PARSE-ERROR",
                "title": "Syntax Error",
                "severity": "info",
                "confidence": "high",
                "cwe_id": "N/A",
                "owasp_ref": "N/A",
                "message": f"Could not parse file: {exc.msg} at line {exc.lineno}",
                "line": exc.lineno or 1,
                "column": max(0, (exc.offset or 1) - 1),
                "end_line": exc.lineno or 1,
                "end_column": (exc.offset or 0) + 1,
                "suggestion": "Fix syntax errors before scanning.",
                "code_snippet": "",
                "context": {"filename": filename},
            }
        ]
        findings.extend(_partial_scan(source, filename))
        return findings

    from app.scanner.rules.python_rules import _mark_tainted, _mark_url_constants
    tainted_names = _mark_tainted(tree)
    url_constants = _mark_url_constants(tree)
    visitor = _RuleVisitor(source, tree, validate=validate, tainted_names=tainted_names,
                           url_constants=url_constants)
    visitor.visit(tree)
    return [f.to_dict() for f in visitor.findings]


def _partial_scan(source: str, filename: str) -> list[dict]:
    """Find high-confidence patterns in an incomplete Python buffer."""
    lines = source.splitlines()
    masked = [list(line) for line in lines]
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                row, col = token.start
                end_row, end_col = token.end
                for line_no in range(row - 1, min(end_row, len(masked))):
                    start_col = col if line_no == row - 1 else 0
                    stop_col = end_col if line_no == end_row - 1 else len(masked[line_no])
                    for pos in range(start_col, min(stop_col, len(masked[line_no]))):
                        masked[line_no][pos] = " "
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass

    patterns: list[tuple[str, str, str, str, str]] = [
        ("PY-SECRETS-001", "Potential Hardcoded Secret", "high", "CWE-798",
         r"\b[A-Za-z_]\w*(?:PASSWORD|SECRET|API_KEY|TOKEN|CREDENTIAL)\w*\s*=\s*[rubfRUBF]*([\"']).+?\1"),
        ("PY-SQLI-001", "Potential SQL Injection", "critical", "CWE-89",
         r"\.(?:execute|executemany|executescript)\s*\(\s*(?:[fF][rRuU]*[\"']|[\"'][^\n]*[\"']\s*[+%])"),
        ("PY-CMD-001", "Potential Command Injection", "critical", "CWE-78",
         r"(?:os\.(?:system|popen)\s*\(|subprocess\.(?:run|call|Popen|check_call|check_output)\s*\([^\n]*(?:shell\s*=\s*True|[fF][rRuU]*[\"']))"),
        ("PY-CODE-EXEC-001", "Dangerous eval() Usage", "critical", "CWE-95", r"\beval\s*\("),
        ("PY-CODE-EXEC-002", "Dangerous exec()/compile() Usage", "critical", "CWE-94", r"\b(?:exec|compile)\s*\("),
        ("PY-CRYPTO-001", "Weak Hashing Algorithm (MD5)", "high", "CWE-328", r"\bmd5\s*\("),
        ("PY-CRYPTO-002", "Weak Hashing Algorithm (SHA1)", "high", "CWE-328", r"\bsha1\s*\("),
        ("PY-CONFIG-001", "Debug Mode Enabled", "medium", "CWE-489", r"\bDEBUG\s*=\s*True\b"),
    ]
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for line_no, chars in enumerate(masked, start=1):
        code_line = "".join(chars)
        for rule_id, title, severity, cwe, pattern in patterns:
            match = re.search(pattern, code_line, re.IGNORECASE)
            if not match or (rule_id, line_no) in seen:
                continue
            seen.add((rule_id, line_no))
            findings.append({
                "rule_id": rule_id, "title": title, "severity": severity,
                "confidence": "medium", "cwe_id": cwe, "owasp_ref": "N/A",
                "message": "Potential security issue found while the file has a syntax error. Review this line after fixing syntax.",
                "line": line_no,
                "column": len(lines[line_no - 1][:match.start()].encode("utf-16-le")) // 2,
                "end_line": line_no,
                "end_column": len(lines[line_no - 1][:match.end()].encode("utf-16-le")) // 2,
                "suggestion": "Review the insecure pattern and use a context-appropriate secure alternative.",
                "code_snippet": lines[line_no - 1].strip(),
                "context": {"filename": filename, "partial_scan": True},
            })
    return findings
