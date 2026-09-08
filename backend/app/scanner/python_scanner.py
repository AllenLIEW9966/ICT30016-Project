import ast
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
    def __init__(self, source: str):
        # keep source lines so we can grab the exact code snippet later
        self.source = source.splitlines()
        self.findings: List[Finding] = []

    def _snippet(self, node: ast.AST) -> str:
        # get the lines involved in this AST node
        start = node.lineno
        end = getattr(node, "end_lineno", start)
        return "\n".join(self.source[start - 1 : end])

    def _check(self, node: ast.AST, rule: dict):
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
                column=node.col_offset,
                end_line=getattr(node, "end_lineno", node.lineno),
                end_column=getattr(node, "end_col_offset", node.col_offset),
                suggestion=rule["suggestion"],
                code_snippet=self._snippet(node),
                context={},
            )
        )

    def visit_Call(self, node: ast.Call):
        # check all call-based rules, e.g. eval(), exec(), os.system()
        for rule in PYTHON_RULES:
            if rule.get("checker") == "call" and rule["matches"](node):
                self._check(node, rule)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # check assignment-based rules, e.g. hardcoded secrets, weak hash
        for rule in PYTHON_RULES:
            if rule.get("checker") == "assign" and rule["matches"](node):
                self._check(node, rule)
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr):
        # check standalone expressions like eval(...)
        for rule in PYTHON_RULES:
            if rule.get("checker") == "eval" and rule["matches"](node):
                self._check(node, rule)
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        # future-proofing: for-loop rules go here if needed
        for rule in PYTHON_RULES:
            if rule.get("checker") == "for" and rule["matches"](node):
                self._check(node, rule)
        self.generic_visit(node)


def scan(source: str, filename: str = "untitled") -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        # if code cannot parse, return one friendly PARSE-ERROR finding
        return [
            {
                "rule_id": "PARSE-ERROR",
                "title": "Syntax Error",
                "severity": "info",
                "confidence": "high",
                "cwe_id": "N/A",
                "owasp_ref": "N/A",
                "message": f"Could not parse file: {exc.msg} at line {exc.lineno}",
                "line": exc.lineno or 1,
                "column": exc.offset or 0,
                "end_line": exc.lineno or 1,
                "end_column": (exc.offset or 0) + 1,
                "suggestion": "Fix syntax errors before scanning.",
                "code_snippet": "",
                "context": {"filename": filename},
            }
        ]

    visitor = _RuleVisitor(source)
    visitor.visit(tree)
    return [f.to_dict() for f in visitor.findings]
