"""Small, offline checks for risky dependency declarations (OWASP A03:2025).

This is not a vulnerability database or a full software supply-chain audit. It
reports declarations that are intentionally unbounded or point at mutable
external sources so users can review and pin them.
"""
from __future__ import annotations

import json
import re
from pathlib import PurePath
from typing import Any
from app.scanner.owasp_mapping import owasp_2021_ref


def _finding(rule_id: str, title: str, line: int, snippet: str, message: str, suggestion: str) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": "medium",
        "confidence": "medium",
        "cwe_id": "CWE-1104",
        "owasp_ref": "A03:2025-Software-Supply-Chain-Failures",
        "owasp_2021_ref": owasp_2021_ref(rule_id),
        "message": message,
        "line": line,
        "column": 0,
        "end_line": line,
        "end_column": max(1, len(snippet)),
        "suggestion": suggestion,
        "code_snippet": snippet.strip(),
        "context": {},
    }


def _unpinned_specifier(specifier: str) -> bool:
    specifier = specifier.strip().strip("\"'")
    return not specifier or specifier.lower() in {"*", "latest"}


def _scan_requirements(code: str) -> list[dict[str, Any]]:
    findings = []
    for line_no, raw in enumerate(code.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-e ", "--editable ")):
            line = line.split(None, 1)[1].strip()
        elif line.startswith("-"):
            # Index, include, constraint, and pip-option directives are not package declarations.
            continue
        if re.match(r"(?:git\+|https?://|ftp://)", line, re.IGNORECASE):
            if not re.search(r"@[0-9a-f]{40}(?:#|$)", line, re.IGNORECASE):
                findings.append(_finding(
                    "DEP-SOURCE-001", "Dependency Uses Mutable External Source", line_no, raw,
                    "This dependency points to an external URL or VCS reference without a pinned commit; its contents may change between installs.",
                    "Use a trusted package index and pin VCS dependencies to a full immutable commit hash; review the source before installing.",
                ))
            continue
        # Strip environment markers and hashes before looking for a version bound.
        requirement = line.split("#", 1)[0].split(";", 1)[0].split(" --hash=", 1)[0].strip()
        match = re.match(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?\s*(.*)$", requirement)
        if match and _unpinned_specifier(match.group(1)):
            findings.append(_finding(
                "DEP-UNPINNED-001", "Unpinned Python Dependency", line_no, raw,
                "This dependency has no version constraint, so installs can resolve to different code over time.",
                "Pin a reviewed version and keep a lock or constraints file updated as part of dependency maintenance.",
            ))
    return findings


def _scan_package_json(code: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(code)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(data, dict):
        return []
    findings = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for package, spec in deps.items():
            if not isinstance(spec, str):
                continue
            line = next((n for n, text in enumerate(code.splitlines(), 1) if re.search(
                rf'^[ \t]*"{re.escape(package)}"\s*:', text
            )), 1)
            source_line = code.splitlines()[line - 1] if code.splitlines() else ""
            if spec.strip().lower() in {"*", "latest"}:
                findings.append(_finding(
                    "DEP-UNPINNED-001", "Unbounded JavaScript Dependency", line, source_line,
                    f"Dependency {package} uses {spec!r}, which can resolve to different code over time.",
                    "Pin a reviewed package version and update it through a reviewed dependency change.",
                ))
            elif re.match(r"^(git\+|git:|https?://|github:)", spec, re.IGNORECASE):
                if not re.search(r"#[0-9a-f]{40}(?:$|\?)", spec, re.IGNORECASE):
                    findings.append(_finding(
                        "DEP-SOURCE-001", "Dependency Uses Mutable External Source", line, source_line,
                        f"Dependency {package} uses an external source without a pinned commit; its contents may change between installs.",
                        "Prefer a trusted registry release, or pin the external source to a full immutable commit hash and review it.",
                    ))
    return findings


def _scan_pyproject(code: str) -> list[dict[str, Any]]:
    try:
        import tomllib
        data = tomllib.loads(code)
    except (ImportError, ValueError):
        return []
    deps = data.get("project", {}).get("dependencies", [])
    if not isinstance(deps, list):
        return []
    findings = []
    for requirement in deps:
        if not isinstance(requirement, str):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)$", requirement)
        if match and _unpinned_specifier(match.group(2)):
            line = next((n for n, text in enumerate(code.splitlines(), 1) if requirement in text), 1)
            source_line = code.splitlines()[line - 1] if code.splitlines() else requirement
            findings.append(_finding(
                "DEP-UNPINNED-001", "Unpinned Python Dependency", line, source_line,
                f"Dependency {match.group(1)} has no version constraint, so installs can resolve to different code over time.",
                "Pin a reviewed version and keep a lock or constraints file updated as part of dependency maintenance.",
            ))
    return findings


def scan(code: str, filename: str) -> list[dict[str, Any]]:
    name = PurePath(filename.replace("\\", "/")).name.lower()
    if name == "package.json":
        findings = _scan_package_json(code)
    elif name == "pyproject.toml":
        findings = _scan_pyproject(code)
    elif name.startswith("requirements") and name.endswith(".txt"):
        findings = _scan_requirements(code)
    else:
        findings = []
    for finding in findings:
        finding["context"] = {"filename": filename}
    return findings
