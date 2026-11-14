"""Small, offline checks for risky dependency declarations (OWASP A03:2025).

This is not a vulnerability database or a full software supply-chain audit. It
reports declarations that are intentionally unbounded or point at mutable
external sources so users can review and pin them.
"""
from __future__ import annotations

import json
import re
import tomllib
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
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


def advisory_coordinates(code, filename, lock_text=""):
    """Return registry coordinates with their source lines. Never resolve a range online."""
    name = PurePath(filename.replace("\\", "/")).name.lower()
    lines = code.splitlines()
    coordinates = []
    if name == "package.json":
        data = json.loads(code)
        lock = json.loads(lock_text) if lock_text else {}
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            for package, spec in data.get(section, {}).items():
                if not isinstance(spec, str):
                    continue
                version = spec
                exact = r"\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?"
                if not re.fullmatch(exact, version):
                    # Only trust a sibling lock recording the same direct declaration.
                    root = lock.get("packages", {}).get("", {})
                    entry = lock.get("packages", {}).get("node_modules/" + package, {})
                    if (root.get(section, {}).get(package) != spec or entry.get("link")
                            or not re.fullmatch(r"[0-9xX*~^<>=| .-]+|latest", spec)):
                        continue
                    version = entry.get("version", "")
                if re.fullmatch(exact, version):
                    pattern = re.escape(json.dumps(package)) + r"\s*:\s*" + re.escape(json.dumps(spec))
                    line = next((i for i, s in enumerate(lines, 1) if re.search(pattern, s)), 1)
                    coordinates.append((("npm", package, version), line))
        return coordinates
    if name == "pyproject.toml":
        specs = tomllib.loads(code).get("project", {}).get("dependencies", [])
        entries = [(next((i for i, s in enumerate(lines, 1) if spec in s), 1), spec) for spec in specs if isinstance(spec, str)]
    elif name.startswith("requirements") and name.endswith(".txt"):
        entries = list(enumerate(lines, 1))
    else:
        return []
    pins = {}
    for package, version in re.findall(r"(?m)^\s*([\w.-]+)==([^\s;#]+)\s*(?:#.*)?$", lock_text):
        pins.setdefault(canonicalize_name(package), set()).add(version)
    for line, raw in entries:
        try:
            req = Requirement(raw.partition("#")[0].partition(" --hash=")[0].strip())
            if req.url:
                continue
            package = canonicalize_name(req.name)
            versions = [s.version for s in req.specifier if s.operator == "==" and "*" not in s.version]
            if not versions:
                versions = list(pins.get(package, ()))
            if len(versions) == 1 and req.specifier.contains(versions[0], prereleases=True):
                coordinates.append((("PyPI", package, versions[0]), line))
        except (InvalidRequirement, ValueError):
            continue
    return coordinates


async def advisory_findings(code, filename, lock_text="", lookup=None):
    from app.scanner.osv_client import lookup as query_osv
    try:
        coords = advisory_coordinates(code, filename, lock_text)
    except (ValueError, TypeError, AttributeError):
        return []
    matches = await (lookup or query_osv)([key for key, _ in coords])
    lines = code.splitlines()
    findings = []
    for key, line in dict.fromkeys(coords):
        if matches.get(key):
            _, package, version = key
            findings.append(_finding("CS-A03-OSV", "Known dependency advisory", line, lines[line - 1],
                f"{package} {version} matches OSV advisories: {', '.join(matches[key])}.",
                "Review the advisory and select a compatible fixed version."))
    return findings


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
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        lifecycle = {"preinstall", "install", "postinstall", "prepare"}
        remote_shell = re.compile(
            r"(?:curl|wget|iwr|invoke-webrequest)[^|;&]*\|\s*(?:sh|bash|pwsh|powershell)|"
            r"(?:sh|bash|pwsh|powershell)\s+-c\s+[^\n]*(?:https?://|curl|wget)",
            re.IGNORECASE,
        )
        for hook in lifecycle:
            command = scripts.get(hook)
            if not isinstance(command, str) or not remote_shell.search(command):
                continue
            line = next((n for n, text in enumerate(code.splitlines(), 1) if re.search(
                rf'^[ \t]*"{re.escape(hook)}"\s*:', text
            )), 1)
            source_line = code.splitlines()[line - 1] if code.splitlines() else ""
            findings.append(_finding(
                "DEP-SCRIPT-001", "Remote Script Executed During Dependency Install", line, source_line,
                f"The {hook} lifecycle script appears to download and execute remote content during installation, creating a software supply-chain risk.",
                "Avoid piping remote content directly into a shell. Pin and review the script, verify its integrity, and prefer a trusted package release.",
            ))
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
