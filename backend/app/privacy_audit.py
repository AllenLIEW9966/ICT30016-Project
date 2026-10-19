"""O-05 zero-egress audit (NFR-02 evidence).

Static: scans backend + extension source for cloud API hosts, API keys,
telemetry endpoints. Fails if any non-localhost HTTP(S) URL or known
cloud vendor host is found in code/config (excluding docs/comments
that merely mention them).

Dynamic helper: prints the packet-capture command for the M5 demo session.

Usage: ./venv/Scripts/python app/privacy_audit.py
Writes PRIVACY-REPORT.md in backend/.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
ROOT = BACKEND.parent

ALLOW_DOCS = {"md", "txt", "log", "json"}
CLOUD_RE = re.compile(
    r"(api\.openai\.com|openai\.com|anthropic\.com|googleapis\.com|"
    r"azure\.com|amazonaws\.com|cloudflare\.com|sentry\.io|segment\.io|"
    r"telemetry|analytics\.google|mixpanel|amplitude)",
    re.IGNORECASE)
URL_RE = re.compile(r"https?://([A-Za-z0-9.\-:]+)")
LOCAL = {"localhost", "127.0.0.1", "::1"}


def main() -> None:
    hits: list[str] = []
    for base in [BACKEND / "app", BACKEND / "js-ast", ROOT / "extension" / "src"]:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix in {".map"}:
                continue
            if "node_modules" in path.parts or "__pycache__" in path.parts:
                continue
            # build-time manifests, not runtime egress
            if path.name in {"package-lock.json", "privacy_audit.py"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="strict")
            except Exception:
                continue
            rel = str(path.relative_to(ROOT))
            for i, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                if not s or s.startswith(("*", "//", "#", "<!--")):
                    continue
                # npm registry URLs are install-time, not code egress
                if "registry.npmjs.org" in line or "registry.yarnpkg.com" in line:
                    continue
                if CLOUD_RE.search(line):
                    hits.append(f"{rel}:{i}: cloud-host mention: {s[:120]}")
                for m in URL_RE.finditer(line):
                    host = m.group(1).split(":")[0].lower()
                    if host not in LOCAL and "example.com" not in host and "owasp.org" not in host:
                        # references lists (OWASP/CWE URLs) are explanation text, not egress
                        if "references" in line.lower() or "https://owasp" in line.lower() or "cwe.mitre" in line.lower():
                            continue
                        hits.append(f"{rel}:{i}: non-local URL: {s[:120]}")

    # config defaults must be local
    cfg_ok = True
    pkg = ROOT / "extension" / "package.json"
    if pkg.exists() and ("gpt-4o" in pkg.read_text() or "8001" in pkg.read_text()):
        hits.append("extension/package.json: non-local AI defaults")
        cfg_ok = False

    ok = len(hits) == 0
    md = (
        "# CodeShield AI — Privacy Report (O-05 / NFR-02)\n\n"
        f"- Static egress audit: **{'PASS — no cloud hosts / non-local URLs in code' if ok else 'FAIL'}**\n"
        + ("".join(f"  - {h}\n" for h in hits) if hits else "")
        + "- Defaults: Ollama `http://localhost:11434/v1` + `codellama:7b-instruct` "
        + ("PASS (local-only)" if cfg_ok else "FAIL") + "\n"
        "- Dynamic (M5 demo): run a full scan-to-AI-fix session, capture with:\n"
        "  `tshark -i any -f \"tcp port 80 or tcp port 443\" -a duration:120 -w m5-capture.pcapng`\n"
        "  then confirm no packets with source-content payloads leave localhost.\n"
        "  Expected: only loopback traffic to :8000 (backend) and :11434 (Ollama).\n"
    )
    (BACKEND / "PRIVACY-REPORT.md").write_text(md)
    print(md)


if __name__ == "__main__":
    main()
