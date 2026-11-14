"""Rule-level crosswalk from selected OWASP Top 10:2025 findings to 2021.

This is a compatibility label, not evidence of comprehensive category coverage.
Where there is no defensible direct counterpart, the result is N/A.
"""

OWASP_2021_BY_RULE = {
    "CS-A03-OSV": "A06:2021-Vulnerable-and-Outdated-Components",
    "PY-SQLI-001": "A03:2021-Injection", "PY-CMD-001": "A03:2021-Injection",
    "PY-CODE-EXEC-001": "A03:2021-Injection", "PY-CODE-EXEC-002": "A03:2021-Injection",
    "JS-SQLI-001": "A03:2021-Injection", "JS-CMD-001": "A03:2021-Injection",
    "JS-CODE-EXEC-001": "A03:2021-Injection", "JS-CODE-EXEC-002": "A03:2021-Injection",
    "JS-XSS-001": "A03:2021-Injection",
    "PY-CRYPTO-001": "A02:2021-Cryptographic-Failures",
    "PY-CRYPTO-002": "A02:2021-Cryptographic-Failures",
    "PY-PASSWORD-HASH-001": "A02:2021-Cryptographic-Failures",
    "PY-TLS-001": "A02:2021-Cryptographic-Failures",
    "JS-CRYPTO-001": "A02:2021-Cryptographic-Failures",
    "JS-RANDOM-001": "A02:2021-Cryptographic-Failures",
    "JS-TLS-001": "A02:2021-Cryptographic-Failures",
    "PY-CONFIG-001": "A05:2021-Security-Misconfiguration",
    "JS-CONFIG-001": "A05:2021-Security-Misconfiguration",
    "PY-DESIGN-001": "A04:2021-Insecure-Design",
    "JS-DESIGN-001": "A04:2021-Insecure-Design",
    "DEP-UNPINNED-001": "A06:2021-Vulnerable-and-Outdated-Components",
    "DEP-SOURCE-001": "A06:2021-Vulnerable-and-Outdated-Components",
    "DEP-SCRIPT-001": "A06:2021-Vulnerable-and-Outdated-Components",
    "PY-SECRETS-001": "A07:2021-Identification-and-Authentication-Failures",
    "PY-AUTH-001": "A07:2021-Identification-and-Authentication-Failures",
    "JS-SECRETS-001": "A07:2021-Identification-and-Authentication-Failures",
    "JS-AUTH-001": "A07:2021-Identification-and-Authentication-Failures",
    "JS-JWT-001": "A07:2021-Identification-and-Authentication-Failures",
    "PY-SERIAL-001": "A08:2021-Software-and-Data-Integrity-Failures",
    "JS-SERIAL-001": "A08:2021-Software-and-Data-Integrity-Failures",
    "PY-LOG-001": "A09:2021-Security-Logging-and-Monitoring-Failures",
    "PY-LOG-002": "A09:2021-Security-Logging-and-Monitoring-Failures",
    "JS-LOG-001": "A09:2021-Security-Logging-and-Monitoring-Failures",
    "JS-LOG-002": "A09:2021-Security-Logging-and-Monitoring-Failures",
    "PY-SSRF-001": "A10:2021-Server-Side-Request-Forgery",
    "JS-SSRF-001": "A10:2021-Server-Side-Request-Forgery",
    "PY-PATH-001": "A01:2021-Broken-Access-Control",
    "JS-PATH-001": "A01:2021-Broken-Access-Control",
    "PY-ACCESS-001": "A01:2021-Broken-Access-Control",
    "JS-ACCESS-001": "A01:2021-Broken-Access-Control",
    "PY-CONFIG-002": "A05:2021-Security-Misconfiguration",
    "PY-CONFIG-003": "A05:2021-Security-Misconfiguration",
    "JS-CONFIG-002": "A05:2021-Security-Misconfiguration",
    "PY-CRYPTO-003": "A02:2021-Cryptographic-Failures",
    "PY-DESIGN-002": "A04:2021-Insecure-Design",
    "JS-DESIGN-002": "A04:2021-Insecure-Design",
    "PY-INJECT-001": "A03:2021-Injection",
    "JS-INJECT-001": "A03:2021-Injection",
}


def owasp_2021_ref(rule_id: str) -> str:
    return OWASP_2021_BY_RULE.get(rule_id, "N/A")
