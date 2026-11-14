import asyncio
import json
from pathlib import Path

import httpx

from app.scanner.dependency_scanner import advisory_coordinates, advisory_findings, scan
from app.scanner.osv_client import lookup


def test_osv_enrichment():
    asyncio.run(_exercise())


async def _exercise():
    fixtures = Path(__file__).resolve().parents[2] / "test/fixtures/dependency-advisories"
    code = "\n".join((fixtures / name).read_text() for name in (
        "requirements-vulnerable.txt", "requirements-safe.txt"))
    seen = []
    cache = {}

    def respond(request):
        seen.append(request.url.path)
        if request.url.path.endswith("querybatch"):
            queries = json.loads(request.content)["queries"]
            assert queries[0] == {"package": {"ecosystem": "PyPI", "name": "django"}, "version": "3.2.1"}
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "MOCK-1"}]}, {}]})
        return httpx.Response(200, json={"aliases": ["CVE-2099-1234"]})

    async def query(keys):
        return await lookup(keys, httpx.MockTransport(respond), cache)

    for _ in range(2):
        findings = await advisory_findings(code, "requirements.txt", lookup=query)
        assert len(findings) == 1
        f = findings[0]
        assert f["rule_id"] == "CS-A03-OSV" and f["line"] == 2
        assert "CVE-2099-1234" in f["message"] and "A06:2021" in f["owasp_2021_ref"]
    assert len(seen) == 2

    for timeout in (False, True):
        def fail(request):
            if timeout:
                raise httpx.ReadTimeout("simulated", request=request)
            return httpx.Response(500)

        async def unavailable(keys):
            return await lookup(keys, httpx.MockTransport(fail), {})

        mixed = code + "\nunpinned"
        assert await advisory_findings(mixed, "requirements.txt", lookup=unavailable) == []
        assert any(f["rule_id"] == "DEP-UNPINNED-001" for f in scan(mixed, "requirements.txt"))

    manifest = '{"dependencies": {"example": "^1.0.0"}}'
    lock = '{"packages":{"":{"dependencies":{"example":"^1.0.0"}},"node_modules/example":{"version":"1.2.0"}}}'
    assert advisory_coordinates(manifest, "package.json", lock) == [(("npm", "example", "1.2.0"), 1)]
    assert advisory_coordinates(manifest, "package.json") == []
    pyproject = '[project]\ndependencies = ["example>=2"]'
    assert advisory_coordinates(pyproject, "pyproject.toml", "example==2.1") == [(("PyPI", "example", "2.1"), 2)]
    assert advisory_coordinates(pyproject, "pyproject.toml", "example==1.1") == []
