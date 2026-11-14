from unittest.mock import patch

from fastapi.testclient import TestClient
from app.main import app


def test_strict_patch_syntax():
    from app.scanner.js_ast_bridge import scan_with_ast
    with patch("app.scanner.js_ast_bridge._start_worker", return_value=None):
        fallback = scan_with_ast("return 1;", "patch.js", True)
        assert fallback is not None and any(f["rule_id"] == "PARSE-ERROR" for f in fallback)
    with TestClient(app) as client:
        for language, invalid, valid in (
            ("python", "def broken(:\n pass", "def valid():\n return 1"),
            ("javascript", "const const x = 1;", "const x = 1;"),
            ("python", "return 1", "x = 1"),
            ("javascript", "return 1;", "function valid() { return 1; }"),
        ):
            for code, fails in ((invalid, True), (valid, False)):
                response = client.post("/scan", json={"language": language, "code": code,
                    "filename": "patch.py" if language == "python" else "patch.js", "require_ast": True})
                assert response.status_code == 200, response.text
                body = response.json()
                assert body["ast_validated"] is True
                assert any(f["rule_id"] == "PARSE-ERROR" for f in body["findings"]) == fails
        with patch("app.scanner.js_ast_bridge.scan_with_ast", return_value=None):
            response = client.post("/scan", json={"language": "javascript", "code": "const x=1", "require_ast": True})
            assert response.status_code == 503
            # Ordinary security scanning retains its offline pattern fallback.
            response = client.post("/scan", json={"language": "javascript", "code": "eval(input)"})
            assert response.status_code == 200
            assert response.json()["ast_validated"] is False
