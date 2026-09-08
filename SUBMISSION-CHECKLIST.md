# Submission Checklist

## Core Deliverables
- [x] Python FastAPI backend at `backend/`
- [x] TypeScript VSCode extension at `extension/`
- [x] README.md with setup and usage instructions
- [x] requirements.txt with backend dependencies

## Functionality Verification
- [x] Python scanner detects SQL injection (`PY-SQLI-001`)
- [x] JavaScript scanner detects eval, innerHTML XSS, weak random
- [x] Extension shows red squiggles for vulnerabilities
- [x] Hover tooltip shows OWASP + CWE + suggestion
- [x] Status bar shows security score badge
- [x] AI fix generates explanation + secure code via Ollama

## Tests
- [x] 15 tests passing (7 Python + 1 clean Python + 6 JS + 1 clean JS)
- [x] Run: `cd backend && python app/tests.py`

## Before Submission
- [ ] Remove any hardcoded API keys/secrets
- [ ] Verify `backend/requirements.txt` is complete
- [ ] Verify `extension/package.json` has correct name/version/engines
- [ ] Test on a clean machine if possible
- [ ] Record demo video or take screenshots for report
- [ ] Write final report/project documentation if required
