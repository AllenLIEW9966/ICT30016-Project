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
- [x] Workspace startup scan reports findings in unopened Python/JavaScript files
- [x] Workspace file changes refresh or clear diagnostics
- [ ] Verify simultaneous VS Code windows with the rebuilt 0.1.35 VSIX

## Tests
- [x] 36 backend scanner/context tests passing after the latest coverage additions
- [x] Run: `cd backend && python app/tests.py`

## Before Submission
- [ ] Remove any hardcoded API keys/secrets
- [ ] Verify `backend/requirements.txt` is complete
- [x] Add the repository URL to the extension manifest
- [ ] Replace the manifest publisher placeholder with the actual Marketplace publisher account before publishing
- [x] Verify `extension/package.json` name, version, VS Code engine, and repository metadata
- [ ] Test on a clean machine if possible
- [ ] Test the current packaged VSIX end-to-end with the prepared Ollama and cloud providers
- [ ] Install 0.1.36 in a clean VS Code profile and verify one-window and two-window startup
- [ ] Capture a packet trace for local Ollama and cloud AI modes
- [ ] Record demo video or take screenshots for report
- [ ] Write final report/project documentation if required
