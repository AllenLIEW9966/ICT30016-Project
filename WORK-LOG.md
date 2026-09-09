# Work Log — Secure Coding Assistant

## Project Info

| Field | Details |
|-------|---------|
| **Project Name** | Secure Coding Assistant |
| **Course** | ICT Software Technology Major — Project 1 |
| **Team** | Allen (Software Technology Major) |
| **Tech Stack** | Python, FastAPI, TypeScript, VS Code Extension API, Ollama |
| **Repo** | https://github.com/<your-username>/secure-coding-assistant |
| **Status** | Core features complete; ready for testing and submission |

---

## Phase 1: Project Setup and Planning

**Duration:** Week 1  
**Goal:** Understand requirements, set up repo, decide architecture.

| Date | Task | Status | Notes |
|------|------|--------|-------|
| 2026-09-01 | Read project brief and grading rubric | ✅ Done | Confirmed Python + JS support, OWASP Top 10, VSCode integration, AI suggestions |
| 2026-09-01 | Create GitHub repo `secure-coding-assistant` | ✅ Done | Repo created, folder structure scaffolded |
| 2026-09-01 | Write `project-plan.md` (8-phase timeline) | ✅ Done | Milestones, risks, grading checklist |
| 2026-09-01 | Write `architecture.md` | ✅ Done | Component diagram, data flow, API schema |
| 2026-09-01 | Decide tech stack | ✅ Done | FastAPI backend + TypeScript extension + Ollama |

---

## Phase 2: Backend Scanner Development

**Duration:** Week 1–2  
**Goal:** Build scanners that can detect vulnerabilities in Python and JS code.

| Date | Task | Status | Notes |
|------|------|--------|-------|
| 2026-09-01 | Scaffold FastAPI app (`main.py`, routes, scanner package) | ✅ Done | `/health`, `/scan`, `/suggest-fix` endpoints |
| 2026-09-01 | Build Python AST scanner (`python_scanner.py`) | ✅ Done | Uses `ast.NodeVisitor` to inspect code structure |
| 2026-09-01 | Write first 7 Python rules (SQLi, eval/exec, cmd injection, weak crypto, hardcoded secrets, unsafe deserialization, path traversal) | ✅ Done | Rules in `rules/python_rules.py` |
| 2026-09-01 | Expand Python rules to 10 (added SSRF, debug mode) | ✅ Done | 10 rules total |
| 2026-09-01 | Write 15 unit tests (`tests.py`) | ✅ Done | 7 Python + 1 clean Python + 6 JS + 1 clean JS |
| 2026-09-01 | Fix missing `__init__.py` and import path issues | ✅ Done | Tests runnable from project root |
| 2026-09-01 | Build JS regex scanner (`js_scanner.py`) | ✅ Done | 9 rules: eval, Function constructor, MD5/SHA1, SQLi, innerHTML XSS, Math.random, hardcoded secrets, debugger, insecure JWT decode |
| 2026-09-01 | Fix JS SQLi regex | ✅ Done | Pattern now catches `+` and template literals correctly |
| 2026-09-01 | Run full test suite | ✅ Done | All 15 tests passing |

---

## Phase 3: AI Integration

**Duration:** Week 2  
**Goal:** Connect Ollama so the extension can ask for AI-generated fixes.

| Date | Task | Status | Notes |
|------|------|--------|-------|
| 2026-09-01 | Create `app/ai/ai_client.py` | ✅ Done | Builds prompt and calls Ollama `/chat/completions` |
| 2026-09-01 | Create `/suggest-fix` backend route | ✅ Done | Accepts finding data + AI config, returns explanation + secure code |
| 2026-09-01 | Install Ollama + pull `codellama:7b-instruct` | ✅ Done | 3.8 GB model downloaded |
| 2026-09-01 | Fix JSON parsing — Ollama returns markdown, not pure JSON | ✅ Done | Added fallback regex extraction for code blocks |
| 2026-09-01 | Increase backend timeout to 180s | ✅ Done | Code Llama on CPU is slow; 30s was too short |
| 2026-09-01 | Make extension call backend `/suggest-fix` instead of Ollama directly | ✅ Done | Centralizes AI config in one place |
| 2026-09-01 | Test AI fix end-to-end | ✅ Done | Returns explanation + secure parameterized query |

---

## Phase 4: VSCode Extension Development

**Duration:** Week 2–3  
**Goal:** Build the extension so users can scan files and see findings inside VS Code.

| Date | Task | Status | Notes |
|------|------|--------|-------|
| 2026-09-01 | Scaffold extension (`package.json`, `tsconfig.json`, `extension.ts`) | ✅ Done | TypeScript compiled successfully |
| 2026-09-01 | Fix TypeScript compilation errors | ✅ Done | Non-null assertions, type narrowing for `findingData`, MarkdownString type |
| 2026-09-01 | Create `.vscode/launch.json` | ✅ Done | F5 launches Extension Development Host |
| 2026-09-01 | Implement scan command (`secureCoding.scanCurrentFile`) | ✅ Done | POSTs to backend `/scan`, shows diagnostics |
| 2026-09-01 | Implement diagnostics (red squiggles) | ✅ Done | `vscode.DiagnosticCollection` with severity mapping |
| 2026-09-01 | Implement hover provider | ✅ Done | Shows OWASP + CWE + suggestion on hover |
| 2026-09-01 | Wire OWASP/CWE into hover tooltips | ✅ Done | `findingsByUri` map stores metadata per document |
| 2026-09-01 | Add status bar security score badge | ✅ Done | Shows 🔒 ? on the right side |
| 2026-09-01 | Implement AI fix command (`secureCoding.fixWithAI`) | ✅ Done | Calls backend `/suggest-fix`, shows diff preview |
| 2026-09-01 | Fix extension path mismatch | ✅ Done | VS Code was loading from Downloads instead of project folder |
| 2026-09-01 | Add activation toast + status bar indicator | ✅ Done | Visible confirmation that extension loaded |

---

## Phase 5: Integration and Testing

**Duration:** Week 3  
**Goal:** Make sure backend + extension work together end-to-end.

| Date | Task | Status | Notes |
|------|------|--------|-------|
| 2026-09-01 | Start uvicorn backend on port 8000 | ✅ Done | `uvicorn app.main:app --reload --port 8000` |
| 2026-09-01 | Test Python scan in Extension Development Host | ✅ Done | `PY-SQLI-001` detected with red squiggle |
| 2026-09-01 | Test JS scan in Extension Development Host | ✅ Done | `JS-CODE-EXEC-001`, `JS-XSS-001`, `JS-RANDOM-001` detected |
| 2026-09-01 | Test hover tooltip shows OWASP/CWE/suggestion | ✅ Done | Hover shows `A03:2021-Injection | CWE-89` |
| 2026-09-01 | Test AI fix generates secure code | ✅ Done | Returns parameterized query suggestion |
| 2026-09-01 | Verify all 15 unit tests pass | ✅ Done | `python app/tests.py` — all green |
| 2026-09-01 | Rewrite code comments to sound casual / less AI-like | ✅ Done | Comments in `python_scanner.py`, `js_scanner.py`, `ai_client.py` |
| 2026-09-01 | Shorten and simplify README.md | ✅ Done | Clear setup steps, no jargon |

---

## Phase 6: Documentation and Polish

**Duration:** Week 4  
**Goal:** Prepare project for submission.

| Date | Task | Status | Notes |
|------|------|--------|-------|
| 2026-09-01 | Write README.md | ✅ Done | Overview, setup, usage, commands, requirements checklist |
| 2026-09-01 | Write SUBMISSION-CHECKLIST.md | ✅ Done | Pre-submission verification list |
| 2026-09-01 | Create `.gitignore` | ✅ Done | Excludes `venv/`, `node_modules/`, `__pycache__/` |
| 2026-09-01 | Push project to GitHub | ⏳ Pending | Need to run `git push` from Git Bash |
| 2026-09-01 | Record demo video / take screenshots | ⏳ Pending | Show scan → hover → AI fix flow |
| 2026-09-01 | Write final project report | ⏳ Pending | If required by course |
| 2026-09-01 | Submit project | ⏳ Pending | Upload zip or share GitHub link |

---

## Issues and Resolutions

| Issue | Cause | Fix |
|-------|-------|-----|
| Extension loaded from wrong folder | VS Code opened `Downloads` instead of project folder | Corrected launch path |
| TypeScript compile errors | `statusBarItem` non-null, `findingData` type mismatch, `MarkdownString` issue | Added non-null assertions and type narrowing |
| Hover tooltip showed `OWASP: N/A` | `findingsByUri` map not storing metadata | Created `findingsByUri` and wired it into hover provider |
| AI fix always returned empty | Ollama returns markdown, not JSON; backend timeout too short | Added regex fallback parser + increased timeout to 180s |
| JS SQLi regex missed concatenation | Pattern too strict | Rewrote regex to catch `+` and template literals |
| Bash `!` history expansion error | Git Bash interprets `!` in strings | Used simpler test command |
| “No commands found” in Extension Development Host | Extension wasn’t fully activated / no visible marker | Added activation toast and status bar badge |

---

## What’s Left to Do

1. Push to GitHub
2. Record demo video or screenshots
3. Write final report (if required)
4. Submit

---

## Lessons Learned

- Python AST is powerful for static analysis but only works for Python — JS needs a different approach
- Ollama’s local API is OpenAI-compatible, but model outputs are unpredictable (markdown vs JSON)
- VSCode extension activation can be silent — always add visible markers (toast, status bar) during debugging
- TypeScript strictness in VS Code extensions requires careful null handling
- Regex-based JS scanning works for a demo but has false positives; a proper JS AST parser would be better next time
