# CodeShield AI — Agent Working Guide

Read this guide before working on the repository. Task prompts describe the change requested. For agents with a different instruction entry point, reference this file from that entry point or keep the instructions in sync.

## 1. Product contract

CodeShield AI is a VS Code prototype for Python and JavaScript. Describe its OWASP coverage as selected patterns or partial checks. Ask for clarification if a task requires complete OWASP coverage or a guarantee of zero false positives.

Preserve automatic local scanning on edits, workspace scanning of up to 2,000 files with a 512 KiB file limit, and diagnostics with severity, CWE, OWASP label, risk explanation and remediation hint. Quick Fix and Fix All handle supported deterministic edits. A developer can request AI Fix using Ollama or a configured cloud provider and choose whether to include related project context. Check candidate syntax and residual findings before offering to apply a change.

Workspace scans analyze files individually. The context cache supplies selected files for AI fixes. Static rules can miss equivalent patterns or flag safe code. Access checks cannot establish the application's authorization policy. Manifest rules run offline. Optional OSV enrichment checks identified dependency versions asynchronously. A successful rescan cannot establish behavioral correctness. The recorded evaluation covers 25 expected detections and 12 negative probes.

## 2. Where changes belong

| Path | Responsibility |
|---|---|
| extension/src/extension.ts | VS Code commands, diagnostics, hover, code actions, context selection and patch review |
| extension/src/backendManager.ts | Local backend lifecycle |
| backend/app/routes/scan.py and suggest.py | Scan and suggestion API entry points |
| backend/app/scanner/python_scanner.py and rules/python_rules.py | Python AST visitor and rule registration |
| backend/app/scanner/js_scanner.py, js_ast_bridge.py and backend/js-ast/ | JavaScript pattern rules, AST bridge and Node analyzer |
| backend/app/scanner/dependency_scanner.py | Dependency manifest checks |
| backend/app/scanner/semantic.py and owasp_mapping.py | Semantic validation and rule-level 2021 crosswalk |
| backend/app/ai/ | Provider requests, context and fix templates |
| backend/app/tests.py, eval_corpus.py and evaluate.py | Regression checks, corpus and evaluation runner |
| zip/ | Separate IDE ZIP prototype |

Extend the relevant scanner and its existing dispatch path. Reuse the rule metadata for diagnostic labels. Keep edition-specific mappings explicit. Avoid introducing a parallel TypeScript scanner tree.

## 3. Build and verification

| Working directory | Command | Purpose |
|---|---|---|
| extension | npm run compile | Build the TypeScript extension |
| backend | python app/tests.py | Run registered backend regression checks in the project Python environment |
| backend | python app/evaluate.py | Evaluate the current synthetic corpus |

The extension manifest defines compile, watch, package and vscode:prepublish scripts. It has no lint, test:unit, test:integration or evaluate npm script. For VS Code API changes, exercise the affected command in an Extension Development Host and record the result until an automated integration suite is available.

## 4. Engineering conventions

- Preserve existing identifiers such as PY-SQLI-001, JS-XSS-001 and DEP-UNPINNED-001. New rules use CS-Axx-<slug> with the two-digit OWASP category (including A10). Use XFILE or EXP suffixes for separately configurable experimental checks. Preserve superseded IDs through the current major version.
- Each new or changed rule needs a labeled vulnerable fixture and a safe counterpart, exercised by the regression runner. Put new fixture files under test/fixtures/<vulnerability-type>/. Include expected result, OWASP edition/category, CWE when known and provenance when applicable.
- Keep deterministic fixes specific to the code and evidence. A password hash migration, allowed CORS origin or package pin can require project-specific information. Never invent that information. When SSRF policy or authorization is unclear, offer guidance or a developer-reviewed snippet. Withhold automatic replacement.
- Keep per-file analysis local and synchronous with a target of under 200 ms per file. Run external enrichment separately with timeouts and graceful fallback. Preserve the existing local backend transport and per-fix cloud context consent.
- Use built-in fetch for new Node HTTP calls. Extend the existing provider implementation without adding a provider SDK. Preserve engines.vscode. Keep diffs focused and flag unrelated work separately.

## 5. Definition of done

Run the compile and regression commands in section 3. For rule changes check both fixture outcomes. For VS Code API changes verify the editor interaction. Record checks that could not be completed. Preserve rule IDs and use partial-coverage language in user-facing text.

## 6. Priority roadmap

These are future tasks in priority order unless the developer selects another.

1. **A03 dependency advisories.** Add asynchronous OSV querybatch enrichment for resolved npm and PyPI package versions in package.json, requirements.txt and pyproject.toml. Batch up to 1,000 queries and cache by ecosystem, name and version for six hours. Keep existing offline checks available on timeout or server error. Acceptance requires a known affected version with a CVE reference where an alias exists and a mocked HTTP 500 that leaves scanning functional.
2. **A05 one-hop flow.** Summarize parameters that reach SQL sinks. At call sites, match request-derived arguments to those parameter positions across supported relative imports in the same directory or one level away. Skip unresolved, renamed, wildcard and dynamic imports. Use CS-A05-XFILE identifiers. Verify one finding in a two-file fixture and none in the equivalent fixture with a validated integer argument.
3. **Evaluation corpus.** Target at least 30 attributed real-world examples in supported languages and 20 safe counterparts under test/evaluation/. Use small, appropriately licensed excerpts with source URLs. Report per-category and overall precision, recall and F1 in JSON with each false result identified by file and rule. Targets are precision ≥ 0.75 and recall ≥ 0.60. Keep the corpus representative.
4. **Coverage dashboard.** Add a VS Code TreeView for A01–A10 with counts and distinct rule IDs derived from existing diagnostics. Reuse category metadata. Selecting a category should invoke codeshield.filterByOwasp. Verify live updates and filtering without triggering a scan.

## 7. Scope boundaries

Avoid compliance claims, new external calls in the scan loop, full authorization inference, unrelated dependency upgrades and model training. Extract attributed evaluation samples without copying entire third-party projects.

## 8. Handling problems

Report unmet completion criteria and their cause. Clarify conflicts with the product contract. If a mistake recurs twice, add a narrowly scoped constraint here to prevent recurrence.
