# CodeShield AI release readiness

Review date: 2026-11-12
Source version: 0.1.48

## Status

**Development and supervised evaluation build; not yet production-ready.** The product is a local VS Code extension with selected Python and JavaScript security rules and optional AI-assisted fixes. It is not comprehensive SAST, and a passing scanner result does not establish that a workspace is secure. Marketplace publishing is out of scope.

## Hardening completed in this pass

- Limited HTTP request bodies to 1 MiB before parsing and bounded scan source, file names, suggestion fields, current-file source, and related project context.
- Moved synchronous scanner work off the FastAPI event loop so scanning does not block health and provider requests.
- Removed rejected request values from validation error responses; these may contain source code or credentials.
- Replaced raw provider exception details in API responses with actionable, non-secret error summaries and appropriate gateway/timeout status codes.
- Pinned direct backend runtime dependencies and PyInstaller build version for repeatable packaging.
- Corrected backend health/OpenAPI version to match extension version 0.1.48.
- Changed post-fix verification to check the remaining finding count for the rule rather than only the old line number.
- Added semantic guards against replacing dynamic command inputs with hard-coded values, accepting weak or incomplete password-hash candidates, changing pickle formats to JSON without producer/consumer evidence, or retaining sensitive values in logging calls. Added safe focused fallbacks for a recognized ping helper and an async HTTP catch block.

## Required before calling this production-ready

1. **Automated quality gates:** Run the complete Python scanner/context suite and evaluation corpus, TypeScript compilation, package validation, and dependency/security audits in CI. Add tests for the new request-size, redaction, provider-error, and AI patch-validation behavior.
2. **Security review:** Review local backend exposure, CORS/origin behavior, data redaction limits, prompt injection defenses, and rule/fix safety. Perform an independent threat model and penetration test before use with sensitive repositories.
3. **AI fix correctness:** Test each supported provider/model against a representative, versioned Python and JavaScript corpus. Check syntax, scanner findings, dependencies, behavior, authorization assumptions, and migrations. Models can produce syntactically valid but semantically unsafe code; every patch requires review and project tests.
4. **Supported operating systems:** Install and smoke-test the packaged Windows x64, macOS Intel, and macOS Apple Silicon builds on clean machines and on the minimum supported VS Code version. Linux packaging is not currently offered.
5. **Privacy evidence:** Packet-capture local Ollama and cloud-provider sessions separately. Confirm only expected destinations and record what code/context is transmitted for each provider.
6. **Reliability and performance:** Test large workspaces, malformed files, repeated edits, concurrent VS Code windows, provider outages, quotas, timeouts, cancellation, and memory/CPU use.
7. **Dependency operations:** Review and update pinned dependencies regularly; scan Python and npm dependencies for known vulnerabilities and keep lockfiles/build inputs reproducible.
8. **User-facing policy:** Keep scanner coverage, provider data use, cloud transfer, limits, and required human review clear in the README and UI.

## Packaging and repository notes

- The VS Code extension manifest still contains the `your-name` publisher placeholder. Local VSIX installs work; Marketplace publishing requires the owner's real publisher identity and remains intentionally untouched.
- The supported packaged targets are Windows x64 and macOS Intel/Apple Silicon. Artifact availability depends on a successful GitHub Actions run.
- Keep generated binaries and VSIX files out of Git unless a deliberate release policy changes.
- No publishing operation was performed as part of this review.

## Verification record for this pass

- Source changes were reviewed and are intended for version 0.1.48.
- Python scanner suite: all 51 checks passed.
- Synthetic evaluation corpus: 37 cases passed (25/25 expected detections and all 12 negative probes); measured static scan latency was p50 0.5 ms, p95 2.7 ms, max 3.9 ms. This small curated corpus is not evidence of real-world completeness.
- TypeScript compilation passed. Windows PyInstaller backend packaging and Windows x64 VSIX packaging completed; the VSIX includes the rebuilt backend executable. Package version and bundled executable hash were checked.
- Local Ollama smoke check used the same synthetic `pickle.loads(payload)` example with the installed Qwen 2.5 Coder 7B, Qwen 2.5 Coder 1.5B, CodeLlama 7B, and Qwen2.5-VL 3B models. The two smaller Qwen models declined, although the 1.5B model gave an incorrect explanation. CodeLlama and Qwen2.5-VL proposed JSON migration without producer/consumer evidence; those proposals are unsafe and must be rejected by the extension's semantic guard. These were single prompt smoke checks, not broad model evaluations or VS Code UI end-to-end tests.
- Cloud provider calls were not run because no cloud API credentials were available in the test environment. The packaged extension launch, macOS builds, OS clean-install checks, and packet captures were also not run.
- Do not interpret these checks as proof of production readiness.
