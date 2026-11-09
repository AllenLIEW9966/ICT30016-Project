# CodeShield AI release readiness

Review date: 2026-11-10

## Current result

**Suitable for continued local demonstration and testing; not ready for Marketplace publication.** Marketplace publishing and publisher identity were intentionally left unchanged.

## Completed in this review

- Fixed the backend startup race for multiple VS Code windows. If a backend process loses the bind race, the extension now checks whether the competing local service becomes healthy before marking CodeShield offline. A mocked runtime check passed for the port-conflict branch; a real two-window run with the rebuilt package remains pending.
- Normalized `localhost` backend URLs to `127.0.0.1`, matching the bundled server's IPv4 loopback binding.
- Corrected both READMEs to describe automatic bounded workspace scans, file-change refreshes, exclusions, and the workspace scan command.
- Added the repository URL from the configured Git remote and aligned FastAPI's advertised version (`0.1.17`) with `/health` (`0.1.17`).
- All 36 backend scanner/context tests passed in this review.
- The backend virtual environment passes `pip check` with no broken requirements.
- TypeScript compilation passed, and a Windows x64 VSIX was packaged as `extension/secure-coding-assistant-win32-x64-0.1.36.vsix` (17.6 MB). The packager no longer warns about missing repository metadata.
- The previous workspace runtime check verified unopened-file findings and refresh after an edit.
- A targeted scan of extension/backend source for common live-key formats found no matches. This is not a complete secret audit.

## Remaining release blockers and checks

1. **Marketplace identity:** `extension/package.json` still uses the `your-name` publisher placeholder. Set it to the actual Marketplace publisher only when publication is authorized.
2. **Platform support:** The packaged extension contains only `server/codeshield-backend.exe`. Packaged macOS and Linux installations are not ready.
3. **Clean installation and concurrency:** The VSIX is built for Windows x64. Install it in a clean VS Code profile and verify startup in one and two real VS Code windows; only the race-handling branch has been mocked so far.
4. **Cloud privacy evidence:** `backend/PRIVACY-REPORT.md` says packet-capture verification is still outstanding. Capture and record local Ollama and cloud-provider traffic separately.
5. **Provider integration:** Test each supported provider with working keys, quotas, current model IDs, errors, and a real fix flow. Cloud free tiers and model availability can change.
6. **Dependency completeness and clean-machine setup:** Verify backend requirements and installation on a clean machine.
7. **Security coverage claims:** The scanner covers selected Python and JavaScript patterns; it is not comprehensive SAST or an enterprise security certification. Keep this limitation clear in product and project claims.
8. **Marketplace publisher:** `publisher` remains `your-name`; replace it only when the correct Marketplace account is known and publishing is authorized.

## Packaging notes

- The latest local package is `extension/secure-coding-assistant-win32-x64-0.1.36.vsix`.
- The backend executable in `extension/server/` matches `backend/dist/codeshield-backend.exe` by SHA-256 at review time.
- No Marketplace publishing, publisher edits, or credentials were changed.
