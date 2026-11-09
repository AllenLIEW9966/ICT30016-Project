# CodeShield AI — Secure Coding Assistant

CodeShield AI is a VS Code prototype that scans Python and JavaScript documents for selected security patterns, explains findings with CWE and OWASP references, and offers rule-based or AI-assisted fixes.

## Current coverage and limits

- Automatically scans Python and JavaScript files in the workspace after the backend starts, including unopened files. It refreshes findings when supported files are created, changed, or deleted, and scans the active file as it is opened, edited, or saved.
- Workspace scans are bounded to 2,000 files, skip files larger than 512 KiB, and exclude common generated or dependency folders such as `.git`, `node_modules`, `venv`, `dist`, and `build`. Use **Secure Coding: Scan Python and JavaScript Workspace** to run a manual scan.
- Python analysis uses the Python AST. JavaScript uses a Babel AST sidecar when available and falls back to pattern scanning if the sidecar cannot start.
- Rules cover selected issues such as injection, unsafe command execution, XSS sinks, weak cryptography, hardcoded credentials, path traversal, SSRF, unsafe deserialization, and insecure JWT handling. This is not comprehensive SAST and a clean scan does not prove a project is secure.
- Workspace context is collected locally to help an explicitly requested AI fix. It does not create diagnostics. Related files are selected by simple import/path/configuration relevance and bounded before use; it is not a semantic review of the whole repository.
- Quick Fix and Fix All use deterministic, context-checked templates where available. AI Fix asks the configured model for a focused patch, validates syntax and scanner findings, and asks before applying. Models can still fail or propose incomplete fixes; review and test every change.

## AI providers and privacy

Ollama is the default local provider. The extension also offers Groq, Gemini, OpenRouter, and a custom OpenAI-compatible endpoint. Cloud providers require the user's API key and model access; free tiers, quotas, model IDs, and data terms can change. Cloud API keys are stored in VS Code SecretStorage.

Static scanning and the workspace context cache run locally. A cloud AI fix sends the selected code and current-file context to the chosen provider. Related workspace files are sent only after a separate per-fix prompt; common credential assignments, private-key blocks, and URL credentials are redacted before prompt construction. Redaction is best-effort and cannot guarantee detection of every secret. Choose **Use Current File Only** or cancel if the project contains sensitive code. Review provider data-use terms.

## Download and install a VSIX

The repository builds platform-specific VSIX files through GitHub Actions. To download one:

1. Open the repository's **Actions** tab and select the latest successful **Build Windows VSIX** or **Build macOS VSIX** run.
2. At the bottom of that run's summary page, download the artifact for your platform:
   - `secure-coding-assistant-win32-x64` — Windows x64
   - `secure-coding-assistant-darwin-x64` — macOS Intel
   - `secure-coding-assistant-darwin-arm64` — macOS Apple Silicon
3. Extract the downloaded ZIP, then in VS Code open **Extensions** → **…** → **Install from VSIX…** and select the `.vsix` file.

Each artifact is available only after its packaging job succeeds. These are CI build artifacts, not permanent releases; if a job fails, inspect its log and rerun it after the issue is fixed. Restart VS Code if prompted after installation.

For development, install the extension dependencies and launch the Extension Development Host:

```powershell
cd extension
npm install
npm run compile
```

Press **F5** in VS Code to launch the development host. The extension starts its bundled backend when installed as a VSIX.

## Commands

- **Secure Coding: Scan Current File** — run a scan on the active supported document.
- **Secure Coding: Scan Python and JavaScript Workspace** — scan supported workspace files and show findings in the Problems panel.
- **Secure Coding: Fix with AI** — request an AI-assisted fix for a selected finding.
- **Secure Coding: Fix All Vulnerabilities in File** — apply available deterministic fixes in the active file.
- **Secure Coding: Show Current File Findings** — show the active file's finding count in the status bar. This is not a workspace security grade.
- **Secure Coding: Configure AI Provider** — select a local or cloud provider and configure its model/key.

The Ollama model picker reads installed model tags from the running Ollama service whenever it opens, so newly downloaded models appear automatically. Prepared Qwen 1.5B and CodeLlama 7B choices remain available to download if they are not installed.

## Checks

Run the backend scanner tests:

```powershell
cd backend
python app/tests.py
```

Run the offline scanner evaluation corpus (does not call an AI provider):

```powershell
python app/evaluate.py
```

Compile the extension:

```powershell
cd extension
npm run compile
```

The synthetic corpus measures only the documented cases. It does not establish real-world recall, model quality, or enterprise readiness. Cloud privacy requires a separate packet-capture check before release.

## Packaging note

The manifest publisher value must match the owner's actual Visual Studio Marketplace publisher account before marketplace publishing. A publisher account was not available to configure during this review; local VSIX installation remains available.
