# CodeShield AI — Secure Coding Assistant

CodeShield AI is a VS Code prototype that scans Python and JavaScript documents for selected security patterns, explains findings with CWE and OWASP references, and offers rule-based or AI-assisted fixes.

## Current coverage and limits

- Automatically scans Python and JavaScript files plus common dependency manifests (`requirements*.txt`, `pyproject.toml`, and `package.json`) in the workspace after the backend starts, including unopened files. It refreshes findings when supported files are created, changed, or deleted, and scans the active file as it is opened, edited, or saved.
- Workspace scans are bounded to 2,000 files, skip files larger than 512 KiB, and exclude common generated or dependency folders such as `.git`, `node_modules`, `venv`, `dist`, and `build`. Use **Secure Coding: Scan Python and JavaScript Workspace** to run a manual scan.
- Python analysis uses the Python AST. JavaScript uses a Babel AST sidecar when available and falls back to pattern scanning if the sidecar cannot start.
- Findings show their selected OWASP Top 10:2025 category and a rule-level OWASP Top 10:2021 crosswalk when a direct mapping applies. A10:2025 is new and has no 2021 category counterpart, so those findings show `N/A` for 2021. The crosswalk does not mean the scanner covers either standard comprehensively. A03 checks common dependency manifests for unbounded package versions and mutable external sources. A06 checks a narrow, high-risk pattern where request data is assigned directly to privilege fields. A08 includes a JavaScript `unserialize()` pattern for unsafe object deserialization; it does not flag ordinary `JSON.parse()`. These checks are partial: they do not query vulnerability databases, audit build pipelines, model business workflows, or prove authorization is correct. Other category checks are pattern-based, not comprehensive coverage. A clean scan does not prove a project is secure.
- Workspace context is collected locally to help an explicitly requested AI fix. It does not create diagnostics. Related files are selected by simple import/path/configuration relevance and bounded before use; it is not a semantic review of the whole repository.
- Quick Fix and Fix All use deterministic, context-checked templates where available; A03 dependency pins are only applied when an existing lock file supplies an exact version or commit. AI Fix asks the configured model for a focused Python or JavaScript patch, validates syntax and scanner findings, and asks before applying. A06 fixes must follow authorization policy visible in context; the model should decline when it is unclear. Models can still fail or propose incomplete fixes; review and test every change.

## AI providers and privacy

Ollama is the default local provider. The extension also offers Groq, Gemini, OpenRouter, and a custom OpenAI-compatible endpoint. Cloud providers require the user's API key and model access; free tiers, quotas, model IDs, and data terms can change. Cloud API keys are stored in VS Code SecretStorage.

Static scanning and the workspace context cache run locally. A cloud AI fix sends the selected code and current-file context to the chosen provider. Related workspace files are sent only after a separate per-fix prompt; common credential assignments, private-key blocks, and URL credentials are redacted before prompt construction. Redaction is best-effort and cannot guarantee detection of every secret. Choose **Use Current File Only** or cancel if the project contains sensitive code. Review provider data-use terms.

## Download and install a VSIX

The repository includes the current Windows x64 package at [`secure-coding-assistant-0.1.57.vsix`](secure-coding-assistant-0.1.57.vsix). Download it from the repository's **Code** tab, then in VS Code open **Extensions** → **…** → **Install from VSIX…** and select the file.

GitHub Actions also builds platform-specific packages. To download a CI build:

1. Open the repository's **Actions** tab.
2. In the left **Workflows** list, select **Build Windows VSIX** or **Build macOS VSIX** for your computer.
3. In the run list, open the newest run with a green check mark. The run title may be a commit or pull request title rather than the workflow name.
4. On the run summary page, scroll to **Artifacts** and download the matching item:

   | Artifact | Platform |
   | --- | --- |
   | `secure-coding-assistant-win32-x64` | Windows x64 |
   | `secure-coding-assistant-darwin-x64` | macOS Intel |
   | `secure-coding-assistant-darwin-arm64` | macOS Apple Silicon |

5. Extract the downloaded ZIP. In VS Code, open **Extensions** → **…** → **Install from VSIX…**, then select the `.vsix` file.

An artifact appears only when its packaging job succeeds. If the run failed or there is no matching artifact, choose another successful run or wait for a successful build. Workflow artifacts are temporary CI downloads and may expire; they are not permanent GitHub Releases or VS Code Marketplace listings. Restart VS Code if prompted after installation. The tracked Windows package is refreshed with source releases; the macOS packages are available from successful Actions runs.

For development, install the extension dependencies and launch the Extension Development Host:

```powershell
cd extension
npm ci
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

## IDE plugin ZIP prototype

A separate early IDE plugin project is in [`zip/`](zip/README.md). Its first milestone scans the active Python or JavaScript file through the existing local backend and lists findings in a CodeShield tool window. The **Build CodeShield ZIP** GitHub Actions workflow packages it as a downloadable ZIP. It currently requires the backend to be started separately and does not yet provide AI fixes, automatic backend startup, or workspace-wide live scanning. See its README for setup and download instructions.

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
