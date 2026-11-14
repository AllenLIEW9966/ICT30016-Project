# CodeShield AI — Secure Coding Assistant

CodeShield AI is a VS Code prototype that scans Python and JavaScript documents for selected security patterns, explains findings with CWE and OWASP references, and offers rule-based or AI-assisted fixes.

The current Windows release is **0.1.60**. Start with the [project evaluation report](EVALUATION_REPORT.md) for architecture, selected OWASP checks and verification evidence. The [presentation outline](PRESENTATION_OUTLINE.md) follows the supplied 12-slide deck and includes speaking notes, timing and recording steps.

## Core features

- Automatic local scanning of supported Python and JavaScript documents, including unsaved edits, plus bounded workspace scanning and supported dependency manifests.
- Findings in VS Code with severity, rule ID, CWE, OWASP category, risk explanation and remediation guidance.
- Quick Fix for supported deterministic changes, Fix All for supported changes in the current file, and requested AI Fix with preview, syntax validation and residual scanner checks.
- Local Ollama models or configured Groq, Gemini, OpenRouter and custom OpenAI-compatible providers. Related project context is an optional per-fix choice.
- Optional asynchronous OSV dependency advisories with CVE references where available, six-hour caching and protection against delayed responses overwriting newer scans.

These capabilities cover selected patterns. Developer review and project tests are required to assess a proposed fix.

## Current coverage and limits

- Automatically scans Python and JavaScript files plus common dependency manifests (`requirements*.txt`, `pyproject.toml`, and `package.json`) in the workspace after the backend starts, including unopened files. It refreshes findings when supported files are created, changed, or deleted, and scans the active file as it is opened, edited, or saved.
- Workspace scans are bounded to 2,000 files, skip files larger than 512 KiB, and exclude common generated or dependency folders such as `.git`, `node_modules`, `venv`, `dist`, and `build`. Use **Secure Coding: Scan Workspace Security Findings** to run a manual scan.
- Python analysis uses the Python AST. JavaScript uses a Babel AST sidecar when available and falls back to pattern scanning if the sidecar cannot start.
- Findings show their selected OWASP Top 10:2025 category and a rule-level OWASP Top 10:2021 crosswalk when a direct mapping applies. A10:2025 is new and has no 2021 category counterpart, so those findings show `N/A` for 2021. The crosswalk does not mean the scanner covers either standard comprehensively. A03 checks common dependency manifests for unbounded package versions and mutable external sources. A06 checks a narrow, high-risk pattern where request data is assigned directly to privilege fields. A08 includes a JavaScript `unserialize()` pattern for unsafe object deserialization; it does not flag ordinary `JSON.parse()`. These checks are partial: they do not audit build pipelines, model business workflows, or prove authorization is correct. Other category checks are pattern-based, not comprehensive coverage. A clean scan does not prove a project is secure.
- Additional targeted patterns cover unscoped request-ID SQL lookups (potential IDOR, A01), credentialed wildcard CORS and Flask debug startup (A02), dependency-install hooks that pipe downloaded code to a shell (A03), weak randomness assigned to security-named values (A04), dynamic server-side template sources (A05), request-driven model updates (A06), password comparisons against credential-like constants (A07), imported aliases of unsafe Python deserializers (A08), request data written directly to logs (A09), and broad exception handlers that return success-like empty values (A10). JavaScript includes matching targeted patterns where practical. These are heuristic rules: they can miss equivalent code written differently and may need review for false positives. A01/A07 checks are limited pattern checks, not complete authorization or cross-file data-flow analysis. Workspace scanning still analyzes files independently; the local context cache is for requested AI fixes, not scanner diagnostics.
- Workspace context is collected locally to help an explicitly requested AI fix. It does not create diagnostics. Related files are selected by simple import/path/configuration relevance and bounded before use; it is not a semantic review of the whole repository.
- Quick Fix and Fix All use deterministic, context-checked templates where available; A03 dependency pins are only applied when an existing lock file supplies an exact version or commit. AI Fix asks the configured model for a focused Python or JavaScript patch, validates syntax and scanner findings, and asks before applying. A06 fixes must follow authorization policy visible in context; the model should decline when it is unclear. Models can still fail or propose incomplete fixes; review and test every change.

## AI providers and privacy

For known dependency advisories, enable `secureCoding.osvAdvisories` in VS Code user settings and scan a manifest in a trusted workspace. The local backend sends package names, ecosystems and exact versions to OSV.dev. The extension displays matches as `CS-A03-OSV` with advisory identifiers. It supports direct dependencies in package.json, requirements*.txt and the project.dependencies array in pyproject.toml. For supported ranges it can use a sibling package-lock.json, requirements.lock or constraints.txt. Unresolved ranges are skipped. Successful lookups are cached for six hours. A timeout or unavailable service leaves the offline findings available.

To inspect advisory updates, open **View → Output** and select **CodeShield Workspace Scan**. Entries tagged `CS-A03-OSV` show the file URI, request number, HTTP response, finding count and published diagnostic count. Disabled or untrusted workspace lookups and stale responses are logged too. The **CodeShield** output channel contains backend startup messages.

Ollama is the default local provider. The extension also offers Groq, Gemini, OpenRouter, and a custom OpenAI-compatible endpoint. Cloud providers require the user's API key and model access; free tiers, quotas, model IDs, and data terms can change. Cloud API keys are stored in VS Code SecretStorage.

Static scanning and the workspace context cache run locally. A cloud AI fix sends the selected code and current-file context to the chosen provider. Related workspace files are sent only after a separate per-fix prompt; common credential assignments, private-key blocks, and URL credentials are redacted before prompt construction. Redaction is best-effort and cannot guarantee detection of every secret. Choose **Use Current File Only** or cancel if the project contains sensitive code. Review provider data-use terms.

## Download and install a VSIX

The current source version is **0.1.60**. Download a platform-specific VSIX from a successful GitHub Actions run. Generated installers are ignored by Git and distributed through Actions Artifacts.

GitHub Actions builds each package on its native operating system. To download a CI build, sign in to GitHub and follow these steps:

1. Open the repository's **Actions** tab.
2. In the left **Workflows** list, select **Build Windows VSIX**, **Build macOS VSIX** or **Build Linux VSIX** for your computer.
3. In the run list, open the newest run with a green check mark. The run title may be a commit or pull request title rather than the workflow name.
4. On the run summary page, scroll to **Artifacts** and download the matching item:

   | Artifact | Platform |
   | --- | --- |
   | `secure-coding-assistant-win32-x64` | Windows x64 |
   | `secure-coding-assistant-darwin-x64` | macOS Intel |
   | `secure-coding-assistant-darwin-arm64` | macOS Apple Silicon |
   | `secure-coding-assistant-linux-x64` | Linux x64 |

5. Extract the downloaded ZIP. In VS Code, open **Extensions** → **…** → **Install from VSIX…**, then select the `.vsix` file.

An artifact appears only when its packaging job succeeds. If the run failed or there is no matching artifact, choose another successful run or wait for a successful build. Workflow artifacts are temporary CI downloads and may expire; they are not permanent GitHub Releases or VS Code Marketplace listings. Restart VS Code if prompted after installation. Choose a successful run for the source commit you want to install. All platforms use Actions Artifacts for distribution.

For development, install the extension dependencies and launch the Extension Development Host:

```powershell
cd extension
npm ci
npm run compile
```

Press **F5** in VS Code to launch the development host. The extension starts its bundled backend when installed as a VSIX.

## Build VSIX and backend ZIP artifacts

CI uses Python 3.12, Node.js 22 and PyInstaller 6.22.3. The Windows, macOS and Linux workflows call `.github/workflows/package-platform.yml`. It installs Python and npm dependencies, compiles the extension, runs backend regression and advisory publication tests, then calls `scripts/package_release.py`.

| VSIX target | CI runner | PyInstaller output | Extension server filename |
| --- | --- | --- | --- |
| `win32-x64` | `windows-latest` | `codeshield-backend.exe` | `codeshield-backend.exe` |
| `darwin-x64` | `macos-15-intel` | `codeshield-backend` | `codeshield-backend-macos` |
| `darwin-arm64` | `macos-15` | `codeshield-backend` | `codeshield-backend-macos` |
| `linux-x64` | `ubuntu-22.04` | `codeshield-backend` | `codeshield-backend-linux` |

Runner labels follow the [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners). Native builds and embedded-library distribution follow [PyInstaller's operating modes](https://pyinstaller.org/en/stable/operating-mode.html).

Build on the native OS and architecture for the requested target. The script checks the host before running PyInstaller with `backend/codeshield-backend.spec`, copies the executable into `extension/server/`, and invokes the locally installed `@vscode/vsce` through `npx`. Other platforms' backend binaries are excluded from that VSIX. macOS and Linux executables retain execute permission. Linux builds target glibc-based x64 systems compatible with the build host. Alpine/musl and Linux ARM are outside this build matrix.

On Windows, run the following PowerShell commands from the repository root. Create `backend/env312` with `py -3.12 -m venv backend/env312` if necessary.

```powershell
.\backend\env312\Scripts\python.exe -m pip install -r backend/requirements.txt pyinstaller==6.22.3
npm ci --prefix backend/js-ast
npm ci --prefix extension
npm run compile --prefix extension
Push-Location backend
.\env312\Scripts\python.exe app/tests.py
Pop-Location
node --test extension/test/advisoryUpdate.test.cjs
.\backend\env312\Scripts\python.exe scripts/package_release.py win32-x64
```

On macOS or Linux, run these commands from the repository root with Python 3.12 and Node.js 22 installed. Set `TARGET` to match the host.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r backend/requirements.txt pyinstaller==6.22.3
npm ci --prefix backend/js-ast
npm ci --prefix extension
npm run compile --prefix extension
(cd backend && python app/tests.py)
node --test extension/test/advisoryUpdate.test.cjs
TARGET=darwin-arm64  # darwin-x64 on Intel Mac, linux-x64 on Linux x64
python scripts/package_release.py "$TARGET"
```

For each target, the script writes `dist/<target>/secure-coding-assistant-<target>-0.1.60.vsix` and `dist/<target>/codeshield-backend-<target>.zip`. The backend ZIP contains the original executable name shown above. The existing PyInstaller spec produces one executable with collected Python libraries, native libraries and JavaScript analyzer assets embedded inside it. Required system libraries remain platform prerequisites. The build extracts the ZIP, checks backend startup and `/health` version, then checks the VSIX contains the intended backend and manifest version.

Each workflow uploads two separate artifacts, `secure-coding-assistant-<target>` and `codeshield-backend-<target>`. GitHub wraps downloaded artifacts in a ZIP. Extract that outer ZIP to get the VSIX installer or the backend ZIP. The backend ZIP is a standalone service distribution. The separate `codeshield-zip` artifact from **Build CodeShield ZIP** is the IDE plugin prototype.

For a standalone backend, extract its ZIP and run `codeshield-backend.exe --host 127.0.0.1 --port 8000` on Windows, or `./codeshield-backend --host 127.0.0.1 --port 8000` on macOS/Linux. If the extraction tool drops executable permission on macOS/Linux, run `chmod +x codeshield-backend`. JavaScript AST analysis outside VS Code needs Node.js on PATH. The installed VSIX supplies VS Code's Node runtime to its managed backend. macOS packages need platform validation and may be subject to Gatekeeper because these workflows do not provide signing or notarization.

## Four-step presentation demo

Use a separate trusted workspace with synthetic fixtures. Install Windows 0.1.60 and wait for the backend to start. Open **View → Output** to access **CodeShield** for backend messages and **CodeShield Workspace Scan** for OSV request/publication logs. Do not install the intentionally old Django version used below. The scanner reads its manifest declaration.

### 1. Scan local code and explain A05

Save the following as `demo_sql.py`. Open it and make an edit to show automatic findings. **Secure Coding: Scan Current File** can repeat the scan.

```python
def find_user(cursor, username):
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    return cursor.execute(query).fetchall()
```

Hover over the execution call and show `PY-SQLI-001`, Critical, CWE-89 and A05:2025 Injection. Its 2021 crosswalk is A03:2021 Injection. This fixture is for static analysis and contains no application or database startup.

### 2. Review a fix, apply and rescan

Open Quick Fix on the finding. Use the deterministic action if offered for this exact shape, or choose AI Fix with a prepared provider. For cloud AI, review the code/context choice before sending it. Preview the diff and check that it preserves `username`, the query and the return value. Apply only a validated proposal. Model output and latency vary, so record the demonstration in advance.

A correct parameterized form for this SQLite example is below. If the chosen model fails, use this reviewed edit to complete the demo and describe that outcome accurately.

```python
def find_user(cursor, username):
    # Why: Bound parameters keep the username separate from SQL syntax.
    return cursor.execute(
        "SELECT id, username FROM users WHERE username = ?",
        (username,),
    ).fetchall()
```

Rescan and show the selected finding clears. Check behavior in the demo application's tests. Quick Fix targets one supported change. Fix All applies available deterministic changes in the current file and can leave unsupported findings for separate review.

### 3. Enable OSV and demonstrate A03

In **user settings**, enable `secureCoding.osvAdvisories`. Save `requirements.txt` in the trusted demo workspace with this content and run **Secure Coding: Scan Current File**.

```text
django==3.2.1
```

Wait for the asynchronous advisory response. Show `CS-A03-OSV` and CVE references attached to the dependency line. In **CodeShield Workspace Scan**, follow `request /dependency-advisories`, the HTTP response/finding count, then `published ... advisory diagnostic(s)` for that file URI. The CVE list can change. Exact dependency pins can be vulnerable even when offline declaration checks produce no warning. This demonstration checks an advisory match without installing Django.

### 4. Explain evidence and limits

Show the recorded **53/53 backend checks**, **3/3 asynchronous publication tests**, and successful packaged-backend/VS Code OSV verification. Present the **25 expected detections and 12 negative probes** as a separate small synthetic corpus.

Explain that local scanning analyzes files individually, the AI context cache supplies selected excerpts for a requested fix, and the tools cover selected vulnerability patterns. OSV failures preserve offline findings. A clean scan does not prove security, and a dependency upgrade needs compatibility testing. Network and stale-response failures were covered with controlled tests. Show a failure as a live or recorded demo only if that behavior was actually exercised.

## Commands

- **Secure Coding: Scan Current File** — run a scan on the active supported document.
- **Secure Coding: Scan Workspace Security Findings** — scan supported workspace files and show findings in the Problems panel.
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
