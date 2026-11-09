# CodeShield AI — Secure Coding Assistant

CodeShield AI is a Visual Studio Code extension that scans Python and JavaScript files for selected security patterns and helps developers review possible fixes. It combines local static analysis, deterministic fixes, and optional AI-assisted fixes.

> **Important:** CodeShield AI is a development aid, not a complete security scanner. It can miss vulnerabilities or report patterns that are safe in their context. Review and test every proposed change, and use other security review tools for important software.

## Features

- Scans supported Python and JavaScript files automatically when the extension starts and as files change.
- Reports findings inline and in VS Code’s Problems panel with severity, rule identifiers, and remediation guidance.
- Covers selected patterns including SQL and command injection, cross-site scripting sinks, hardcoded credentials, weak cryptography, path traversal, server-side request forgery, unsafe deserialization, and insecure JWT handling.
- Offers deterministic **Quick Fix** actions for supported rules and **Fix All** for supported deterministic fixes in the active file.
- Offers **AI Fix** for a focused finding using a configured local or cloud model. The proposal is syntax-checked and rescanned before the extension asks whether to apply it.
- Adds a short “Why” comment to AI fixes where it can do so safely.
- Labels whether a proposal came from the selected model, the built-in CodeShield fallback, or an unverified source. Fallback messages include the available reason.
- Caches relevant workspace context locally to help an explicitly requested AI fix match the surrounding project. This context cache does not create findings.

## Requirements

- Visual Studio Code 1.85 or later.
- The packaged release currently targets **Windows x64**. The bundled backend executable is not provided for macOS or Linux.
- An AI provider is optional for scanning and deterministic fixes. To use AI Fix, configure a provider and a model that can be reached from your computer.

## Install from a VSIX

1. Download or locate `secure-coding-assistant-0.1.37.vsix`.
2. In VS Code, open **Extensions**.
3. Open the Extensions view’s **…** menu and choose **Install from VSIX…**.
4. Select the VSIX and reload VS Code if prompted.

The packaged extension starts its bundled backend automatically. No manual terminal or PowerShell setup is required for the packaged Windows build.

## Getting started

1. Open a workspace containing Python or JavaScript files.
2. CodeShield AI starts its local backend and scans supported workspace files automatically. Findings appear inline and in **View → Problems**.
3. To run a scan again manually, open the Command Palette with **Ctrl+Shift+P** and choose **Secure Coding: Scan Python and JavaScript Workspace**. To scan just the active file, choose **Secure Coding: Scan Current File**.
4. Place the cursor on a CodeShield finding and open **Quick Fix** with **Ctrl+.** to see available actions.
5. Review a fix before accepting it. AI Fix shows a preview and confirmation before changing the file.

The CodeShield status-bar item shows the selected AI provider and the active file’s finding count. The file count is not a workspace security score.

## AI providers

Open **Secure Coding: Configure AI Provider** from the Command Palette or click the CodeShield AI status-bar item.

| Provider | What you need |
| --- | --- |
| **Ollama** | Ollama running locally and an installed model. The model picker refreshes from Ollama, so newly downloaded models can appear automatically. |
| **Groq** | A Groq API key and access to the selected model. |
| **Gemini** | A Google AI Studio API key and access to the selected model. |
| **OpenRouter** | An OpenRouter API key and an available model. |
| **Custom OpenAI-compatible API** | An HTTPS endpoint, model ID, and API key. A custom endpoint may charge for usage. |

Cloud providers may have changing model availability, quotas, rate limits, and data-use terms. “Free” model or tier availability is controlled by the provider and is not guaranteed by this extension. API keys are stored using VS Code SecretStorage. Do not paste keys into source files.

### Ollama

Keep the Ollama application or service running. Open **Secure Coding: Configure AI Provider**, choose **Ollama**, then select an installed model. The picker checks installed models when opened. If a model is missing, install it through Ollama first; a model download can take time and depends on model size and network speed.

## Choosing a fix action

- **Quick Fix** applies a supported, context-checked CodeShield template for the selected finding. It is fast and does not require an AI provider.
- **Fix All** applies supported deterministic templates to findings in the active file. Findings without a safe supported template remain for review.
- **AI Fix** asks the selected model for a focused replacement. CodeShield validates the candidate’s syntax and checks whether its scanner still reports the selected finding, then offers a diff and asks before applying.

AI models can return incomplete, unsafe, or invalid code. A model may also decline or fail to produce a usable patch. When a context-checked built-in template is available, CodeShield may offer it as a fallback. The confirmation identifies the fallback and gives the available reason; that patch is not model-generated. If the backend does not report the source, the confirmation labels it unverified. Review the complete diff and run the project’s own checks before relying on any fix.

## Scan scope and limitations

- Automatic workspace scanning is limited to Python and JavaScript files, and is bounded to 2,000 files. Individual files larger than 512 KiB are skipped.
- Common generated and dependency directories are excluded, including `.git`, `node_modules`, `venv`, `dist`, and `build`.
- Python analysis uses the Python AST. JavaScript uses a Babel AST sidecar when available and falls back to pattern scanning if the sidecar cannot start.
- Rules cover selected patterns; this is not comprehensive static application security testing. A clean result does not prove that code is secure.
- Syntax and scanner validation can reject an otherwise useful AI patch or allow an incomplete fix. Validation reduces risk but does not guarantee correctness.
- Diagnostics from Pylance, ESLint, or other VS Code extensions are separate from CodeShield findings.

## Privacy and data handling

Static scanning and the workspace context cache run locally. Scanning does not send code to a cloud AI provider.

When you explicitly request an AI fix from a cloud provider, CodeShield sends the selected finding and current-file context to that provider. Related workspace files are sent only after a separate prompt lists the files and lets you choose to include them. Common credential assignments, private-key blocks, and URL credentials are redacted before prompt construction, but redaction is best-effort and may miss secrets. Choose **Use Current File Only** or cancel when project context should not be shared. Review the provider’s data-use terms before sending code.

For Ollama, the AI request is sent to the configured local Ollama service. Cloud API keys are stored in VS Code SecretStorage; provider accounts and services remain subject to their own security and privacy policies.

## Commands

Open the Command Palette with **Ctrl+Shift+P** and search for:

| Command | Purpose |
| --- | --- |
| **Secure Coding: Scan Current File** | Scan the active supported file. |
| **Secure Coding: Scan Python and JavaScript Workspace** | Scan supported files in the workspace. |
| **Secure Coding: Fix with AI** | Choose a finding and request a focused AI fix. |
| **Secure Coding: Fix All Vulnerabilities in File** | Apply available deterministic fixes in the active file. |
| **Secure Coding: Show Current File Findings** | Show the current file’s finding count. |
| **Secure Coding: Configure AI Provider** | Select a provider and configure its model or credentials. |
| **Secure Coding: Show Backend Log** | Open the backend log when troubleshooting startup or scanner issues. |

## Settings

These settings are available under **Settings → Extensions → Secure Coding Assistant**:

| Setting | Purpose |
| --- | --- |
| `secureCoding.backendUrl` | Backend API URL. The packaged Windows extension normally starts its bundled backend at `http://127.0.0.1:8000`. |
| `secureCoding.aiProvider` | Selected provider: `ollama`, `groq`, `gemini`, `openrouter`, or `custom`. |
| `secureCoding.aiApiBase` | Local Ollama API base URL. Defaults to `http://localhost:11434/v1`. |
| `secureCoding.aiModel` | Model ID used by the selected provider. |
| `secureCoding.cloudApiBase` | Endpoint for a custom OpenAI-compatible provider. |

Use the provider picker to configure credentials; do not put API keys in workspace settings or commit them to source control.

## Troubleshooting

### No findings appear

- Check that the active file is Python or JavaScript and is within the documented scan limits.
- Wait for the local backend to start, then run **Secure Coding: Scan Current File**.
- Use **Secure Coding: Show Backend Log** if startup or scanner errors persist.
- Remember that CodeShield detects only the patterns it implements; it will not find every bug or vulnerability.

### Ollama model is missing or takes a long time

- Confirm Ollama is installed and running.
- Check the model name with Ollama, download it if needed, and reopen the CodeShield provider picker.
- The first request can take longer while a model loads into memory. Larger models need more RAM and disk space.

### Cloud AI request fails

- Confirm the selected provider, saved API key, model ID, and provider account access.
- Check provider quotas, free-tier limits, and service availability. Rate limiting or model access errors must be resolved with the provider.
- Avoid retrying repeatedly during an outage; try again later or select another configured provider.

### AI Fix uses a built-in fallback

Read the confirmation’s fallback reason. It may indicate a provider error, a model decline, an invalid response, a syntax failure, or a patch that could not safely fit the selected code range. The fallback is a CodeShield rule template, not output from the selected model. If no safe template exists, no fallback patch is offered.

### A fix is rejected or the finding remains

Review the candidate and its syntax/scanner warning. The finding may need broader changes than a focused fix can safely make. You can try another configured model, edit the code manually, and run the scan again. Do not apply a patch solely because an AI model suggested it.

## Development

From the `extension` directory:

```powershell
npm install
npm run compile
```

Open the repository in VS Code and press **F5** to launch an Extension Development Host. To create a local VSIX:

```powershell
npm run package
```

Packaging creates a local artifact; it does not publish the extension to the Visual Studio Marketplace.

The current Windows VSIX includes only the Windows backend. A macOS VSIX must be built on a Mac of the target architecture because PyInstaller does not normally cross-compile between operating systems. On a Mac, run `bash backend/build-macos.sh`, then `bash extension/package-macos.sh darwin-arm64` on Apple Silicon or `bash extension/package-macos.sh darwin-x64` on Intel. The **Build macOS VSIX** GitHub Actions workflow also builds both targets and stores the VSIX files as workflow artifacts; it does not publish them. Mac packaging is prepared in this repository but still needs to be run and smoke-tested on macOS.

## Project

Source repository: [ICT30016 Project](https://github.com/AllenLIEW9966/ICT30016-Project)
