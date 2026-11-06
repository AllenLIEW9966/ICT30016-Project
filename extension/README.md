# Secure Coding Assistant

VS Code extension for Python and JavaScript security scanning and AI-assisted fixes.

## Workspace context for AI fixes

The extension builds a bounded local context cache of eligible Python, JavaScript, and project configuration files at activation, then refreshes it as files are opened or edited. This context pass does not run AI security review and does not create findings or diagnostics. When you explicitly request **Fix with AI**, the extension adds relevant imports, project configuration, and related files to the fix request so the selected model can understand more of the project. With a cloud provider, this related context is sent to that provider as part of your requested AI fix.

## Commands

- **Secure Coding: Scan Current File** — run the static scanner on the active file.
- **Secure Coding: Fix with AI** — ask the selected provider to fix the active finding.
- **Secure Coding: Fix All Vulnerabilities in File** — apply supported deterministic templates in the active file.
- **Secure Coding: Configure AI Provider** — select a local or cloud provider.
