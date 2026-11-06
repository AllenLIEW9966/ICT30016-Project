# Secure Coding Assistant

A VS Code extension + FastAPI backend that statically scans Python and JavaScript for common security issues while you type, then suggests fixes using local or cloud AI. It keeps a bounded local workspace context cache to improve requested AI fixes; context collection does not create findings.

## What it does

- Scans Python and JS files in real time
- Highlights risky code with red squiggles
- Shows OWASP/CWE info on hover
- Suggests secure alternatives
- Can use AI to generate a fix
- Keeps relevant workspace source and configuration in a local context cache for AI fixes

## Setup

### Backend

```bash
cd backend
python -m venv venv
venv/Scripts/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### AI (optional)

```bash
ollama pull codellama:7b-instruct
ollama serve
```

The extension defaults to local Ollama. Use **Secure Coding: Configure AI Provider** to select Ollama, Groq Free Tier, Gemini Free Tier, OpenRouter Free Models, or a custom OpenAI-compatible endpoint. The prepared cloud choices use free-tier models and require your own API key. Keys are stored in VS Code SecretStorage. Static scanning and workspace context collection run locally. For a cloud AI fix, selected-file context goes to the provider; related workspace files are included only after a separate prompt. Free quotas and model availability can change. The custom endpoint may incur charges, and Google may use free-tier API content to improve its products.

### VSCode Extension

```bash
cd extension
npm install
npm run compile
```

Press **F5** in VS Code to test.

## Commands

- **Secure Coding: Scan Current File** — run scan manually
- **Secure Coding: Fix with AI** — get AI suggestion for current finding
- **Secure Coding: Show Security Score** — see score in status bar

## Test

```bash
cd backend
python app/tests.py
```

## What I built

- Python scanner using AST
- JS scanner using regex
- FastAPI backend with /scan and /suggest-fix
- VSCode extension with diagnostics, hover, status bar
- AI integration via Ollama
