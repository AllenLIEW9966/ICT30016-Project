# Secure Coding Assistant

A VSCode extension + FastAPI backend that scans Python and JavaScript for common security issues while you type, then suggests fixes using a local AI model.

## What it does

- Scans Python and JS files in real time
- Highlights risky code with red squiggles
- Shows OWASP/CWE info on hover
- Suggests secure alternatives
- Can use AI to generate a fix

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
