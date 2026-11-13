# CodeShield AI IDE plugin ZIP

This is a separate IDE plugin project. It does not change the VS Code extension.

## First version

- Adds a **CodeShield** tool window with a **Scan Active File** action.
- Scans Python (`.py`) and JavaScript (`.js`, `.jsx`, `.mjs`, `.cjs`) through the existing CodeShield backend `/scan` endpoint.
- Lists findings and lets you select one to navigate to its source line.
- Uses `http://127.0.0.1:8000` by default. Backend URL configuration is restricted to loopback to avoid sending source code to an unintended remote server.

This first version is a scanning integration. AI fixes, automatic backend startup, bundled platform backends, workspace-wide scanning, and inline editor inspections are not implemented yet.

## Run the backend locally

Start the existing backend from the `backend` directory before scanning.

### Windows PowerShell

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm ci --prefix js-ast
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### macOS or Linux

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
npm ci --prefix js-ast
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Build the plugin ZIP

Use JDK 17 or newer and Gradle 9.0.0 or newer. From this folder run:

```bash
gradle buildPlugin
```

The distributable ZIP is written under `build/distributions/`. In the target IDE, install it from **Settings → Plugins → ⚙ → Install Plugin from Disk…**.

You can also download the ZIP built by GitHub Actions: open the repository's **Actions** tab, select **Build CodeShield ZIP**, open its latest successful run, and download the `codeshield-zip` artifact. Extract it before installing with **Install Plugin from Disk…**. The CI artifact does not include or start the backend; follow **Run the backend locally** first.

This is an early IDE plugin ZIP prototype. The build creates an installable package, but verify it in each intended IDE and operating system before distributing it. The ZIP does not include or start the CodeShield backend.
