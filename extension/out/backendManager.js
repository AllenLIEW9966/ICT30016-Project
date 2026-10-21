"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.BackendManager = void 0;
const vscode = __importStar(require("vscode"));
const cp = __importStar(require("child_process"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/** A1: backend lifecycle manager — bundled exe first, dev server fallback. */
class BackendManager {
    constructor(url, ollamaUrl) {
        this.proc = null;
        this.ollamaReady = false;
        this.ollamaModelAvailable = false;
        this.url = url.replace(/\/$/, '');
        this.ollamaUrl = ollamaUrl.replace(/\/$/, '');
        this.out = vscode.window.createOutputChannel('CodeShield');
    }
    bundledExe(ctx) {
        const base = ctx.extensionPath;
        const names = process.platform === 'win32'
            ? ['server/codeshield-backend.exe']
            : ['server/codeshield-backend', 'server/codeshield-backend-macos'];
        for (const n of names) {
            const p = path.join(base, n);
            try {
                if (fs.existsSync(p)) {
                    return p;
                }
            }
            catch {
                /* ignore */
            }
        }
        return null;
    }
    devCommand(ctx) {
        // Dev fallback: backend/ next to extension/ in the source checkout.
        const backendDir = path.resolve(ctx.extensionPath, '..', 'backend');
        const uvicorn = process.platform === 'win32'
            ? path.join(backendDir, 'venv', 'Scripts', 'uvicorn.exe')
            : path.join(backendDir, 'venv', 'bin', 'uvicorn');
        if (fs.existsSync(backendDir) && fs.existsSync(uvicorn)) {
            return { cmd: uvicorn, args: ['app.main:app', '--host', '127.0.0.1', '--port', '8000'], cwd: backendDir };
        }
        const py = process.platform === 'win32' ? 'python' : 'python3';
        if (fs.existsSync(path.join(backendDir, 'app', 'main.py'))) {
            return { cmd: py, args: ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000'], cwd: backendDir };
        }
        return null;
    }
    async isUp() {
        try {
            const ctl = new AbortController();
            const t = setTimeout(() => ctl.abort(), 1500);
            const r = await fetch(`${this.url}/health`, { signal: ctl.signal });
            clearTimeout(t);
            return r.ok;
        }
        catch {
            return false;
        }
    }
    async ensureRunning(ctx, status) {
        if (await this.isUp()) {
            await this.checkOllama();
            return true;
        }
        status.text = '$(sync~spin) CodeShield: starting…';
        const exe = this.bundledExe(ctx);
        let cmd;
        let args;
        let cwd;
        if (exe) {
            cmd = exe;
            args = ['--host', '127.0.0.1', '--port', '8000'];
            cwd = path.dirname(exe);
            this.out.appendLine(`[backend] starting bundled: ${exe}`);
        }
        else {
            const dev = this.devCommand(ctx);
            if (!dev) {
                status.text = '$(alert) CodeShield: backend missing';
                this.out.appendLine('[backend] no bundled exe and no dev backend found.');
                vscode.window.showWarningMessage('CodeShield backend not found. Scans are disabled until the backend is installed.');
                return false;
            }
            cmd = dev.cmd;
            args = dev.args;
            cwd = dev.cwd;
            this.out.appendLine(`[backend] starting dev server: ${cmd} ${args.join(' ')}`);
        }
        try {
            // A2: hand VS Code's own Node to the backend so users never install Node.
            const env = { ...process.env, CODESHIELD_NODE_BIN: process.execPath };
            this.proc = cp.spawn(cmd, args, { cwd, windowsHide: true, env });
        }
        catch (err) {
            this.out.appendLine(`[backend] spawn failed: ${err}`);
            status.text = '$(alert) CodeShield: backend failed';
            return false;
        }
        this.proc.stdout?.on('data', (d) => this.out.append(d.toString()));
        this.proc.stderr?.on('data', (d) => this.out.append(d.toString()));
        this.proc.on('exit', (code) => {
            this.out.appendLine(`[backend] exited code=${code}`);
            this.proc = null;
        });
        for (let i = 0; i < 30; i++) {
            await new Promise((r) => setTimeout(r, 1000));
            if (await this.isUp()) {
                this.out.appendLine('[backend] ready');
                await this.checkOllama();
                return true;
            }
            if (this.proc === null) {
                break;
            }
        }
        status.text = '$(alert) CodeShield: backend failed';
        this.out.appendLine('[backend] did not become ready in 30s.');
        return false;
    }
    /* ---------- B1: Ollama probe (optional AI) ---------- */
    async checkOllama() {
        this.ollamaReady = false;
        this.ollamaModelAvailable = false;
        try {
            const ctl = new AbortController();
            const t = setTimeout(() => ctl.abort(), 2000);
            const r = await fetch(`${this.ollamaUrl}/api/tags`, { signal: ctl.signal });
            clearTimeout(t);
            if (r.ok) {
                this.ollamaReady = true;
                const data = (await r.json());
                const model = vscode.workspace
                    .getConfiguration('secureCoding')
                    .get('aiModel', 'codellama:7b-instruct');
                this.ollamaModelAvailable = data.models?.some((m) => m.name?.startsWith(model)) ?? false;
            }
        }
        catch {
            /* Ollama not running — AI suggestions offline, templates still work */
        }
        this.out.appendLine(`[ollama] ready=${this.ollamaReady} model=${this.ollamaModelAvailable}`);
    }
    isOllamaReady() {
        return this.ollamaReady;
    }
    isOllamaModelAvailable() {
        return this.ollamaModelAvailable;
    }
    ollamaStatusText() {
        if (this.ollamaModelAvailable)
            return '$(check) AI';
        if (this.ollamaReady)
            return '$(circle-outline) AI (model missing)';
        return '$(error) AI (offline)';
    }
    showLog() {
        this.out.show();
    }
    dispose() {
        try {
            this.proc?.kill();
        }
        catch {
            /* ignore */
        }
        this.proc = null;
        this.out.dispose();
    }
}
exports.BackendManager = BackendManager;
//# sourceMappingURL=backendManager.js.map