import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/** A1: backend lifecycle manager — bundled exe first, dev server fallback. */
export class BackendManager {
  private proc: cp.ChildProcess | null = null;
  private out: vscode.OutputChannel;
  private url: string;
  private ollamaUrl: string;
  private ollamaReady = false;
  private ollamaModelAvailable = false;

  constructor(url: string, ollamaUrl: string) {
    this.url = url.replace(/\/$/, '');
    this.ollamaUrl = ollamaUrl.replace(/\/$/, '');
    this.out = vscode.window.createOutputChannel('CodeShield');
  }

  private bundledExe(ctx: vscode.ExtensionContext): string | null {
    const base = ctx.extensionPath;
    const names =
      process.platform === 'win32'
        ? ['server/codeshield-backend.exe']
        : ['server/codeshield-backend', 'server/codeshield-backend-macos'];
    for (const n of names) {
      const p = path.join(base, n);
      try {
        if (fs.existsSync(p)) {
          return p;
        }
      } catch {
        /* ignore */
      }
    }
    return null;
  }

  private devCommand(ctx: vscode.ExtensionContext): { cmd: string; args: string[]; cwd: string } | null {
    // Dev fallback: backend/ next to extension/ in the source checkout.
    const backendDir = path.resolve(ctx.extensionPath, '..', 'backend');
    const uvicorn =
      process.platform === 'win32'
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

  async isUp(): Promise<boolean> {
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 1500);
      const r = await fetch(`${this.url}/health`, { signal: ctl.signal });
      clearTimeout(t);
      return r.ok;
    } catch {
      return false;
    }
  }

  async ensureRunning(ctx: vscode.ExtensionContext, status: vscode.StatusBarItem): Promise<boolean> {
    if (await this.isUp()) {
      await this.checkOllama();
      return true;
    }
    status.text = '$(sync~spin) CodeShield: starting…';
    const exe = this.bundledExe(ctx);
    let cmd: string;
    let args: string[];
    let cwd: string | undefined;
    if (exe) {
      cmd = exe;
      args = ['--host', '127.0.0.1', '--port', '8000'];
      cwd = path.dirname(exe);
      this.out.appendLine(`[backend] starting bundled: ${exe}`);
    } else {
      const dev = this.devCommand(ctx);
      if (!dev) {
        status.text = '$(alert) CodeShield: backend missing';
        this.out.appendLine('[backend] no bundled exe and no dev backend found.');
        vscode.window.showWarningMessage(
          'CodeShield backend not found. Scans are disabled until the backend is installed.',
        );
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
    } catch (err) {
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

  async checkOllama(): Promise<void> {
    this.ollamaReady = false;
    this.ollamaModelAvailable = false;
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 2000);
      const r = await fetch(`${this.ollamaUrl}/api/tags`, { signal: ctl.signal });
      clearTimeout(t);
      if (r.ok) {
        this.ollamaReady = true;
        const data = (await r.json()) as { models?: { name?: string }[] };
        const model = vscode.workspace
          .getConfiguration('secureCoding')
          .get<string>('aiModel', 'codellama:7b-instruct');
        this.ollamaModelAvailable = data.models?.some((m) => m.name?.startsWith(model)) ?? false;
      }
    } catch {
      /* Ollama not running — AI suggestions offline, templates still work */
    }
    this.out.appendLine(
      `[ollama] ready=${this.ollamaReady} model=${this.ollamaModelAvailable}`,
    );
  }

  isOllamaReady(): boolean {
    return this.ollamaReady;
  }

  isOllamaModelAvailable(): boolean {
    return this.ollamaModelAvailable;
  }

  ollamaStatusText(): string {
    if (this.ollamaModelAvailable) return '$(check) AI';
    if (this.ollamaReady) return '$(circle-outline) AI (model missing)';
    return '$(error) AI (offline)';
  }

  showLog() {
    this.out.show();
  }

  dispose() {
    try {
      this.proc?.kill();
    } catch {
      /* ignore */
    }
    this.proc = null;
    this.out.dispose();
  }
}
