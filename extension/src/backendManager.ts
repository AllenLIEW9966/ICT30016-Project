import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

/** Prefer the IPv4 loopback address used by the bundled backend on Windows. */
export function normalizeBackendUrl(value: string): string {
  const trimmed = value.trim().replace(/\/$/, '');
  try {
    const url = new URL(trimmed);
    if (url.hostname.toLowerCase() === 'localhost') {
      url.hostname = '127.0.0.1';
    }
    return url.toString().replace(/\/$/, '');
  } catch {
    return trimmed;
  }
}

/** A1: backend lifecycle manager — bundled exe first, dev server fallback. */
export class BackendManager {
  private readonly expectedBackendVersion = '0.1.51';
  private proc: cp.ChildProcess | null = null;
  private out: vscode.OutputChannel;
  private url: string;
  private ollamaUrl: string;
  private ollamaReady = false;
  private ollamaModelAvailable = false;

  constructor(url: string, ollamaUrl: string) {
    this.url = normalizeBackendUrl(url);
    this.ollamaUrl = ollamaUrl.replace(/\/$/, '');
    this.out = vscode.window.createOutputChannel('CodeShield');
  }

  private bundledExe(ctx: vscode.ExtensionContext): string | null {
    const base = ctx.extensionPath;
    const names = process.platform === 'win32'
      ? ['server/codeshield-backend.exe']
      : process.platform === 'darwin'
        ? ['server/codeshield-backend-macos']
        : process.platform === 'linux'
          ? ['server/codeshield-backend-linux', 'server/codeshield-backend']
          : [];
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

  private async healthState(): Promise<'current' | 'stale' | 'offline'> {
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 1500);
      const r = await fetch(`${this.url}/health`, { signal: ctl.signal });
      clearTimeout(t);
      if (!r.ok) return 'offline';
      const body = await r.json() as { version?: string };
      return body.version === this.expectedBackendVersion ? 'current' : 'stale';
    } catch {
      return 'offline';
    }
  }

  async isUp(): Promise<boolean> {
    return (await this.healthState()) === 'current';
  }

  async ensureRunning(ctx: vscode.ExtensionContext, status: vscode.StatusBarItem): Promise<boolean> {
    const initialHealth = await this.healthState();
    if (initialHealth === 'current') {
      await this.checkOllama();
      return true;
    }
    if (initialHealth === 'stale') {
      status.text = '$(alert) CodeShield: restart required';
      this.out.appendLine('[backend] an older or incompatible backend is already responding on the configured port.');
      vscode.window.showErrorMessage(
        'An older CodeShield backend is still running. Close all VS Code windows and end any remaining codeshield-backend process, then reopen VS Code.',
      );
      return false;
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
      const env = { ...process.env, CODESHIELD_NODE_BIN: process.execPath, ELECTRON_RUN_AS_NODE: '1' };
      this.proc = cp.spawn(cmd, args, { cwd, windowsHide: true, env });
    } catch (err) {
      this.out.appendLine(`[backend] spawn failed: ${err}`);
      status.text = '$(alert) CodeShield: backend failed';
      return false;
    }
    let startupOutput = '';
    let competingBackendLikely = false;
    let childExitAt: number | undefined;
    const captureStartupOutput = (data: Buffer | string) => {
      const text = data.toString();
      startupOutput = `${startupOutput}${text}`.slice(-10000);
      this.out.append(text);
      if (/EADDRINUSE|WinError\s*10048|only one usage of each socket address|address already in use/i.test(startupOutput)) {
        competingBackendLikely = true;
      }
    };
    this.proc.stdout?.on('data', captureStartupOutput);
    this.proc.stderr?.on('data', captureStartupOutput);
    this.proc.on('error', (error) => {
      this.out.appendLine(`[backend] process error: ${error.message}`);
      childExitAt = Date.now();
      this.proc = null;
    });
    this.proc.on('exit', (code) => {
      this.out.appendLine(`[backend] exited code=${code}`);
      childExitAt = Date.now();
      this.proc = null;
    });
    const startupStartedAt = Date.now();
    for (let i = 0; i < 30; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      const health = await this.healthState();
      if (health === 'current') {
        this.out.appendLine(competingBackendLikely
          ? '[backend] connected to the healthy backend already using this port.'
          : '[backend] ready');
        await this.checkOllama();
        return true;
      }
      if (health === 'stale') {
        this.proc?.kill();
        status.text = '$(alert) CodeShield: restart required';
        vscode.window.showErrorMessage(
          'An older CodeShield backend is still responding on the configured port. Stop it and restart VS Code before scanning or fixing code.',
        );
        return false;
      }
      // Another VS Code window can win the race to bind the shared local port.
      // Its server may still be finishing startup after our child exits; retry
      // health briefly instead of immediately declaring this window offline.
      if (this.proc === null && (!competingBackendLikely || (childExitAt !== undefined && Date.now() - childExitAt >= 10000))) {
        break;
      }
    }
    status.text = '$(alert) CodeShield: backend failed';
    this.out.appendLine(`[backend] did not become ready after ${Math.round((Date.now() - startupStartedAt) / 1000)}s.`);
    if (competingBackendLikely) {
      this.out.appendLine(`[backend] a process is using ${this.url}, but it did not expose a compatible CodeShield health endpoint.`);
      vscode.window.showErrorMessage(
        `CodeShield could not connect to a compatible backend at ${this.url}. Another process may be using that port; close it or configure a free backend port.`,
      );
    }
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

  async listOllamaModels(): Promise<string[]> {
    try {
      const ctl = new AbortController();
      const timeout = setTimeout(() => ctl.abort(), 2000);
      try {
        const response = await fetch(`${this.ollamaUrl}/api/tags`, { signal: ctl.signal });
        if (!response.ok) return [];
        const data = await response.json() as { models?: { name?: string }[] };
        return [...new Set((data.models || []).map((model) => model.name?.trim()).filter((name): name is string => Boolean(name)))];
      } finally {
        clearTimeout(timeout);
      }
    } catch {
      return [];
    }
  }

  async waitForOllamaModel(model: string, onStatus: (available: boolean) => void): Promise<boolean> {
    const deadline = Date.now() + 20 * 60 * 1000;
    const normalizedModel = model.trim().toLowerCase();
    while (Date.now() < deadline) {
      try {
        const ctl = new AbortController();
        const timeout = setTimeout(() => ctl.abort(), 2000);
        const response = await fetch(`${this.ollamaUrl}/api/tags`, { signal: ctl.signal });
        clearTimeout(timeout);
        this.ollamaReady = response.ok;
        if (response.ok) {
          const data = await response.json() as { models?: { name?: string }[] };
          this.ollamaModelAvailable = data.models?.some((item) => {
            const name = item.name?.toLowerCase() || '';
            return name === normalizedModel || name.startsWith(`${normalizedModel}:`);
          }) ?? false;
          if (this.ollamaModelAvailable) {
            onStatus(true);
            this.out.appendLine(`[ollama] model pull completed: ${model}`);
            return true;
          }
        } else {
          this.ollamaModelAvailable = false;
        }
      } catch {
        this.ollamaReady = false;
        this.ollamaModelAvailable = false;
      }
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
    onStatus(false);
    this.out.appendLine(`[ollama] timed out waiting for model: ${model}`);
    return false;
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
