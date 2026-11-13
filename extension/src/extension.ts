import * as vscode from 'vscode';
import * as path from 'path';
import { BackendManager, normalizeBackendUrl } from './backendManager';

type Finding = {
  rule_id: string;
  title: string;
  severity: string;
  cwe_id: string;
  owasp_ref: string;
  owasp_2021_ref?: string;
  message: string;
  line: number;
  column: number;
  end_line: number;
  end_column: number;
  suggestion: string;
  code_snippet: string;
};

type DependencyFix = { range: vscode.Range; text: string };

async function dependencyManifestFix(document: vscode.TextDocument, finding: Finding): Promise<DependencyFix | undefined> {
  if (!['DEP-UNPINNED-001', 'DEP-SOURCE-001'].includes(finding.rule_id)) return undefined;
  const root = vscode.workspace.getWorkspaceFolder(document.uri);
  if (!root) return undefined;
  const lineIndex = Math.max(0, finding.line - 1);
  const line = document.lineAt(lineIndex).text;
  const basename = path.basename(document.uri.fsPath).toLowerCase();
  let updatedLine: string | undefined;

  if (basename === 'package.json') {
    const entry = /^(\s*)("(?:[^"\\]|\\.)+")(\s*:\s*)("(?:[^"\\]|\\.)*")(\s*,?\s*(?:\/\/.*)?)$/.exec(line);
    if (!entry) return undefined;
    let packageName: string;
    let spec: string;
    try { packageName = JSON.parse(entry[2]); spec = JSON.parse(entry[4]); } catch { return undefined; }
    const isUnbounded = finding.rule_id === 'DEP-UNPINNED-001' && ['*', 'latest'].includes(spec.toLowerCase());
    const isMutableSource = finding.rule_id === 'DEP-SOURCE-001' && /^(?:git\+|git:|https?:\/\/|github:)/i.test(spec);
    if (!isUnbounded && !isMutableSource) return undefined;
    const npmLock = await readNearestLock(document, root, 'package-lock.json');
    if (!npmLock) return undefined;
    try {
      const lock = JSON.parse(npmLock);
      const packageEntry = lock.packages?.[`node_modules/${packageName}`] || lock.dependencies?.[packageName];
      if (!packageEntry) return undefined;
      let replacement = '';
      if (isUnbounded && typeof packageEntry.version === 'string' && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(packageEntry.version)) {
        replacement = packageEntry.version;
      } else if (isMutableSource && typeof packageEntry.resolved === 'string' && /#[0-9a-f]{40}(?:$|\?)/i.test(packageEntry.resolved)) {
        replacement = packageEntry.resolved;
      }
      if (!replacement) return undefined;
      updatedLine = `${entry[1]}${entry[2]}${entry[3]}${JSON.stringify(replacement)}${entry[5]}`;
    } catch { return undefined; }
  } else if (/^requirements.*\.txt$/.test(basename)) {
    if (finding.rule_id !== 'DEP-UNPINNED-001') return undefined;
    const entry = /^(\s*)([A-Za-z0-9_.-]+)(\[[^\]]+\])?(\s*(?:#.*)?)$/.exec(line);
    if (!entry) return undefined;
    const name = entry[2];
    const pin = await findPythonLockPin(document, root, name);
    if (!pin) return undefined;
    updatedLine = `${entry[1]}${name}${entry[3] || ''}==${pin}${entry[4]}`;
  } else if (basename === 'pyproject.toml') {
    if (finding.rule_id !== 'DEP-UNPINNED-001') return undefined;
    const entry = /(["'])([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)(\1)/.exec(line);
    if (!entry) return undefined;
    const name = entry[2].match(/^([A-Za-z0-9_.-]+)/)?.[1];
    if (!name) return undefined;
    const pin = await findPythonLockPin(document, root, name);
    if (!pin) return undefined;
    updatedLine = line.replace(entry[0], `${entry[1]}${entry[2]}==${pin}${entry[1]}`);
  }

  if (updatedLine === undefined || updatedLine === line) return undefined;
  return {
    range: new vscode.Range(lineIndex, 0, lineIndex, line.length),
    text: updatedLine,
  };
}

async function readNearestLock(document: vscode.TextDocument, root: vscode.WorkspaceFolder, filename: string): Promise<string | undefined> {
  let directory = path.dirname(document.uri.fsPath);
  const rootPath = path.resolve(root.uri.fsPath);
  while (true) {
    const candidate = vscode.Uri.file(path.join(directory, filename));
    try {
      const bytes = await vscode.workspace.fs.readFile(candidate);
      if (bytes.byteLength > 2 * 1024 * 1024 || bytes.includes(0)) return undefined;
      return new TextDecoder('utf-8').decode(bytes);
    } catch { /* Check the next parent directory for the manifest's lock file. */ }
    if (path.resolve(directory).toLowerCase() === rootPath.toLowerCase()) break;
    const parent = path.dirname(directory);
    const relative = path.relative(rootPath, parent);
    if (parent === directory || relative.startsWith('..') || path.isAbsolute(relative)) break;
    directory = parent;
  }
  return undefined;
}

async function findPythonLockPin(document: vscode.TextDocument, root: vscode.WorkspaceFolder, packageName: string): Promise<string | undefined> {
  const normalizedName = packageName.toLowerCase().replace(/[-_.]+/g, '-');
  for (const lockName of ['requirements.lock', 'constraints.txt', 'poetry.lock', 'uv.lock', 'Pipfile.lock']) {
    const content = await readNearestLock(document, root, lockName);
    if (!content) continue;
    if (lockName === 'Pipfile.lock') {
      try {
        const lock = JSON.parse(content);
        const entry = lock.default?.[packageName] || lock.develop?.[packageName];
        const version = typeof entry?.version === 'string' ? entry.version.replace(/^==/, '') : '';
        if (/^[A-Za-z0-9][A-Za-z0-9.!+_-]*$/.test(version)) return version;
      } catch { /* Invalid lock file: keep looking for a supported exact pin. */ }
      continue;
    }
    const escapedPackageName = packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const requirement = new RegExp(`^\\s*${escapedPackageName}(?:\\[[^\\]]+\\])?\\s*==\\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)`, 'im').exec(content);
    if (requirement) return requirement[1];
    if (lockName === 'poetry.lock' || lockName === 'uv.lock') {
      for (const block of content.split(/^\[\[package\]\]\s*$/m).slice(1)) {
        const nameMatch = /^name\s*=\s*["']([^"']+)["']/m.exec(block);
        const versionMatch = /^version\s*=\s*["']([^"']+)["']/m.exec(block);
        if (nameMatch && versionMatch && nameMatch[1].toLowerCase().replace(/[-_.]+/g, '-') === normalizedName && /^[A-Za-z0-9][A-Za-z0-9.!+_-]*$/.test(versionMatch[1])) return versionMatch[1];
      }
    }
  }
  return undefined;
}

type SuggestionResponse = {
  can_fix?: boolean;
  explanation: string;
  secure_code: string;
  references: string[];
  source?: 'provider' | 'template';
  provider?: string;
  warning?: string;
};

// C3: secrets storage, populated during activate
let secretStorage: {
  get(key: string): Thenable<string | undefined>;
  store(key: string, value: string): Thenable<void>;
} | undefined;

function secretKeyFor(provider: string): string {
  return `secureCoding.aiApiKey.${provider}`;
}

export function activate(context: vscode.ExtensionContext) {
  console.log('Secure Coding Assistant is now active');

  const backendUrl = normalizeBackendUrl(
    vscode.workspace.getConfiguration('secureCoding').get<string>('backendUrl', 'http://127.0.0.1:8000'),
  );
  const ollamaUrl = vscode.workspace.getConfiguration('secureCoding').get<string>('aiApiBase', 'http://localhost:11434/v1').replace('/v1', '');
  const backend = new BackendManager(backendUrl, ollamaUrl);
  let backendReady = false;
  secretStorage = context.secrets;
  context.subscriptions.push({ dispose: () => backend.dispose() });
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('secureCoding');
  context.subscriptions.push(diagnosticCollection);

  // Keep finding metadata keyed by document URI so hover/fix can access OWASP/CWE/suggestion
  const findingsByUri = new Map<string, Finding[]>();
  const findingVersionsByUri = new Map<string, number>();
  const workspaceScanOutput = vscode.window.createOutputChannel('CodeShield Workspace Scan');
  context.subscriptions.push(workspaceScanOutput);

  let statusBarItem: vscode.StatusBarItem | undefined;
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'secureCoding.showSecurityScore';
  statusBarItem.tooltip = 'CodeShield findings for the active file';
  statusBarItem.text = '$(shield) File: —';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // B: AI status bar item
  const aiStatusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 99);
  aiStatusBarItem.command = 'secureCoding.installLocalAI';
  aiStatusBarItem.tooltip = 'Local AI status — click to install Ollama';
  aiStatusBarItem.text = '$(sync~spin) AI';
  aiStatusBarItem.show();
  context.subscriptions.push(aiStatusBarItem);

  const debounceTimers = new Map<string, NodeJS.Timeout>();
  const workspaceScanTimers = new Map<string, NodeJS.Timeout>();
  const scanRequestIds = new Map<string, number>();
  const maxWorkspaceScanFiles = 2000;
  const maxWorkspaceScanFileBytes = 512 * 1024;
  const workspaceScanExcludeGlob = '**/{.git,.venv,venv,node_modules,dist,build,out,coverage,__pycache__,.next,vendor,.pytest_cache,.mypy_cache}/**';

  // Fetch a fresh configuration snapshot each time. WorkspaceConfiguration is
  // immutable; retaining one across provider changes can leave AI Fix using a
  // stale provider while the status bar shows the newly selected one.
  const getAiConfig = () => vscode.workspace.getConfiguration('secureCoding');
  const cloudProviders: Record<string, { label: string; models: { label: string; description: string }[] }> = {
    groq: {
      label: 'Groq Free Tier',
      models: [{ label: 'openai/gpt-oss-20b', description: 'Free-plan model; subject to Groq account limits' }],
    },
    gemini: {
      label: 'Gemini Free Tier',
      models: [{ label: 'gemini-3.1-flash-lite', description: 'Gemini API free-tier model' }],
    },
    openrouter: {
      label: 'OpenRouter Free Models',
      models: [{ label: 'openrouter/free', description: 'Routes to a currently available free model' }],
    },
  };

  async function promptForCloudKey(provider: string): Promise<string | undefined> {
    return secretStorage?.get(secretKeyFor(provider));
  }

  async function ensureAiReady(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): Promise<boolean> {
    const provider = getAiConfig().get<string>('aiProvider', 'ollama');
    if (provider !== 'ollama' && !(await promptForCloudKey(provider))) {
      const configure = await vscode.window.showWarningMessage(
        `No API key is saved for ${provider}. Configure an AI provider first.`,
        'Configure AI Provider',
      );
      if (configure) await vscode.commands.executeCommand('secureCoding.installLocalAI');
      return false;
    }
    if (provider === 'ollama' && !backend.isOllamaModelAvailable()) {
      const choice = await vscode.window.showInformationMessage(
        `The selected Ollama model is not available for ${String(diagnostic.code)}.`,
        { modal: true },
        'Download Model',
        'Use Quick Fix',
      );
      if (choice === 'Download Model') {
        await vscode.commands.executeCommand('secureCoding.installLocalAI');
      } else if (choice === 'Use Quick Fix') {
        await applyTemplateFix(document, diagnostic, diagnosticCollection, () => scanDocument(document));
      }
      return false;
    }
    return true;
  }

  function startOllamaPull(model: string): void {
    const terminal = vscode.window.createTerminal('Ollama Install');
    terminal.sendText(`ollama pull ${model}`);
    terminal.show();
    aiStatusBarItem.text = '$(sync~spin) AI: Ollama';
    aiStatusBarItem.tooltip = `Waiting for ${model} to finish downloading.`;
    void backend.waitForOllamaModel(model, (available) => {
      const currentConfig = vscode.workspace.getConfiguration('secureCoding');
      if (currentConfig.get<string>('aiProvider') !== 'ollama' ||
          currentConfig.get<string>('aiModel') !== model) return;
      aiStatusBarItem.text = available ? '$(check) AI: Ollama' : '$(warning) AI: Ollama';
      aiStatusBarItem.tooltip = available
        ? `Ollama model ${model} is ready. Click to change providers.`
        : `Could not confirm ${model} after 20 minutes. Check the Ollama Install terminal and Ollama service.`;
      if (available) {
        vscode.window.showInformationMessage(`${model} is ready for local AI fixes.`);
      } else {
        vscode.window.showWarningMessage(
          `Could not find ${model} in Ollama. Check the Ollama Install terminal and confirm the Ollama service is running.`,
        );
      }
    });
  }

  async function suggestAlternativeModels(reason: string): Promise<void> {
    if (/allowed operations|allowlist|permitted operations|missing application policy/i.test(reason)) {
      vscode.window.showWarningMessage(
        `${reason} This is a missing application policy, not a model configuration issue. Define the permitted operations or review a fail-closed candidate; switching models alone will not provide that policy.`,
      );
      return;
    }
    const currentProvider = getAiConfig().get<string>('aiProvider', 'ollama');
    const currentModel = getAiConfig().get<string>('aiModel', 'qwen2.5-coder:1.5b-instruct');
    const installedOllamaModels = await backend.listOllamaModels();
    const localModels = [
      { model: 'qwen2.5-coder:1.5b-instruct', label: 'Qwen 2.5 Coder 1.5B', description: 'Prepared local coding model' },
      { model: 'codellama:7b-instruct', label: 'CodeLlama 7B', description: 'Prepared local coding model' },
      ...installedOllamaModels.map((model) => ({ model, label: model, description: 'Installed Ollama model' })),
    ];
    const choices: { label: string; description: string; provider: string; model: string }[] = [
      ...localModels.map((model) => ({
        label: `Ollama · ${model.label}`,
        description: `Local model · ${model.model} · ${model.description}`,
        provider: 'ollama',
        model: model.model,
      })),
      ...Object.entries(cloudProviders).flatMap(([provider, config]) => config.models.map((model) => ({
        label: `${config.label} · ${model.label}`,
        description: `${model.description} · requires your ${provider} API key`,
        provider,
        model: model.label,
      }))),
    ].filter((item, index, all) =>
      (item.provider !== currentProvider || item.model !== currentModel) &&
      all.findIndex((candidate) => candidate.provider === item.provider && candidate.model === item.model) === index,
    );

    const action = await vscode.window.showWarningMessage(
      `${reason} The current model may not be able to complete this fix. Choose another prepared model to retry.`,
      { modal: true },
      'Choose Suggested Model',
      'Keep Current Model',
    );
    if (action !== 'Choose Suggested Model') return;
    const selected = await vscode.window.showQuickPick(choices, {
      placeHolder: 'Suggested models currently available in Secure Coding Assistant',
      matchOnDescription: true,
    });
    if (!selected) return;

    if (selected.provider === 'ollama') {
      await getAiConfig().update('aiProvider', 'ollama', vscode.ConfigurationTarget.Global);
      await getAiConfig().update('aiModel', selected.model, vscode.ConfigurationTarget.Global);
      await backend.checkOllama();
      if (backend.isOllamaModelAvailable()) {
        aiStatusBarItem.text = '$(check) AI: Ollama';
        aiStatusBarItem.tooltip = `Ollama model ${selected.model} is ready.`;
        vscode.window.showInformationMessage(`Switched to ${selected.model}. Retry Fix with AI.`);
        return;
      }
      const pull = await vscode.window.showInformationMessage(
        `${selected.model} is not installed in Ollama. Download it now?`,
        { modal: true },
        'Download Model',
      );
      if (pull === 'Download Model') startOllamaPull(selected.model);
      return;
    }

    const disclosure = await vscode.window.showInformationMessage(
      'Cloud AI sends the selected finding and current-file context to that provider. Related workspace files are shared only after a separate prompt when you request an AI fix. Your API key is stored in VS Code SecretStorage; provider data-use terms apply.',
      { modal: true },
      'Continue',
    );
    if (disclosure !== 'Continue') return;
    let apiKey = await promptForCloudKey(selected.provider);
    if (!apiKey) {
      apiKey = await vscode.window.showInputBox({
        prompt: `Enter your ${selected.provider} API key`,
        password: true,
        ignoreFocusOut: true,
        validateInput: (value) => value.trim() ? undefined : 'An API key is required',
      });
      if (!apiKey?.trim()) return;
      await secretStorage?.store(secretKeyFor(selected.provider), apiKey.trim());
    }
    await getAiConfig().update('aiProvider', selected.provider, vscode.ConfigurationTarget.Global);
    await getAiConfig().update('aiModel', selected.model, vscode.ConfigurationTarget.Global);
    aiStatusBarItem.text = `$(cloud) AI: ${cloudProviders[selected.provider].label}`;
    aiStatusBarItem.tooltip = `Selected ${selected.model} through ${cloudProviders[selected.provider].label}.`;
    vscode.window.showInformationMessage(`Switched to ${selected.model}. Retry Fix with AI.`);
  }

  function findingForDiagnostic(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): Finding | undefined {
    return (findingsByUri.get(document.uri.toString()) || []).find((finding) =>
      finding.rule_id === String(diagnostic.code || '') &&
      finding.line === diagnostic.range.start.line + 1 &&
      finding.column === diagnostic.range.start.character &&
      finding.end_line === diagnostic.range.end.line + 1 &&
      finding.end_column === diagnostic.range.end.character,
    );
  }

  type CachedWorkspaceFile = { path: string; uri: vscode.Uri; document: vscode.TextDocument; version: number; content: string };
  const workspaceContextFiles = new Map<string, CachedWorkspaceFile>();
  let workspaceContextRefresh: Promise<void> = Promise.resolve();
  const contextExcludedDirectories = new Set([
    '.git', '.venv', 'venv', 'node_modules', 'dist', 'build', 'out', 'coverage',
    '__pycache__', '.next', 'vendor', '.pytest_cache', '.mypy_cache',
  ]);
  const contextConfigNames = new Set([
    'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock',
    'pyproject.toml', 'requirements.txt', 'pipfile', 'poetry.lock', 'setup.cfg', 'tox.ini',
    'tsconfig.json', 'dockerfile', 'vite.config.js', 'webpack.config.js',
    'cargo.toml', 'go.mod', 'composer.json', 'gemfile', 'pom.xml', 'build.gradle', 'build.gradle.kts',
  ]);
  const contextSecretName = (name: string) =>
    name.startsWith('.env') || /secret|credential|password|private.?key|(^|[._-])id_(rsa|ed25519)([._-]|$)|\.pem$|\.key$|\.p12$|\.pfx$|\.db$/i.test(name);
  const contextPatterns = [
    // Read key manifests first so a large source tree cannot crowd them out.
    '**/package.json', '**/package-lock.json', '**/pnpm-lock.yaml', '**/yarn.lock',
    '**/pyproject.toml', '**/requirements*.txt', '**/Pipfile', '**/poetry.lock',
    '**/setup.cfg', '**/tox.ini', '**/tsconfig.json', '**/Dockerfile',
    '**/Cargo.toml', '**/go.mod', '**/composer.json', '**/Gemfile', '**/pom.xml', '**/build.gradle*',
    '**/*.{py,js,jsx,ts,tsx,html,css,sql,sh,ps1,java,cs,go,rs,php,rb,vue,svelte}',
    '**/*.{yaml,yml,toml,ini,cfg}',
  ];
  const contextExcludeGlob = '**/{.git,.venv,venv,node_modules,dist,build,out,coverage,__pycache__,.next,vendor,.pytest_cache,.mypy_cache}/**';
  const contextMaxFiles = 500;
  const contextMaxFileChars = 80000;
  const contextMaxTotalChars = 500000;

  // Build a local context cache only; this is not an AI scan and emits no findings.
  workspaceContextRefresh = refreshWorkspaceContext();

  function contextPathFor(uri: vscode.Uri): string | undefined {
    const root = vscode.workspace.getWorkspaceFolder(uri);
    if (!root) return undefined;
    const relative = path.relative(root.uri.fsPath, uri.fsPath).replace(/\\/g, '/');
    return (vscode.workspace.workspaceFolders?.length || 0) > 1 ? root.name + '/' + relative : relative;
  }

  function eligibleContextFile(relative: string): boolean {
    const parts = relative.split('/');
    const name = parts[parts.length - 1]?.toLowerCase() || '';
    const suffix = path.extname(name).toLowerCase();
    const supported = ['.py', '.js', '.jsx', '.ts', '.tsx', '.html', '.css', '.sql', '.sh', '.ps1', '.java', '.cs', '.go', '.rs', '.php', '.rb', '.vue', '.svelte', '.yaml', '.yml', '.toml', '.ini', '.cfg'].includes(suffix) ||
      contextConfigNames.has(name) || /^requirements(?:[-_.].*)?\.txt$/i.test(name);
    return supported && !parts.some((part) => contextExcludedDirectories.has(part.toLowerCase())) &&
      !contextSecretName(name);
  }

  async function refreshWorkspaceContext(): Promise<void> {
    workspaceContextFiles.clear();
    const roots = vscode.workspace.workspaceFolders || [];
    let totalChars = 0;
    for (const root of roots) {
      for (const pattern of contextPatterns) {
        const uris = await vscode.workspace.findFiles(new vscode.RelativePattern(root, pattern), contextExcludeGlob, contextMaxFiles);
        for (const uri of uris) {
          if (workspaceContextFiles.size >= contextMaxFiles || totalChars >= contextMaxTotalChars) return;
          const relative = contextPathFor(uri);
          if (!relative || !eligibleContextFile(relative) || [...workspaceContextFiles.values()].some((item) => item.uri.toString() === uri.toString())) continue;
          try {
            const document = await vscode.workspace.openTextDocument(uri);
            const content = document.getText();
            if (content.includes('\0') || content.length > contextMaxFileChars || totalChars + content.length > contextMaxTotalChars) continue;
            workspaceContextFiles.set(relative, { path: relative, uri, document, version: document.version, content });
            totalChars += content.length;
          } catch {
            // Ignore unreadable or binary workspace files.
          }
        }
      }
    }
  }

  function updateWorkspaceContext(document: vscode.TextDocument): void {
    const relative = contextPathFor(document.uri);
    if (!relative) return;
    if (!eligibleContextFile(relative)) {
      workspaceContextFiles.delete(relative);
      return;
    }
    const content = document.getText();
    if (content.includes('\0') || content.length > contextMaxFileChars) {
      workspaceContextFiles.delete(relative);
      return;
    }
    const currentTotal = [...workspaceContextFiles.values()].reduce((sum, item) => sum + item.content.length, 0);
    const previous = workspaceContextFiles.get(relative);
    if (!previous && workspaceContextFiles.size >= contextMaxFiles) return;
    if (currentTotal - (previous?.content.length || 0) + content.length > contextMaxTotalChars) return;
    workspaceContextFiles.set(relative, { path: relative, uri: document.uri, document, version: document.version, content });
  }

  function securityLanguageForUri(uri: vscode.Uri): 'python' | 'javascript' | 'dependencies' | undefined {
    const extension = path.extname(uri.fsPath).toLowerCase();
    if (extension === '.py') return 'python';
    if (['.js', '.jsx', '.mjs', '.cjs'].includes(extension)) return 'javascript';
    const basename = path.basename(uri.fsPath).toLowerCase();
    if (basename === 'package.json' || basename === 'pyproject.toml' || /^requirements.*\.txt$/.test(basename)) return 'dependencies';
    return undefined;
  }

  function isScannableWorkspaceUri(uri: vscode.Uri): boolean {
    const root = vscode.workspace.getWorkspaceFolder(uri);
    if (!root || !securityLanguageForUri(uri)) return false;
    const relative = path.relative(root.uri.fsPath, uri.fsPath);
    if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) return false;
    return !relative.split(/[\\/]/).some((part) => contextExcludedDirectories.has(part.toLowerCase()));
  }

  async function scanWorkspaceUri(uri: vscode.Uri): Promise<void> {
    const language = securityLanguageForUri(uri);
    if (!backendReady || !language || !isScannableWorkspaceUri(uri)) return;

    // Use the editor's current buffer when it is visible or unsaved. Otherwise read
    // from disk so context indexing cannot cause scans merely by opening documents.
    const openDocument = vscode.workspace.textDocuments.find((document) => document.uri.toString() === uri.toString());
    const visible = vscode.window.visibleTextEditors.some((editor) => editor.document.uri.toString() === uri.toString());
    if (openDocument && (visible || openDocument.isDirty)) {
      await scanDocument(openDocument);
      return;
    }

    const uriKey = uri.toString();
    const requestId = (scanRequestIds.get(uriKey) || 0) + 1;
    scanRequestIds.set(uriKey, requestId);
    try {
      const bytes = await vscode.workspace.fs.readFile(uri);
      if (bytes.byteLength > maxWorkspaceScanFileBytes || bytes.includes(0)) {
        workspaceScanOutput.appendLine(`[workspace] skipped oversized/binary file: ${uri.fsPath}`);
        if (scanRequestIds.get(uriKey) === requestId) {
          diagnosticCollection.delete(uri);
          findingsByUri.delete(uriKey);
          findingVersionsByUri.delete(uriKey);
        }
        return;
      }
      const code = new TextDecoder('utf-8').decode(bytes);
      const response = await fetch(`${backendUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ language, code, filename: uri.fsPath }),
      });
      if (!response.ok) throw new Error(`backend returned HTTP ${response.status}`);
      const result = await response.json() as { findings?: Finding[] };
      if (scanRequestIds.get(uriKey) !== requestId) return;

      const currentDocument = vscode.workspace.textDocuments.find((document) => document.uri.toString() === uriKey);
      if (currentDocument && (currentDocument.isDirty || currentDocument.getText() !== code)) {
        await scanDocument(currentDocument);
        return;
      }

      const findings = result.findings || [];
      const diagnostics = findings.map((finding) => {
        const range = new vscode.Range(
          Math.max(0, finding.line - 1), Math.max(0, finding.column),
          Math.max(0, finding.end_line - 1), Math.max(0, finding.end_column),
        );
        const severity = finding.severity === 'critical' || finding.severity === 'high'
          ? vscode.DiagnosticSeverity.Error
          : finding.severity === 'medium'
            ? vscode.DiagnosticSeverity.Warning
            : vscode.DiagnosticSeverity.Information;
        const diagnostic = new vscode.Diagnostic(range, `[${finding.severity.toUpperCase()}] ${finding.message}`, severity);
        diagnostic.source = 'Secure Coding';
        diagnostic.code = finding.rule_id;
        return diagnostic;
      });
      diagnosticCollection.set(uri, diagnostics);
      findingsByUri.set(uriKey, findings);
      // -1 marks disk-indexed diagnostics. Opening the file triggers a normal buffer
      // scan and replaces this with the document version before code actions are offered.
      findingVersionsByUri.set(uriKey, -1);
    } catch (error) {
      if (scanRequestIds.get(uriKey) === requestId) {
        workspaceScanOutput.appendLine(`[workspace] scan failed for ${uri.fsPath}: ${String(error)}`);
      }
    }
  }

  async function scanWorkspace(showSummary = false): Promise<void> {
    if (!backendReady) {
      if (showSummary) vscode.window.showWarningMessage('CodeShield backend is not ready yet. Try scanning the workspace again shortly.');
      return;
    }
    const scanGlobs = ['**/*.{py,js,jsx,mjs,cjs}', '**/package.json', '**/pyproject.toml', '**/requirements*.txt'];
    const uniqueFiles = new Map<string, vscode.Uri>();
    for (const glob of scanGlobs) {
      const remaining = maxWorkspaceScanFiles + 1 - uniqueFiles.size;
      if (remaining <= 0) break;
      const matches = await vscode.workspace.findFiles(glob, workspaceScanExcludeGlob, remaining);
      for (const uri of matches) uniqueFiles.set(uri.toString(), uri);
    }
    const files = [...uniqueFiles.values()];
    const limited = files.length > maxWorkspaceScanFiles;
    const targets = files.slice(0, maxWorkspaceScanFiles);
    let next = 0;
    let processed = 0;
    const worker = async () => {
      while (next < targets.length) {
        const uri = targets[next++];
        await scanWorkspaceUri(uri);
        processed++;
      }
    };
    await Promise.all(Array.from({ length: Math.min(3, targets.length) }, () => worker()));
    workspaceScanOutput.appendLine(`[workspace] processed ${processed} Python/JavaScript source file(s) and dependency manifest(s)${limited ? `; stopped at the ${maxWorkspaceScanFiles}-file safety limit` : ''}.`);
    if (showSummary) {
      vscode.window.showInformationMessage(
        `Workspace scan finished for ${processed} source file(s) and dependency manifest(s)${limited ? ` (limit: ${maxWorkspaceScanFiles}; narrow the workspace or excluded folders for full coverage)` : ''}. Findings are shown in VS Code's Problems panel.`,
      );
    }
  }

  function scheduleWorkspaceScan(uri: vscode.Uri): void {
    if (!isScannableWorkspaceUri(uri)) return;
    const openDocument = vscode.workspace.textDocuments.find((document) => document.uri.toString() === uri.toString());
    if (openDocument && (openDocument.isDirty || vscode.window.visibleTextEditors.some((editor) => editor.document.uri.toString() === uri.toString()))) return;
    const key = uri.toString();
    const existing = workspaceScanTimers.get(key);
    if (existing) clearTimeout(existing);
    workspaceScanTimers.set(key, setTimeout(() => {
      workspaceScanTimers.delete(key);
      void scanWorkspaceUri(uri);
    }, 600));
  }

  function clearWorkspaceFindings(uri: vscode.Uri): void {
    const key = uri.toString();
    const timer = workspaceScanTimers.get(key);
    if (timer) clearTimeout(timer);
    workspaceScanTimers.delete(key);
    scanRequestIds.set(key, (scanRequestIds.get(key) || 0) + 1);
    diagnosticCollection.delete(uri);
    findingsByUri.delete(key);
    findingVersionsByUri.delete(key);
  }

  function removeWorkspaceContext(uri: vscode.Uri): void {
    for (const [key, item] of workspaceContextFiles) {
      if (item.uri.toString() === uri.toString()) workspaceContextFiles.delete(key);
    }
  }

  function getRelatedWorkspaceContext(document: vscode.TextDocument): { path: string; content: string }[] {
    const currentPath = contextPathFor(document.uri) || '';
    const currentDir = path.posix.dirname(currentPath);
    const source = document.getText();
    const imports = new Set<string>();
    const identifiers = new Set<string>();
    if (document.languageId === 'python') {
      for (const match of source.matchAll(/^\s*(?:from\s+([A-Za-z0-9_.]+)\s+import|import\s+([A-Za-z0-9_.]+))/gm)) {
        const moduleName = match[1] || match[2];
        if (moduleName) imports.add(moduleName.replace(/\./g, '/').toLowerCase());
      }
    } else {
      for (const match of source.matchAll(/(?:from\s*|require\s*\()\s*['"]([^'"]+)['"]/g)) {
        if (match[1]?.startsWith('.')) imports.add(path.posix.normalize(path.posix.join(currentDir, match[1])).toLowerCase());
      }
    }
    // Include names actually used by this module. They help find project-local
    // conventions and imports even when this file has no explicit import yet.
    for (const match of source.matchAll(/\b[A-Za-z_$][\w$]{2,}\b/g)) {
      const identifier = match[0].toLowerCase();
      if (!['function', 'return', 'const', 'async', 'await', 'import', 'from', 'class', 'true', 'false', 'none', 'null', 'self', 'this', 'string', 'number', 'object', 'result', 'error', 'value', 'data'].includes(identifier)) {
        identifiers.add(identifier);
        if (identifiers.size >= 80) break;
      }
    }
    const currentBase = path.posix.basename(currentPath, path.posix.extname(currentPath)).toLowerCase();
    const ranked = [...workspaceContextFiles.values()]
      .filter((item) => item.uri.toString() !== document.uri.toString())
      .map((item) => {
        const candidate = item.path.toLowerCase();
        const candidateNoExt = candidate.replace(/\.(py|js|jsx|ts|tsx|html|css|sql|sh|ps1|java|cs|go|rs|php|rb|vue|svelte|yaml|yml|toml|ini|cfg|json)$/i, '');
        const basename = path.posix.basename(candidateNoExt);
        let score = contextConfigNames.has(path.posix.basename(candidate)) ? 2 : 0;
        if (candidate.startsWith(currentDir + '/') && ['.py', '.js'].includes(path.extname(candidate))) score += 1;
        if (basename === currentBase) score += 1;
        for (const imported of imports) {
          if (candidateNoExt === imported || candidateNoExt.endsWith('/' + imported) || basename === path.posix.basename(imported)) score += 10;
        }
        const candidateText = item.content.toLowerCase();
        const candidateIdentifiers = new Set(candidateText.match(/\b[A-Za-z_$][\w$]{2,}\b/g) || []);
        const symbolMatches = [...identifiers].reduce((count, identifier) => count + Number(candidateIdentifiers.has(identifier)), 0);
        // Rank files that establish imports/APIs used by the target above files
        // that happen to share only a folder name. Cap lexical matches so a
        // large general-purpose module cannot crowd out direct dependencies.
        score += Math.min(symbolMatches, 12);
        if (/^\s*from\s+flask\s+import\b/im.test(item.content) &&
            /\b(?:request|send_file|abort|jsonify|Flask)\b/.test(source)) score += 8;
        return { item, score };
      })
      .filter((entry) => entry.score > 0)
      .sort((a, b) => b.score - a.score || a.item.path.localeCompare(b.item.path));
    const selected: { path: string; content: string }[] = [];
    let total = 0;
    for (const { item } of ranked) {
      if (selected.length >= 8 || total >= 18000) break;
      // The backend enforces a 6,000-character per-file limit. Match it here
      // and keep useful headers/imports plus excerpts around target symbols so
      // large files are not silently discarded by the backend.
      const content = contextExcerpt(item.content, identifiers, Math.min(6000, 18000 - total));
      if (!content) continue;
      selected.push({ path: item.path, content });
      total += content.length;
    }
    return selected;
  }

  function contextExcerpt(content: string, identifiers: Set<string>, limit: number): string {
    if (content.length <= limit) return content;
    const lines = content.split(/\r?\n/);
    const keep = new Set<number>();
    // Always retain file-level imports and a short header, which reveal the
    // framework, available helpers, and module contract.
    for (let index = 0; index < Math.min(lines.length, 60); index += 1) {
      if (index < 8 || /^\s*(?:import\s|from\s+\S+\s+import\b|const\s+\w+\s*=\s*require\s*\()/.test(lines[index])) keep.add(index);
    }
    const rankedLines = lines.map((line, index) => {
      const lineIdentifiers = new Set(line.toLowerCase().match(/\b[A-Za-z_$][\w$]{2,}\b/g) || []);
      const score = [...identifiers].reduce((count, identifier) => count + Number(lineIdentifiers.has(identifier)), 0);
      return { index, score };
    }).filter((entry) => entry.score > 0).sort((a, b) => b.score - a.score || a.index - b.index);
    let retainedChars = [...keep].reduce((sum, line) => sum + lines[line].length + 1, 0);
    for (const { index } of rankedLines) {
      for (let line = Math.max(0, index - 2); line <= Math.min(lines.length - 1, index + 2); line += 1) {
        if (keep.has(line)) continue;
        keep.add(line);
        retainedChars += lines[line].length + 1;
      }
      if (retainedChars >= limit) break;
    }
    const ordered = [...keep].sort((a, b) => a - b);
    let excerpt = '';
    let previous = -2;
    for (const index of ordered) {
      const part = `${index > previous + 1 ? '\n…\n' : ''}${lines[index]}\n`;
      if (excerpt.length + part.length > limit) continue;
      excerpt += part;
      previous = index;
    }
    return excerpt.trim();
  }

  async function confirmProjectContextForCloudFix(
    files: { path: string; content: string }[],
  ): Promise<{ files: { path: string; content: string }[]; cancelled: boolean }> {
    const provider = getAiConfig().get<string>('aiProvider', 'ollama');
    if (provider === 'ollama' || files.length === 0) return { files, cancelled: false };
    const fileList = files.map((file) => file.path).slice(0, 8).join(', ');
    const choice = await vscode.window.showInformationMessage(
      `To improve this AI fix, these related workspace files may be sent with the selected code to ${provider}: ${fileList}. Common credential assignments, private-key blocks, and URL credentials are redacted automatically, but redaction is not exhaustive. The local context cache does not send or scan files.`,
      { modal: true },
      'Include Project Context',
      'Use Current File Only',
    );
    if (!choice) return { files: [], cancelled: true };
    const include = choice === 'Include Project Context';
    return { files: include ? files : [], cancelled: false };
  }
  async function scanDocument(document: vscode.TextDocument): Promise<void> {
    if (!backendReady) return;
    const language = securityLanguageForUri(document.uri);
    console.log(`[Secure Coding] scanDocument called for ${document.fileName}, language=${language}`);
    if (!language) {
      console.log('[Secure Coding] skipped, unsupported language');
      return;
    }

    const code = document.getText();
    const uriKey = document.uri.toString();
    const version = document.version;
    const requestId = (scanRequestIds.get(uriKey) || 0) + 1;
    scanRequestIds.set(uriKey, requestId);
    console.log(`[Secure Coding] sending ${code.length} chars to ${backendUrl}/scan`);
    try {
      const response = await fetch(`${backendUrl}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ language, code, filename: document.fileName }),
      });

      console.log(`[Secure Coding] response status=${response.status}`);
      if (!response.ok) {
        if (scanRequestIds.get(uriKey) === requestId && document.version === version) {
          diagnosticCollection.delete(document.uri);
          findingsByUri.delete(uriKey);
          findingVersionsByUri.delete(uriKey);
          statusBarItem!.tooltip = `Scan failed: backend returned HTTP ${response.status}`;
        }
        return;
      }

      const result = (await response.json()) as { findings: Finding[] };
      if (scanRequestIds.get(uriKey) !== requestId || document.version !== version || document.isClosed) {
        return;
      }
      const findings: Finding[] = result.findings || [];
      console.log(`[Secure Coding] findings=${findings.length}`, result);

      const diagnostics: vscode.Diagnostic[] = findings.map((f) => {
        const startLine = Math.max(0, f.line - 1);
        const endLine = Math.max(0, f.end_line - 1);
        const range = new vscode.Range(
          startLine,
          Math.max(0, f.column),
          endLine,
          Math.max(0, f.end_column),
        );
        const severity =
          f.severity === 'critical' || f.severity === 'high'
            ? vscode.DiagnosticSeverity.Error
            : f.severity === 'medium'
              ? vscode.DiagnosticSeverity.Warning
              : vscode.DiagnosticSeverity.Information;

        const diag = new vscode.Diagnostic(range, `[${f.severity.toUpperCase()}] ${f.message}`, severity);
        diag.source = 'Secure Coding';
        diag.code = f.rule_id;
        return diag;
      });

      diagnosticCollection.set(document.uri, diagnostics);
      console.log(`[Secure Coding] set ${diagnostics.length} diagnostics for ${document.uri.toString()}`);
      findingsByUri.set(uriKey, findings);
      findingVersionsByUri.set(uriKey, version);
      updateStatusBar(findings);
    } catch (error) {
      console.error(`[Secure Coding] Scan failed: ${error}`);
      if (scanRequestIds.get(uriKey) === requestId && document.version === version && !document.isClosed) {
        diagnosticCollection.delete(document.uri);
        findingsByUri.delete(uriKey);
        findingVersionsByUri.delete(uriKey);
        statusBarItem!.tooltip = 'Scan failed. Check that the backend is running, then scan again.';
      }
    }
  }

  function updateStatusBar(findings: Finding[]) {
    const critical = findings.filter((f) => f.severity === 'critical').length;
    const high = findings.filter((f) => f.severity === 'high').length;
    const medium = findings.filter((f) => f.severity === 'medium').length;
    const low = findings.filter((f) => f.severity === 'low').length;

    const total = critical + high + medium + low;
    statusBarItem!.text = `$(shield) File: ${total}`;
    statusBarItem!.tooltip = `CodeShield findings for the active file: ${total}\nCritical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}\nThis rule-based scan covers selected patterns; it is not a security certification.`;
    statusBarItem!.show();
  }

  // Scan on text change (debounced)
  const changeListener = vscode.workspace.onDidChangeTextDocument((event) => {
    const document = event.document;
    updateWorkspaceContext(document);
    if (!securityLanguageForUri(document.uri)) {
      return;
    }

    const key = document.uri.toString();
    const existingTimer = debounceTimers.get(key);
    if (existingTimer) clearTimeout(existingTimer);
    debounceTimers.set(key, setTimeout(() => {
      debounceTimers.delete(key);
      void scanDocument(document);
    }, 450));
  });

  const closeListener = vscode.workspace.onDidCloseTextDocument((document) => {
    const key = document.uri.toString();
    const timer = debounceTimers.get(key);
    if (timer) clearTimeout(timer);
    debounceTimers.delete(key);
    if (isScannableWorkspaceUri(document.uri)) {
      // Keep workspace findings visible after the editor closes, and refresh them
      // from disk in case the user saved while closing.
      findingVersionsByUri.set(key, -1);
      scheduleWorkspaceScan(document.uri);
    } else {
      scanRequestIds.delete(key);
      findingsByUri.delete(key);
      findingVersionsByUri.delete(key);
      diagnosticCollection.delete(document.uri);
    }
  });

  const openListener = vscode.workspace.onDidOpenTextDocument((document) => {
    updateWorkspaceContext(document);
  });
  const activeEditorListener = vscode.window.onDidChangeActiveTextEditor((editor) => {
    if (editor && securityLanguageForUri(editor.document.uri)) {
      void scanDocument(editor.document);
    }
  });

  // Scan on save
  const saveListener = vscode.workspace.onDidSaveTextDocument((document) => {
    void scanDocument(document);
    updateWorkspaceContext(document);
  });
  const workspaceFolderListener = vscode.workspace.onDidChangeWorkspaceFolders(() => {
    workspaceContextRefresh = refreshWorkspaceContext();
    void scanWorkspace();
  });
  const contextWatcher = vscode.workspace.createFileSystemWatcher('**/*.{py,js,jsx,ts,tsx,html,css,sql,sh,ps1,java,cs,go,rs,php,rb,vue,svelte,json,toml,yaml,yml,ini,cfg,txt,xml,gradle,mod,lock}');
  const contextCreateListener = contextWatcher.onDidCreate((uri) => {
    void vscode.workspace.openTextDocument(uri).then(updateWorkspaceContext, () => undefined);
  });
  const contextChangeListener = contextWatcher.onDidChange((uri) => {
    void vscode.workspace.openTextDocument(uri).then(updateWorkspaceContext, () => undefined);
  });
  const contextDeleteListener = contextWatcher.onDidDelete((uri) => removeWorkspaceContext(uri));
  const securityWatcher = vscode.workspace.createFileSystemWatcher(
    '**/{*.py,*.js,*.jsx,*.mjs,*.cjs,package.json,pyproject.toml,requirements*.txt}',
  );
  const securityCreateListener = securityWatcher.onDidCreate(scheduleWorkspaceScan);
  const securityChangeListener = securityWatcher.onDidChange(scheduleWorkspaceScan);
  const securityDeleteListener = securityWatcher.onDidDelete(clearWorkspaceFindings);

  // Scan current file command
  const scanCommand = vscode.commands.registerCommand('secureCoding.scanCurrentFile', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('No active editor');
      return;
    }
    await scanDocument(editor.document);
    vscode.window.showInformationMessage('Scan complete');
  });
  const scanWorkspaceCommand = vscode.commands.registerCommand('secureCoding.scanWorkspace', async () => {
    await scanWorkspace(true);
  });
  // FR-04: 1-click Quick Fix — lightbulb action on every diagnostic
  const quickFixProvider = vscode.languages.registerCodeActionsProvider(
    ['python', 'javascript'],
    {
      provideCodeActions(document, range, ctx) {
        if (findingVersionsByUri.get(document.uri.toString()) !== document.version) {
          return [];
        }
        const actions: vscode.CodeAction[] = [];
        for (const d of ctx.diagnostics) {
          if (d.source !== 'Secure Coding') {
            continue;
          }
          const ruleId = String(d.code || '');
          if (ruleId.startsWith('DEP-')) {
            // Dependency findings are handled by the separate manifest provider.
            continue;
          }
          // Rule-based instant fix (no AI round-trip)
          const replacementRange = expandedFixRange(document, ruleId, d.range);
          const codeSnippet = document.getText(replacementRange);
          const template = templateFix(document.languageId, d.message, ruleId, codeSnippet, document.getText());
          if (template) {
            const a = new vscode.CodeAction(
              `⚡ Quick Fix: ${ruleId}`,
              vscode.CodeActionKind.QuickFix,
            );
            a.diagnostics = [d];
            a.isPreferred = true;
            a.edit = new vscode.WorkspaceEdit();
            a.edit.replace(document.uri, replacementRange, indentReplacement(document, replacementRange, template));
            actions.push(a);
          }
          // AI fix via backend (O-02 bounded context)
          const ai = new vscode.CodeAction(
            `🤖 AI Fix (any finding): ${ruleId}`,
            vscode.CodeActionKind.QuickFix,
          );
          ai.diagnostics = [d];
          ai.command = {
            command: 'secureCoding.fixDiagnostic',
            title: 'Fix with AI',
            arguments: [
              document.uri.toString(),
              ruleId,
              {
                startLine: d.range.start.line,
                startCharacter: d.range.start.character,
                endLine: d.range.end.line,
                endCharacter: d.range.end.character,
              },
            ],
          };
          actions.push(ai);
        }
        return actions;
      },
    },
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
  );

  // Manifest fixes can read lock files asynchronously. Keep that I/O out of
  // Python/JavaScript code-action requests so source quick fixes appear at once.
  const dependencyQuickFixProvider = vscode.languages.registerCodeActionsProvider(
    ['json', 'jsonc', 'toml', 'plaintext'],
    {
      async provideCodeActions(document, _range, ctx) {
        if (findingVersionsByUri.get(document.uri.toString()) !== document.version) return [];
        const actions: vscode.CodeAction[] = [];
        for (const diagnostic of ctx.diagnostics) {
          if (diagnostic.source !== 'Secure Coding' || !String(diagnostic.code || '').startsWith('DEP-')) continue;
          const finding = findingForDiagnostic(document, diagnostic);
          const dependencyFix = finding ? await dependencyManifestFix(document, finding) : undefined;
          if (findingVersionsByUri.get(document.uri.toString()) !== document.version) return [];
          if (!dependencyFix) continue;
          const ruleId = String(diagnostic.code || '');
          const action = new vscode.CodeAction(
            `⚡ Quick Fix: Pin ${ruleId === 'DEP-SOURCE-001' ? 'dependency source' : 'dependency version'} from lock file`,
            vscode.CodeActionKind.QuickFix,
          );
          action.diagnostics = [diagnostic];
          action.isPreferred = true;
          action.edit = new vscode.WorkspaceEdit();
          action.edit.replace(document.uri, dependencyFix.range, dependencyFix.text);
          actions.push(action);
        }
        return actions;
      },
    },
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
  );

  // Resolve a diagnostic + full source, then reuse the AI flow
  const fixDiagnosticCmd = vscode.commands.registerCommand(
    'secureCoding.fixDiagnostic',
    async (uriStr: string, ruleId: string, target?: {
      startLine: number; startCharacter: number; endLine: number; endCharacter: number;
    }) => {
      const uri = vscode.Uri.parse(uriStr);
      const editor = vscode.window.visibleTextEditors.find(
        (e) => e.document.uri.toString() === uriStr,
      );
      const doc = editor?.document ?? (await vscode.workspace.openTextDocument(uri));
      if (findingVersionsByUri.get(uriStr) !== doc.version) {
        vscode.window.showInformationMessage('The file changed since its last scan. Rescanning before fixing.');
        await scanDocument(doc);
        return;
      }
      const diagnostic = (diagnosticCollection.get(uri) || []).find((d) =>
        String(d.code) === ruleId && target &&
        d.range.start.line === target.startLine && d.range.start.character === target.startCharacter &&
        d.range.end.line === target.endLine && d.range.end.character === target.endCharacter,
      );
      if (!diagnostic) {
        vscode.window.showWarningMessage(`The selected ${ruleId} finding is no longer available. Scan the file again.`);
        return;
      }
      const finding = findingForDiagnostic(doc, diagnostic);
      if (!finding) {
        vscode.window.showErrorMessage('Finding details are out of date. Scan the file again.');
        return;
      }
      if (!(await ensureAiReady(doc, diagnostic))) return;
      const baselineDiagnostics = diagnosticCollection.get(doc.uri) || [];
      await workspaceContextRefresh;
      if (findingVersionsByUri.get(uriStr) !== doc.version) {
        vscode.window.showWarningMessage('The file changed while workspace context was being prepared. Rescanning before fixing.');
        await scanDocument(doc);
        return;
      }
      const relatedProjectFiles = getRelatedWorkspaceContext(doc);
      const contextChoice = await confirmProjectContextForCloudFix(relatedProjectFiles);
      if (contextChoice.cancelled) return;
      await applyAiFix(doc, diagnostic, finding, backendUrl, () => scanDocument(doc), suggestAlternativeModels, baselineDiagnostics, contextChoice.files);
    },
  );
  const fixCommand = vscode.commands.registerCommand('secureCoding.fixWithAI', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('No active editor');
      return;
    }
    if (editor.document.languageId !== 'python' && editor.document.languageId !== 'javascript') {
      vscode.window.showInformationMessage('AI Fix currently supports Python and JavaScript source. Dependency warnings can be fixed automatically only when a lock file supplies an exact reviewed pin.');
      return;
    }

    const selection = editor.selection;
    const document = editor.document;
    const diagnostics = diagnosticCollection.get(document.uri) || [];
    if (findingVersionsByUri.get(document.uri.toString()) !== document.version) {
      vscode.window.showInformationMessage('The file changed since its last scan. Rescanning before fixing.');
      await scanDocument(document);
      return;
    }

    const selectedDiagnostics = diagnostics.filter((d) => {
      const range = d.range;
      return range.contains(selection.start) || range.contains(selection.end);
    });

    if (selectedDiagnostics.length === 0) {
      vscode.window.showWarningMessage('No vulnerabilities found at the cursor position');
      return;
    }

    let diagnostic = selectedDiagnostics[0];
    if (selectedDiagnostics.length > 1) {
      const choice = await vscode.window.showQuickPick(
        selectedDiagnostics.map((item) => ({
          label: String(item.code || 'Finding'),
          description: `Line ${item.range.start.line + 1}: ${item.message}`,
          diagnostic: item,
        })),
        { placeHolder: 'Choose the single finding to send for an AI fix' },
      );
      if (!choice) return;
      diagnostic = choice.diagnostic;
    }
    const finding = findingForDiagnostic(document, diagnostic);
    if (!finding) {
      vscode.window.showErrorMessage('Finding details are out of date. Scan the file again.');
      return;
    }
    if (!(await ensureAiReady(document, diagnostic))) return;
    const baselineDiagnostics = diagnosticCollection.get(document.uri) || [];
    await workspaceContextRefresh;
    if (findingVersionsByUri.get(document.uri.toString()) !== document.version) {
      vscode.window.showWarningMessage('The file changed while workspace context was being prepared. Rescanning before fixing.');
      await scanDocument(document);
      return;
    }
    const relatedProjectFiles = getRelatedWorkspaceContext(document);
    const contextChoice = await confirmProjectContextForCloudFix(relatedProjectFiles);
    if (contextChoice.cancelled) return;
    await applyAiFix(document, diagnostic, finding, backendUrl, () => scanDocument(document), suggestAlternativeModels, baselineDiagnostics, contextChoice.files);
  });

  // Security score command
  const scoreCommand = vscode.commands.registerCommand('secureCoding.showSecurityScore', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage('Open a Python or JavaScript file to see CodeShield findings.');
      return;
    }
    const diagnostics = diagnosticCollection.get(editor.document.uri) || [];
    updateStatusBar(diagnosticsToFindings(diagnostics));
    const score = statusBarItem.text || 'No scan yet';
    const tooltipText = typeof statusBarItem.tooltip === 'string' ? statusBarItem.tooltip : '';
    vscode.window.showInformationMessage(`Current file scan: ${score}`, { detail: tooltipText });
  });

  // Hover provider
  const hoverProvider = vscode.languages.registerHoverProvider(['python', 'javascript'], {
    provideHover(document, position) {
      const diagnostics = diagnosticCollection.get(document.uri) || [];
      const relevant = diagnostics.filter((d) => d.range.contains(position));

      if (relevant.length === 0) {
        return null;
      }

      const findings = findingsByUri.get(document.uri.toString()) || [];
      const markdown = new vscode.MarkdownString();
      markdown.isTrusted = true;
      markdown.appendMarkdown('## Secure Coding Findings\n\n');

      relevant.forEach((d) => {
        const sev = d.severity === vscode.DiagnosticSeverity.Error ? '❌' : '⚠️';
        const matched = findings.find((f) => f.rule_id === d.code);
        const owasp = matched ? matched.owasp_ref : 'N/A';
        const owasp2021 = matched ? matched.owasp_2021_ref || 'N/A' : 'N/A';
        const cwe = matched ? matched.cwe_id : 'N/A';
        const suggestion = matched ? matched.suggestion : 'N/A';
        markdown.appendMarkdown(`${sev} **${d.code}**: ${d.message}\n\n`);
        markdown.appendMarkdown(`> OWASP 2025: ${owasp} | OWASP 2021: ${owasp2021} | CWE: ${cwe}\n\n`);
        markdown.appendMarkdown(`💡 **Suggestion:** ${suggestion}\n\n`);
      });

      return new vscode.Hover(markdown);
    },
  });

  context.subscriptions.push(
    changeListener,
    closeListener,
    openListener,
    activeEditorListener,
    saveListener,
    workspaceFolderListener,
    scanCommand,
    scanWorkspaceCommand,
    fixCommand,
    fixDiagnosticCmd,
    quickFixProvider,
    dependencyQuickFixProvider,
    scoreCommand,
    vscode.commands.registerCommand('secureCoding.showBackendLog', () => backend.showLog()),
    vscode.commands.registerCommand('secureCoding.installLocalAI', async () => {
      const providerOptions = [
          { label: 'Ollama', description: 'Run locally; code stays on this machine.', provider: 'ollama' },
          { label: 'Groq Free Tier', description: 'Free-plan inference, subject to provider limits.', provider: 'groq' },
          { label: 'Gemini Free Tier', description: 'Free-tier model; review Google data terms.', provider: 'gemini' },
          { label: 'OpenRouter Free Models', description: 'Free models only; requests are rate-limited.', provider: 'openrouter' },
          { label: 'Custom OpenAI-compatible API', description: 'Your endpoint, model, and API key; may incur charges.', provider: 'custom' },
          { label: 'Open Ollama website', description: 'Download Ollama.', provider: 'open-ollama' },
        ];
      const choices = await Promise.all(providerOptions.map(async (option) => {
        if (option.provider === 'ollama' || option.provider === 'open-ollama') return option;
        const savedKey = await promptForCloudKey(option.provider);
        if (!savedKey) return option;
        const modelLabel = option.provider === 'custom'
          ? getAiConfig().get<string>('aiModel', 'Configured custom model')
          : cloudProviders[option.provider]?.models.map((model) => model.label).join(', ');
        return {
          ...option,
          description: `API key saved · ${modelLabel || 'model configured'} · ${option.description}`,
        };
      }));
      const choice = await vscode.window.showQuickPick(choices, { placeHolder: 'Choose an AI provider' });
      if (!choice) return;
      if (choice.provider === 'open-ollama') {
        await vscode.env.openExternal(vscode.Uri.parse('https://ollama.com/download'));
        return;
      }

      if (choice.provider === 'ollama') {
        // Query Ollama each time this picker opens so newly pulled tags appear without
        // requiring an extension update. Keep the prepared models as pullable fallbacks.
        const installedModels = await backend.listOllamaModels();
        const preparedModels = [
          { model: 'qwen2.5-coder:1.5b-instruct', description: 'Small, fast local model · download if needed' },
          { model: 'codellama:7b-instruct', description: 'Larger local model · download if needed' },
        ];
        const installedChoices = installedModels.map((model) => ({
          label: model,
          description: 'Installed in Ollama',
          installed: true,
        }));
        const preparedChoices = preparedModels
          .filter(({ model }) => !installedModels.some((installed) => installed.toLowerCase() === model.toLowerCase()))
          .map(({ model, description }) => ({ label: model, description, installed: false }));
        const selectedModel = await vscode.window.showQuickPick(
          [...installedChoices, ...preparedChoices],
          {
            placeHolder: installedModels.length
              ? 'Select an installed Ollama model or a prepared model to download'
              : 'No Ollama models detected; select a prepared model to download',
            matchOnDescription: true,
          },
        );
        if (!selectedModel) return;
        await getAiConfig().update('aiProvider', 'ollama', vscode.ConfigurationTarget.Global);
        await getAiConfig().update('aiModel', selectedModel.label, vscode.ConfigurationTarget.Global);
        if (selectedModel.installed) {
          await backend.checkOllama();
          aiStatusBarItem.text = backend.isOllamaModelAvailable()
            ? '$(check) AI: Ollama'
            : '$(warning) AI: Ollama';
          aiStatusBarItem.tooltip = backend.isOllamaModelAvailable()
            ? `Ollama model ${selectedModel.label} is ready.`
            : `Could not confirm ${selectedModel.label}. Check that Ollama is running.`;
          if (backend.isOllamaModelAvailable()) {
            vscode.window.showInformationMessage(`Selected installed Ollama model ${selectedModel.label}.`);
          } else {
            vscode.window.showWarningMessage(`Could not connect to Ollama or find ${selectedModel.label}. Check that Ollama is running.`);
          }
        } else {
          startOllamaPull(selectedModel.label);
        }
        return;
      }

      const isCustom = choice.provider === 'custom';
      const disclosure = await vscode.window.showInformationMessage(
        'Cloud AI sends the selected finding and current-file context to the chosen API. Related workspace files are shared only after a separate prompt when you request an AI fix. Your API key is stored in VS Code SecretStorage. Providers apply their own data-use terms; free-tier Google AI Studio content may be used to improve Google products.',
        { modal: true },
        'Continue',
      );
      if (disclosure !== 'Continue') return;

      let apiBase = '';
      if (isCustom) {
        const enteredBase = await vscode.window.showInputBox({
          prompt: 'Enter the OpenAI-compatible API base URL (for example, https://host.example/v1)',
          value: getAiConfig().get<string>('cloudApiBase', ''),
          ignoreFocusOut: true,
          validateInput: (value) => {
            try {
              const parsed = new URL(value);
              if (!['http:', 'https:'].includes(parsed.protocol)) return 'Use an HTTP(S) URL';
              if (parsed.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)) {
                return 'Use HTTPS for remote endpoints';
              }
              if (parsed.username || parsed.password || parsed.search || parsed.hash) return 'Do not include credentials, query, or fragment';
              return undefined;
            } catch {
              return 'Enter a valid absolute URL';
            }
          },
        });
        if (!enteredBase) return;
        apiBase = enteredBase.replace(/\/$/, '');
      }

      const provider = choice.provider;
      let apiKey = await promptForCloudKey(provider);
      if (apiKey) {
        const keyChoice = await vscode.window.showQuickPick(
          [
            { label: 'Use saved API key', description: `Reuse the key securely saved for ${choice.label}.` },
            { label: 'Replace saved API key', description: 'Enter a new key and replace the saved one.' },
          ],
          { placeHolder: `${choice.label} API key is already saved` },
        );
        if (!keyChoice) return;
        if (keyChoice.label === 'Replace saved API key') apiKey = undefined;
      }
      if (!apiKey) {
        const enteredKey = await vscode.window.showInputBox({
          prompt: `Enter your ${choice.label} API key`,
          password: true,
          ignoreFocusOut: true,
          validateInput: (value) => value.trim() ? undefined : 'An API key is required',
        });
        if (!enteredKey?.trim()) return;
        apiKey = enteredKey.trim();
      }

      let model: string;
      if (isCustom) {
        const enteredModel = await vscode.window.showInputBox({
          prompt: 'Enter the model ID supported by this API. This endpoint may charge for usage.',
          value: getAiConfig().get<string>('aiModel', ''),
          ignoreFocusOut: true,
          validateInput: (value) => value.trim() ? undefined : 'A model ID is required',
        });
        if (!enteredModel?.trim()) return;
        model = enteredModel.trim();
      } else {
        const selectedModel = await vscode.window.showQuickPick(cloudProviders[provider].models, {
          placeHolder: `Choose a free ${cloudProviders[provider].label} model`,
        });
        if (!selectedModel) return;
        model = selectedModel.label;
      }

      await secretStorage?.store(secretKeyFor(provider), apiKey.trim());
      await getAiConfig().update('aiProvider', provider, vscode.ConfigurationTarget.Global);
      await getAiConfig().update('aiModel', model, vscode.ConfigurationTarget.Global);
      await getAiConfig().update('cloudApiBase', isCustom ? apiBase : '', vscode.ConfigurationTarget.Global);
      aiStatusBarItem.text = `$(cloud) AI: ${choice.label}`;
      aiStatusBarItem.tooltip = `Cloud AI selected: ${choice.label}. Code context is sent to this provider when you request a fix. Click to change providers.`;
      vscode.window.showInformationMessage(`${choice.label} configured. Cloud AI will be used for requested fixes.`);
    }),
    vscode.commands.registerCommand('secureCoding.fixAllFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('No active editor');
        return;
      }
      await fixAllFile(editor.document, diagnosticCollection, findingsByUri, findingVersionsByUri, () => scanDocument(editor.document));
    }),
    hoverProvider,
    contextWatcher,
    contextCreateListener,
    contextChangeListener,
    contextDeleteListener,
    securityWatcher,
    securityCreateListener,
    securityChangeListener,
    securityDeleteListener,
    { dispose: () => {
      for (const timer of workspaceScanTimers.values()) clearTimeout(timer);
      workspaceScanTimers.clear();
    } },
  );

  // A1: ensure backend is up before first scan (bundled exe, zero terminal)
  void (async () => {
    const ok = await backend.ensureRunning(context, statusBarItem!);
    backendReady = ok;
    statusBarItem!.text = ok ? '🔒 CodeShield' : '🔒 CodeShield (offline)';
    const selectedProvider = getAiConfig().get<string>('aiProvider', 'ollama');
    if (selectedProvider === 'ollama') {
      aiStatusBarItem.text = backend.ollamaStatusText();
      aiStatusBarItem.tooltip = backend.isOllamaModelAvailable()
        ? 'Local AI ready — click to configure AI'
        : 'Local AI not available — click to configure AI';
    } else {
      const hasKey = Boolean(await promptForCloudKey(selectedProvider));
      const providerLabel = cloudProviders[selectedProvider]?.label || 'Custom API';
      aiStatusBarItem.text = hasKey ? `$(cloud) AI: ${providerLabel}` : `$(warning) AI: ${providerLabel}`;
      aiStatusBarItem.tooltip = hasKey
        ? `Cloud AI selected: ${providerLabel}. Code context is sent when you request a fix.`
        : `No API key saved for ${providerLabel}. Click to configure AI.`;
    }
    if (ok) {
      const activeEditor = vscode.window.activeTextEditor;
      if (activeEditor) {
        void scanDocument(activeEditor.document);
      }
      workspaceContextRefresh = refreshWorkspaceContext();
      void scanWorkspace();
    }
  })();

  // Scan active file on activation (after backend ready, see above)
}

function findingsToRequest(
  diagnostic: vscode.Diagnostic,
  document: vscode.TextDocument,
): { findingData: { rule_id: string; title: string; severity: string; cwe_id: string; owasp_ref: string; owasp_2021_ref: string; language: string; code_snippet: string; context: any }; range: vscode.Range } | null {
  const range = diagnostic.range;
  const codeSnippet = document.getText(range);

  const findingData = {
    rule_id: diagnostic.code as string,
    title: (diagnostic as any).title || 'Vulnerability',
    severity: diagnostic.severity === vscode.DiagnosticSeverity.Error ? 'critical' : 'medium',
    cwe_id: 'N/A',
    owasp_ref: 'N/A',
    owasp_2021_ref: 'N/A',
    language: document.languageId,
    code_snippet: codeSnippet,
    context: {},
  };

  return { findingData, range };
}

async function requestSuggestion(findingData: {
  rule_id: string;
  title: string;
  severity: string;
  cwe_id: string;
  owasp_ref: string;
  owasp_2021_ref: string;
  language: string;
  code_snippet: string;
  context: any;
}, backendUrl: string): Promise<SuggestionResponse> {
  const provider = vscode.workspace.getConfiguration('secureCoding').get<string>('aiProvider', 'ollama');
  const savedKey = provider === 'ollama'
    ? 'ollama'
    : await secretStorage?.get(secretKeyFor(provider));
  const aiConfig = {
    ...findingData.context,
    ai_api_base: vscode.workspace.getConfiguration('secureCoding').get<string>('aiApiBase', 'http://localhost:11434/v1'),
    ai_api_key: savedKey ?? '',
    ai_model: vscode.workspace.getConfiguration('secureCoding').get<string>('aiModel', 'qwen2.5-coder:1.5b-instruct'),
    ai_provider: provider,
    cloud_api_base: provider === 'custom'
      ? vscode.workspace.getConfiguration('secureCoding').get<string>('cloudApiBase', '')
      : '',
  };

  const response = await fetch(`${backendUrl}/suggest-fix`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...findingData, context: aiConfig }),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => 'Unknown error');
    const unavailableStatus = text.match(/\b(502|503|504)\b/)?.[1];
    if (unavailableStatus) {
      throw new Error(`The selected AI provider is temporarily unavailable (HTTP ${unavailableStatus}). No fix was generated. Try again later or choose another configured provider.`);
    }
    if (/\b429\b/.test(text)) {
      throw new Error('The selected AI provider rate limit was reached (HTTP 429). No fix was generated. Wait and try again later.');
    }
    throw new Error(`AI request failed: ${response.status} ${text}`);
  }

  const data = (await response.json()) as SuggestionResponse;
  if (!data.secure_code) {
    return data;
  }

  return data;
}

function diagnosticsToFindings(diagnostics: readonly vscode.Diagnostic[]): Finding[] {
  return diagnostics.map((d) => ({
    rule_id: d.code as string,
    title: (d as any).title || 'Vulnerability',
    severity: d.severity === vscode.DiagnosticSeverity.Error ? 'critical' : 'medium',
    cwe_id: (d as any).cwe_id || 'N/A',
    owasp_ref: (d as any).owasp_ref || 'N/A',
    owasp_2021_ref: (d as any).owasp_2021_ref || 'N/A',
    message: d.message,
    line: d.range.start.line + 1,
    column: d.range.start.character,
    end_line: d.range.end.line + 1,
    end_column: d.range.end.character,
    suggestion: (d as any).suggestion || '',
    code_snippet: '',
  }));
}

// FR-04: Fix All Current File — applies every rule-based template fix at once
async function fixAllFile(
  document: vscode.TextDocument,
  diagnosticCollection: vscode.DiagnosticCollection,
  findingsByUri: Map<string, Finding[]>,
  findingVersionsByUri: Map<string, number>,
  rescan: () => void | Promise<void>,
): Promise<void> {
  const uriKey = document.uri.toString();
  if (findingVersionsByUri.get(uriKey) !== document.version) {
    vscode.window.showInformationMessage('The file changed since its last scan. Rescanning before Fix All.');
    await rescan();
    return;
  }
  const findings = findingsByUri.get(document.uri.toString()) || [];

  // Deduplicate findings by line+column+rule_id to avoid overlapping edits
  const seen = new Set<string>();
  const uniqueFindings = findings.filter((d) => {
    const key = d.line + ':' + d.column + ':' + d.rule_id;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const source = document.getText();
  const sourceVersion = document.version;
  // Collect replacements as (startLine, startChar, endLine, endChar, newText)
  type Replacement = { sl: number; sc: number; el: number; ec: number; text: string };
  const replacements: Replacement[] = [];

  for (const d of uniqueFindings) {
    const ruleId = String(d.rule_id || '');
    if (ruleId.startsWith('DEP-')) {
      const dependencyFix = await dependencyManifestFix(document, d);
      if (dependencyFix) {
        replacements.push({
          sl: dependencyFix.range.start.line,
          sc: dependencyFix.range.start.character,
          el: dependencyFix.range.end.line,
          ec: dependencyFix.range.end.character,
          text: dependencyFix.text,
        });
      }
      continue;
    }
    // Extract code snippet from document if not in findings
    const findingRange = new vscode.Range(
      new vscode.Position(d.line - 1, d.column),
      new vscode.Position(d.end_line - 1, d.end_column),
    );
    const range = expandedFixRange(document, ruleId, findingRange);
    const snippet = document.getText(range);
    const template = templateFix(document.languageId, d.message, ruleId, snippet, source);
    if (template) {
      replacements.push({
        sl: range.start.line,
        sc: range.start.character,
        el: range.end.line,
        ec: range.end.character,
        text: template,
      });
    }
  }

  if (replacements.length === 0) {
    const hasDependencyFindings = uniqueFindings.some((finding) => String(finding.rule_id || '').startsWith('DEP-'));
    vscode.window.showInformationMessage(hasDependencyFindings
      ? `No safe dependency pin was found in a lock file. ${uniqueFindings.length} finding(s) remain; review the dependency and choose an exact trusted version or immutable source manually.`
      : `No supported rule-based fixes are available. ${uniqueFindings.length} finding(s) remain for individual AI or manual review.`);
    return;
  }

  const edit = new vscode.WorkspaceEdit();
  // VS Code applies original-coordinate edits atomically. Reject overlaps so one
  // finding can never overwrite another finding's replacement.
  const ordered = [...replacements].sort((a, b) => a.sl - b.sl || a.sc - b.sc || a.el - b.el || a.ec - b.ec);
  for (let i = 1; i < ordered.length; i++) {
    const previous = ordered[i - 1];
    const current = ordered[i];
    if (current.sl < previous.el || (current.sl === previous.el && current.sc < previous.ec)) {
      vscode.window.showWarningMessage('Some findings overlap. No Fix All edits were applied; use individual fixes instead.');
      return;
    }
  }

  const skippedCount = uniqueFindings.length - ordered.length;
  const proceed = await vscode.window.showInformationMessage(
    `Fix All will apply ${ordered.length} supported rule-based or lockfile-backed fix(es) and leave ${skippedCount} finding(s) unchanged. Use individual AI Fix where supported; dependency findings without an exact lockfile pin require manual review. Continue?`,
    { modal: true },
    'Apply Fixes',
  );
  if (proceed !== 'Apply Fixes') return;
  if (document.version !== sourceVersion || findingVersionsByUri.get(uriKey) !== sourceVersion) {
    vscode.window.showWarningMessage('The file changed while Fix All was awaiting confirmation. No edits were applied; scan again.');
    await rescan();
    return;
  }

  for (const r of ordered) {
    const range = new vscode.Range(
      new vscode.Position(r.sl, r.sc),
      new vscode.Position(r.el, r.ec),
    );
    edit.replace(document.uri, range, indentReplacement(document, range, r.text));
  }

  const applied = await vscode.workspace.applyEdit(edit);
  if (applied) {
    const fixedCount = ordered.length;
    const fileName = document.uri.path.split(/[\\/]/).pop() || document.uri.toString();
    vscode.window.showInformationMessage(
      `Applied ${fixedCount} supported rule-based fix(es) to ${fileName}; ${skippedCount} finding(s) remain. Use Fix with AI on a remaining finding to request a model-based fix.`,
    );
    // Re-scan after fixes to clear resolved diagnostics
    void rescan();
  } else {
    vscode.window.showErrorMessage('Failed to apply fixes');
  }
}

// FR-04: Apply a single rule-based template fix to one diagnostic (no AI round-trip)
async function applyTemplateFix(
  document: vscode.TextDocument,
  diagnostic: vscode.Diagnostic,
  diagnosticCollection: vscode.DiagnosticCollection,
  rescan?: () => Promise<void>,
): Promise<void> {
  const ruleId = String(diagnostic.code || '');
  const range = expandedFixRange(document, ruleId, diagnostic.range);
  const codeSnippet = document.getText(range);
  const template = templateFix(document.languageId, diagnostic.message, ruleId, codeSnippet, document.getText());
  if (!template) {
    vscode.window.showInformationMessage(
      `No rule-based fix available for ${ruleId}.`,
    );
    return;
  }

  const edit = new vscode.WorkspaceEdit();
  edit.replace(document.uri, range, indentReplacement(document, range, template));
  const applied = await vscode.workspace.applyEdit(edit);
  if (applied) {
    const fileName = document.uri.path.split(/[\\/]/).pop() || document.uri.toString();
    vscode.window.showInformationMessage(`Rule-based fix applied to ${fileName}`);
    // Re-scan after fix to clear resolved diagnostics
    if (rescan) await rescan();
    else void vscode.commands.executeCommand('secureCoding.scanCurrentFile');
  } else {
    vscode.window.showErrorMessage('Failed to apply rule-based fix');
  }
}

export function deactivate() {}

// FR-04 helpers: instant rule-based templates + shared AI-apply flow
function templateFix(languageId: string, message: string, ruleId: string, codeSnippet: string, fullSource = ''): string | null {
  const lang = languageId === 'js' ? 'javascript' : languageId;
  if (lang === 'python' && ruleId === 'PY-CMD-001') {
    // Exact, behavior-preserving fix for the common interpolated ping helper.
    // Never guess a host or silently replace the caller's value with a sample.
    const command = /^\s*command\s*=\s*f(["'])ping\s+-c\s+1\s+\{([A-Za-z_]\w*)\}\1\s*$/m.exec(fullSource);
    const call = /^\s*subprocess\.run\(\s*command\s*,\s*shell\s*=\s*True\s*(,\s*check\s*=\s*(?:True|False))?\s*\)\s*$/.exec(codeSnippet);
    if (command && call) {
      const hostVariable = command[2];
      const checkOption = call[1] || '';
      return `subprocess.run(["ping", "-c", "1", ${hostVariable}], shell=False${checkOption})`;
    }
    return null;
  }
  if (lang === 'python' && ruleId === 'PY-PATH-001') {
    // A narrowly recognized Flask download handler can be repaired as a whole
    // function. Keep the route signature and filename assignment, and use an
    // exact commonpath comparison (a string-prefix check is unsafe).
    const functionHeader = /^([ \t]*def\s+[A-Za-z_]\w*\s*\([^\n]*\)\s*:)[ \t]*$/m.exec(codeSnippet);
    const filenameAssignment = /^([ \t]*)([A-Za-z_]\w*)\s*=\s*request\.args\.get\((['"][^'"\n]+['"])(?:\s*,[^)]*)?\)\s*$/m.exec(codeSnippet);
    const pathAssignment = /^([ \t]*)([A-Za-z_]\w*)\s*=\s*os\.path\.join\(\s*(['"])([^'"\n]+)\3\s*,\s*([A-Za-z_]\w*)\s*\)\s*$/m.exec(codeSnippet);
    const sendFileReturn = /^([ \t]*)return\s+send_file\(\s*([A-Za-z_]\w*)\s*\)\s*$/m.exec(codeSnippet);
    const executableLines = codeSnippet.split(/\r?\n/).filter((line) => line.trim() && !/^\s*#/.test(line));
    if (functionHeader && filenameAssignment && pathAssignment && sendFileReturn &&
      executableLines.length === 4 && pathAssignment[2] === sendFileReturn[2] &&
      pathAssignment[5] === filenameAssignment[2] && /\bimport\s+os\b/.test(fullSource)) {
      const indent = filenameAssignment[1];
      const filename = filenameAssignment[2];
      const base = JSON.stringify(pathAssignment[4]);
      return [
        functionHeader[1],
        `${indent}${filenameAssignment[2]} = request.args.get(${filenameAssignment[3]})`,
        `${indent}if not ${filename}:`,
        `${indent}    return "Missing file name", 400`,
        `${indent}base_dir = os.path.realpath(${base})`,
        `${indent}${pathAssignment[2]} = os.path.realpath(os.path.join(base_dir, ${filename}))`,
        `${indent}try:`,
        `${indent}    if os.path.normcase(os.path.commonpath((base_dir, ${pathAssignment[2]}))) != os.path.normcase(base_dir):`,
        `${indent}        return "Invalid file path", 400`,
        `${indent}except ValueError:`,
        `${indent}    return "Invalid file path", 400`,
        `${indent}return send_file(${pathAssignment[2]})`,
      ].join('\n');
    }
    const openedPath = /\bopen\(\s*([A-Za-z_]\w*)\s*,/.exec(codeSnippet)?.[1];
    if (!openedPath) return null;
    const escapedName = openedPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const assignment = new RegExp(`^([ \\t]*)${escapedName}\\s*=\\s*os\\.path\\.join\\(\\s*([A-Za-z_]\\w*)\\s*,\\s*([A-Za-z_]\\w*)\\s*\\)\\s*$`, 'm');
    if (!assignment.test(codeSnippet)) return null;
    return codeSnippet.replace(assignment, (_line, indent: string, configuredBase: string, filename: string) => [
      `${indent}# Why: Resolve the requested path and reject traversal outside the configured base directory.`,
      `${indent}base_dir = os.path.realpath(${configuredBase})`,
      `${indent}${openedPath} = os.path.realpath(os.path.join(base_dir, ${filename}))`,
      `${indent}if os.path.normcase(os.path.commonpath((base_dir, ${openedPath}))) != os.path.normcase(base_dir):`,
      `${indent}    raise ValueError("Path escapes the allowed directory")`,
    ].join('\n'));
  }
  if (lang === 'python' && ruleId === 'PY-SSRF-001') {
    const requestLine = /^([ \t]*)([A-Za-z_]\w*)\s*=\s*requests\.get\(\s*([A-Za-z_]\w*)\s*(?:,\s*([^\)\n]*))?\)\s*$/m.exec(codeSnippet);
    if (!requestLine) return null;
    const [, indent, responseName, urlName] = requestLine;
    let requestArgs = requestLine[4]?.trim() || '';
    if (/\ballow_redirects\s*=/.test(requestArgs)) {
      requestArgs = requestArgs.replace(/\ballow_redirects\s*=\s*(?:True|False)/, 'allow_redirects=False');
    } else {
      requestArgs = [requestArgs, 'allow_redirects=False'].filter(Boolean).join(', ');
    }
    const safeRequest = `${indent}${responseName} = requests.get(${urlName}, ${requestArgs})`;
    const guard = [
      `${indent}# Why: Only request explicitly approved HTTPS hosts, and do not follow redirects to another host.`,
      `${indent}from urllib.parse import urlparse`,
      `${indent}allowed_hosts = {host.strip().lower() for host in os.environ.get("TRUSTED_REQUEST_HOSTS", "").split(",") if host.strip()}`,
      `${indent}parsed_url = urlparse(${urlName})`,
      `${indent}if parsed_url.scheme != "https" or not parsed_url.hostname or parsed_url.hostname.lower() not in allowed_hosts or parsed_url.username is not None or parsed_url.password is not None:`,
      `${indent}    raise ValueError("Request URL is not in TRUSTED_REQUEST_HOSTS")`,
    ].join('\n');
    return codeSnippet.replace(requestLine[0], `${guard}\n${safeRequest}`);
  }
  if (lang === 'javascript' && ruleId === 'JS-CODE-EXEC-002') {
    const assignment = /^([ \t]*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*)new\s+Function\s*\(/.exec(codeSnippet);
    if (!assignment) return null;
    return `${assignment[1]}() => { throw new Error("Dynamic filter expressions are disabled; use an allowlisted filter instead."); };`;
  }
  if (lang === 'javascript' && ruleId === 'JS-RANDOM-001') {
    const isTokenFunction = /function\s+[A-Za-z_$]*?(?:token|nonce|session|csrf)[A-Za-z_$]*\s*\(/i.test(fullSource) ||
      /(?:token|nonce|session|csrf)/i.test(codeSnippet);
    if (!isTokenFunction || !/^\s*return\b/.test(codeSnippet) || !/Math\.random\s*\(/.test(codeSnippet)) return null;
    const secureRandom = /\brequire\s*\(/.test(fullSource)
      ? 'require("crypto").randomUUID()'
      : 'globalThis.crypto.randomUUID()';
    return codeSnippet.replace(/return\b[\s\S]*?Math\.random\s*\([^)]*\)[^;]*;?/, `return ${secureRandom};`);
  }
  if (lang === 'javascript' && ruleId === 'JS-EXCEPT-001') {
    if (!/http\.createServer\s*\(\s*async\b/.test(fullSource) || !/catch\s*\([^)]*\)\s*\{[\s\S]*throw\s+error\s*;/.test(codeSnippet)) return null;
    return codeSnippet.replace(/throw\s+error\s*;/, 'if (!res.headersSent) { res.statusCode = 500; res.end("Internal server error"); }');
  }
  if (lang === 'python' && ruleId === 'PY-SQLI-001') {
    // This range may include both the vulnerable f-string assignment and its
    // execute(query) call. Replace the pair together to remove stale SQL.
    const call = [...codeSnippet.matchAll(/^\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.execute)\(\s*([A-Za-z_]\w*)\s*\)\s*$/gm)]
      .at(-1);
    if (!call) return null;
    const variable = call[2];
    const escapedName = variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const assignment = new RegExp(`^\\s*${escapedName}\\s*=\\s*f(["'])(.*?)\\1\\s*$`, 'm').exec(fullSource);
    if (!assignment) return null;
    const interpolation = /(['"]?)\{([A-Za-z_]\w*)\}(['"]?)/g;
    const params: string[] = [];
    const query = assignment[2].replace(interpolation, (_match, _before: string, name: string, _after: string) => {
      params.push(name);
      return '?';
    });
    // Only offer this fix when the f-string has simple name placeholders and looks like SQL.
    if (!params.length || /\{[^}]+\}/.test(query) || !/^\s*(select|insert|update|delete)\b/i.test(query)) return null;
    return `${call[1]}(${JSON.stringify(query)}, (${params.join(', ')}${params.length === 1 ? ',' : ''}))`;
  }
  if (lang === 'python' && ruleId === 'PY-SECRETS-001') {
    const match = codeSnippet.trim().match(/^([A-Za-z_]\w*)\s*=/);
    if (!match || !/\bimport\s+os\b|\bfrom\s+os\s+import\s+environ\b/.test(fullSource)) return null;
    const varName = match[1];
    return /\bfrom\s+os\s+import\s+environ\b/.test(fullSource)
      ? `${varName} = environ["${varName}"]`
      : `${varName} = os.environ["${varName}"]`;
  }
  return null;
}

function indentReplacement(document: vscode.TextDocument, range: vscode.Range, replacement: string): string {
  const eol = document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n';
  const lineText = document.lineAt(range.start.line).text;
  const wholeLineIndent = lineText.match(/^\s*/)?.[0] || '';
  if (range.start.character === 0 && wholeLineIndent) {
    const lines = replacement.split(/\r?\n/).map((line, index) => {
      const content = index === 0
        ? line.trimStart()
        : line.startsWith(wholeLineIndent) ? line.slice(wholeLineIndent.length) : line;
      return `${wholeLineIndent}${content}`;
    });
    return lines.join(eol);
  }
  const linePrefix = document.lineAt(range.start.line).text.slice(0, range.start.character);
  const indent = /^\s*$/.test(linePrefix) ? linePrefix : '';
  return replacement.replace(/\r?\n/g, eol)
    .replace(/\r?\n/g, (newline) => `${newline}${indent}`);
}

function expandedFixRange(document: vscode.TextDocument, ruleId: string, baseRange: vscode.Range): vscode.Range {
  if (document.languageId === 'javascript' && ['JS-CODE-EXEC-002', 'JS-RANDOM-001'].includes(ruleId)) {
    const line = document.lineAt(baseRange.start.line);
    return new vscode.Range(baseRange.start.line, 0, baseRange.start.line, line.text.length);
  }
  if (document.languageId === 'python' && ['PY-PATH-001', 'PY-SSRF-001'].includes(ruleId)) {
    const findingIndent = document.lineAt(baseRange.start.line).text.match(/^\s*/)?.[0].length || 0;
    let functionStart = -1;
    let functionIndent = -1;
    for (let line = baseRange.start.line; line >= 0; line -= 1) {
      const text = document.lineAt(line).text;
      const definition = /^(\s*)(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(/.exec(text);
      if (definition && definition[1].length <= findingIndent) {
        functionStart = line;
        functionIndent = definition[1].length;
        break;
      }
    }
    if (functionStart >= 0) {
      let endLine = document.lineCount - 1;
      for (let line = functionStart + 1; line < document.lineCount; line += 1) {
        const text = document.lineAt(line).text;
        if (!text.trim()) continue;
        const indentation = text.match(/^\s*/)?.[0].length || 0;
        if (indentation <= functionIndent) {
          endLine = line - 1;
          break;
        }
      }
      while (endLine > functionStart && !document.lineAt(endLine).text.trim()) endLine -= 1;
      return new vscode.Range(functionStart, 0, endLine, document.lineAt(endLine).text.length);
    }
  }
  if (document.languageId === 'python' && ruleId === 'PY-SQLI-001') {
    const highlightedCode = document.getText(baseRange);
    const call = /\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.execute\(\s*([A-Za-z_]\w*)\s*\)/.exec(highlightedCode);
    if (!call) return baseRange;

    const variable = call[1];
    const escapedVariable = variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const assignmentPattern = new RegExp(`^([ \\t]*)${escapedVariable}\\s*=\\s*f([\"'])(.*?)\\2\\s*$`);
    const callIndent = document.lineAt(baseRange.start.line).text.match(/^\s*/)?.[0] || '';
    for (let line = baseRange.start.line - 1; line >= Math.max(0, baseRange.start.line - 30); line -= 1) {
      const assignment = assignmentPattern.exec(document.lineAt(line).text);
      if (!assignment) continue;
      const sql = assignment[3];
      if (!/\b(select|insert|update|delete)\b/i.test(sql) || !/\{[A-Za-z_]\w*\}/.test(sql)) return baseRange;
      if (assignment[1].length !== callIndent.length) return baseRange;
      return new vscode.Range(line, 0, baseRange.end.line, baseRange.end.character);
    }
    return baseRange;
  }
  if (document.languageId !== 'javascript' || ruleId !== 'JS-SQLI-001') return baseRange;

  // SQL injection fixes often need to edit both the SQL string and the query
  // call. The scanner highlights the call, so include its simple local query
  // variable declaration in the AI replacement range when it is recognizable.
  const highlightedCode = document.getText(baseRange);
  const call = /\b(?:[A-Za-z_$][\w$]*\.)*query\s*\(\s*([A-Za-z_$][\w$]*)\s*\)/.exec(highlightedCode);
  if (!call) return baseRange;

  const variable = call[1];
  const escapedVariable = variable.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const declarationPattern = new RegExp(`^\\s*(?:const|let|var)\\s+${escapedVariable}\\s*=`, '');
  for (let line = baseRange.start.line - 1; line >= Math.max(0, baseRange.start.line - 30); line -= 1) {
    const text = document.lineAt(line).text;
    if (!declarationPattern.test(text)) continue;
    const sqlAssignment = text.slice(text.indexOf('=') + 1);
    const looksLikeInterpolatedSql = /\b(select|insert|update|delete)\b/i.test(sqlAssignment) &&
      (/\$\{[^}]+\}/.test(sqlAssignment) || /\+\s*[A-Za-z_$][\w$]*/.test(sqlAssignment));
    if (!looksLikeInterpolatedSql) return baseRange;
    return new vscode.Range(line, 0, baseRange.end.line, baseRange.end.character);
  }
  return baseRange;
}

function aiFixRange(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.Range {
  return expandedFixRange(document, String(diagnostic.code || ''), diagnostic.range);
}

type PreparedAiReplacement = {
  text: string;
  commentInsertion?: { position: vscode.Position; text: string };
  importInsertions?: { position: vscode.Position; text: string }[];
};

function prepareAiReplacement(
  document: vscode.TextDocument,
  range: vscode.Range,
  code: string,
  finding: Finding,
): PreparedAiReplacement {
  const language = document.languageId === 'python' ? 'python' : 'javascript';
  const prefix = language === 'python' ? '#' : '//';
  const rationale: Record<string, string> = {
    'PY-SQLI-001': 'Bound parameters keep user input separate from SQL syntax.',
    'PY-CMD-001': 'Passing arguments without a shell prevents input from becoming a shell command.',
    'PY-SECRETS-001': 'Reading the credential from configuration avoids hard-coding it in source.',
    'PY-PATH-001': 'Resolving and checking the final path keeps file access inside the configured directory.',
    'PY-SSRF-001': 'An HTTPS host allowlist blocks requests to unapproved destinations.',
    'JS-SQLI-001': 'Bound parameters keep user input separate from SQL syntax.',
    'JS-XSS-001': 'Rendering the value as text prevents it from being interpreted as HTML.',
    'JS-SECRETS-001': 'Reading the credential from configuration avoids hard-coding it in source.',
    'JS-CMD-001': 'Passing arguments without a shell prevents input from becoming a shell command.',
    'JS-CODE-EXEC-002': 'Rejecting dynamic filter strings prevents execution of attacker-controlled JavaScript.',
    'JS-RANDOM-001': 'A cryptographic random UUID is unpredictable and suitable for token generation.',
  };
  const comment = `${prefix} Why: ${rationale[String(finding.rule_id)] || `This change addresses the ${finding.title} finding.`}`;
  const lineText = document.lineAt(range.start.line).text;
  const linePrefix = lineText.slice(0, range.start.character);
  let commentLine = range.start.line;
  while (commentLine > 0 && /^\s*@/.test(document.lineAt(commentLine - 1).text)) commentLine -= 1;
  const previousLine = commentLine > 0 ? document.lineAt(commentLine - 1).text.trimStart() : '';
  if (/^(#|\/\/)\s*Why:/i.test(previousLine)) {
    return { text: indentReplacement(document, range, code.trim()) };
  }
  if (/^\s*$/.test(linePrefix)) {
    if (commentLine !== range.start.line) {
      const eol = document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n';
      const indentation = document.lineAt(commentLine).text.match(/^\s*/)?.[0] || '';
      return {
        text: indentReplacement(document, range, code.trim()),
        commentInsertion: { position: new vscode.Position(commentLine, 0), text: `${indentation}${comment}${eol}` },
      };
    }
    return { text: indentReplacement(document, range, `${comment}\n${code.trim()}`) };
  }
  // Some rules select only the initializer/value within a JS declaration. A
  // standalone comment is safe before the declaration, but not before an
  // arbitrary mid-line expression (which could comment out surrounding code).
  if (language !== 'javascript' || !/^\s*(?:const|let|var)\s+$/.test(linePrefix)) {
    return { text: indentReplacement(document, range, code.trim()) };
  }
  const indentation = lineText.match(/^\s*/)?.[0] || '';
  const eol = document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n';
  return {
    text: indentReplacement(document, range, code.trim()),
    commentInsertion: {
      position: new vscode.Position(range.start.line, 0),
      text: `${indentation}${comment}${eol}`,
    },
  };
}

function prepareAiReplacementWithImports(
  document: vscode.TextDocument,
  range: vscode.Range,
  code: string,
  finding: Finding,
  relatedProjectFiles: { path: string; content: string }[],
): PreparedAiReplacement {
  const prepared = prepareAiReplacement(document, range, code, finding);
  if (document.languageId !== 'python') return prepared;

  const source = document.getText();
  const startOffset = document.offsetAt(range.start);
  const endOffset = document.offsetAt(range.end);
  const candidateSource = source.slice(0, startOffset) + prepared.text + source.slice(endOffset);
  const importInsertions: { position: vscode.Position; text: string }[] = [];
  const insertionPosition = pythonImportInsertionPosition(document);
  const eol = document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n';

  // Inspect the whole candidate module: the patched range may depend on
  // standard-library names already used elsewhere in the target file.
  const supportedModules = ['os', 'json', 're', 'hashlib', 'secrets', 'subprocess', 'pathlib', 'ast', 'hmac', 'base64', 'tempfile', 'shlex'];
  for (const moduleName of supportedModules) {
    if (!new RegExp(`\\b${moduleName}\\s*\\.`).test(candidateSource)) continue;
    const importPattern = new RegExp(`^import\\s+${moduleName}(?:\\.[A-Za-z_]\\w*)?(?:\\s+as\\s+([A-Za-z_]\\w*))?(?:\\s*(?:,|$))`, 'm');
    const importedAs = importPattern.exec(source)?.[1];
    if (!importPattern.test(source) || (importedAs && importedAs !== moduleName)) {
      importInsertions.push({ position: insertionPosition, text: `import ${moduleName}${eol}` });
    }
  }

  // Imports from another Python module do not define names in this module.
  // When workspace evidence confirms Flask and this file uses its API, add
  // just the missing, known Flask imports at this file's import section.
  const projectText = relatedProjectFiles.map((file) => file.content).join('\n');
  const flaskEvidence = /(?:^\s*from\s+flask\s+import\b|\bFlask\s*\()/im.test(projectText) ||
    /(?:^|\n)\s*flask(?:\s*[=<>!~]|\s*$)/im.test(projectText) ||
    /@\s*\w+\.route\s*\(/.test(candidateSource) ||
    (/\brequest\.(?:args|form|json)\b/.test(candidateSource) && /\bsend_file\s*\(/.test(candidateSource));
  const flaskIsUsed = /@\s*\w+\.(?:route|get|post|put|delete)\s*\(/.test(candidateSource) ||
    /\b(?:request\.(?:args|form|json)|send_file\s*\(|abort\s*\(|jsonify\s*\(|Flask\s*\()/.test(candidateSource);
  if (flaskEvidence && flaskIsUsed && !/^\s*import\s+flask\b/m.test(source)) {
    const imported = new Set<string>();
    for (const match of source.matchAll(/^\s*from\s+flask\s+import\s+([^\n#]+)/gm)) {
      for (const part of match[1].split(',')) {
        const importMatch = /^\s*([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?/.exec(part);
        if (importMatch) imported.add(importMatch[2] || importMatch[1]);
      }
    }
    const flaskNames = ['Flask', 'request', 'send_file', 'abort', 'jsonify'];
    const missing = flaskNames.filter((name) => {
      if (imported.has(name) || !new RegExp(`\\b${name}\\b`).test(candidateSource)) return false;
      const locallyDefined = new RegExp(`(?:^|\\n)\\s*(?:def\\s+\\w+\\s*\\([^)]*\\b${name}\\b|${name}\\s*=)`, 'm').test(source);
      return !locallyDefined;
    });
    if (missing.length) importInsertions.push({ position: insertionPosition, text: `from flask import ${missing.join(', ')}${eol}` });
  }

  prepared.importInsertions = importInsertions;
  return prepared;
}

function pythonImportInsertionPosition(document: vscode.TextDocument): vscode.Position {
  const lines = document.getText().split(/\r?\n/);
  let index = 0;
  if (lines[0]?.startsWith('#!')) index = 1;
  for (let candidate = index; candidate < Math.min(lines.length, 2); candidate += 1) {
    if (/coding[:=]\s*[-\w.]+/i.test(lines[candidate])) index = Math.max(index, candidate + 1);
  }
  while (index < lines.length && /^\s*(?:#.*)?$/.test(lines[index])) index += 1;
  const docstringStart = /^\s*(?:[rRuUbB]{0,2})('''|""")/.exec(lines[index] || '');
  if (docstringStart) {
    const delimiter = docstringStart[1];
    const remainder = lines[index].slice(docstringStart[0].length);
    if (remainder.includes(delimiter)) index += 1;
    else {
      index += 1;
      while (index < lines.length && !lines[index].includes(delimiter)) index += 1;
      if (index < lines.length) index += 1;
    }
  }
  while (index < lines.length && /^\s*(?:#.*)?$/.test(lines[index])) index += 1;
  while (index < lines.length && /^\s*from\s+__future__\s+import\b/.test(lines[index])) index += 1;
  while (index < lines.length && /^\s*(?:import\s+|from\s+\S+\s+import\b)/.test(lines[index])) index += 1;
  return new vscode.Position(Math.min(index, document.lineCount - 1), 0);
}

function composeAiPreview(
  source: string,
  startOffset: number,
  endOffset: number,
  replacement: PreparedAiReplacement,
  document: vscode.TextDocument,
): string {
  const operations = [{
    start: startOffset,
    end: endOffset,
    text: replacement.text,
  }];
  if (replacement.commentInsertion) {
    const offset = document.offsetAt(replacement.commentInsertion.position);
    operations.push({ start: offset, end: offset, text: replacement.commentInsertion.text });
  }
  for (const insertion of replacement.importInsertions || []) {
    const offset = document.offsetAt(insertion.position);
    operations.push({ start: offset, end: offset, text: insertion.text });
  }
  operations.sort((a, b) => b.start - a.start || b.end - a.end);
  let result = source;
  for (const operation of operations) {
    result = result.slice(0, operation.start) + operation.text + result.slice(operation.end);
  }
  return result;
}

async function applyAiFix(
  document: vscode.TextDocument,
  diagnostic: vscode.Diagnostic,
  finding: Finding,
  backendUrl: string,
  rescan: () => Promise<void>,
  onFixFailure: (reason: string) => Promise<void>,
  baselineDiagnostics: readonly vscode.Diagnostic[],
  relatedProjectFiles: { path: string; content: string }[],
): Promise<void> {
  const diagnosticRange = diagnostic.range;
  const range = aiFixRange(document, diagnostic);
  const line = diagnosticRange.start.line + 1;
  const configuredProvider = vscode.workspace.getConfiguration('secureCoding').get<string>('aiProvider', 'ollama');
  const configuredModel = vscode.workspace.getConfiguration('secureCoding').get<string>('aiModel', '');
  const originalVersion = document.version;
  const originalSource = document.getText();
  const ruleId = String(diagnostic.code || '');
  const baselineFindingCount = Math.max(1, baselineDiagnostics.filter((item) => String(item.code || '') === ruleId).length);
  const findingData = {
    rule_id: String(diagnostic.code || ''),
    title: finding.title,
    severity: finding.severity,
    cwe_id: finding.cwe_id,
    owasp_ref: finding.owasp_ref,
    owasp_2021_ref: finding.owasp_2021_ref || 'N/A',
    language: document.languageId,
    code_snippet: document.getText(range),
    context: {
      line,
      end_line: range.end.line + 1,
      start_column: range.start.character,
      end_column: range.end.character,
      full_source: originalSource,
      related_project_files: relatedProjectFiles,
      validation_feedback: undefined as string | undefined,
    },
  };
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Window, title: 'Generating secure fix with AI...' },
    async () => {
      try {
        let suggestion: SuggestionResponse;
        suggestion = await requestSuggestion(findingData, backendUrl);
        if (suggestion.source === 'provider' &&
            (suggestion.can_fix === false || !suggestion.secure_code?.trim())) {
          findingData.context.validation_feedback = [
            'The previous response declined or did not provide a candidate. Reconsider the finding using your own reasoning and return your best focused patch for review.',
            suggestion.explanation,
          ].filter(Boolean).join(' ');
          try {
            const repaired = await requestSuggestion(findingData, backendUrl);
            if (repaired.can_fix !== false && repaired.secure_code?.trim()) suggestion = repaired;
            else if (repaired.explanation) suggestion.explanation = repaired.explanation;
          } catch {
            // Keep the explicit refusal if the single bounded repair request fails.
          }
        }
        if (suggestion.can_fix === false || !suggestion.secure_code?.trim()) {
          await onFixFailure(suggestion.explanation || 'The selected model did not provide a candidate. No code was changed.');
          return;
        }
        if (suggestion.secure_code.length > 12000 || suggestion.secure_code.includes('```')) {
          await onFixFailure('The selected model response was not a focused replacement. No code was changed.');
          return;
        }
        if (document.version !== originalVersion || document.getText(range) !== findingData.code_snippet) {
          vscode.window.showWarningMessage('The file changed while the model was generating a fix. No code was changed; scan again.');
          await rescan();
          return;
        }
        const startOffset = document.offsetAt(range.start);
        const endOffset = document.offsetAt(range.end);
        let prepared = prepareAiReplacementWithImports(document, range, suggestion.secure_code.trim(), finding, relatedProjectFiles);
        let secureCode = prepared.text;
        const originalRangeText = document.getText(range);
        if (addsImportOutsideRange(document.languageId, originalRangeText, secureCode)) {
          await onFixFailure('The selected model proposed an import that CodeShield cannot place safely outside the focused edit. No code was changed.');
          return;
        }
        // Some scanners highlight an expression but exclude the statement's trailing
        // semicolon. Avoid producing `statement;;` when the model returns one.
        const originalSuffix = originalSource.slice(endOffset);
        if (document.languageId === 'javascript' && secureCode.endsWith(';') && /^[ \t]*;/.test(originalSuffix)) {
          secureCode = secureCode.slice(0, -1);
          prepared.text = secureCode;
        }
        let previewSource = composeAiPreview(originalSource, startOffset, endOffset, prepared, document);
        let validation = await validateAiPreview(
          document.languageId,
          previewSource,
          document.fileName,
          backendUrl,
          findingData.rule_id,
          baselineDiagnostics,
        );
        // Some models occasionally return a nearly-correct replacement with a
        // syntax defect (for example, a duplicated `const` or unmatched `)`).
        // Give the selected model one bounded repair attempt using the exact
        // local parser error. The candidate still must pass every normal gate.
        if (validation.syntaxError || validation.findingRemains) {
          findingData.context.validation_feedback = validation.syntaxError ||
            `The preview still has a ${findingData.rule_id} finding. Choose a different secure approach; CodeShield does not prescribe the remediation.`;
          try {
            const retry = await requestSuggestion(findingData, backendUrl);
            if (retry.can_fix !== false && retry.secure_code?.trim() &&
              retry.secure_code.length <= 12000 && !retry.secure_code.includes('```')) {
              const retryPrepared = prepareAiReplacementWithImports(
                document,
                range,
                retry.secure_code.trim(),
                finding,
                relatedProjectFiles,
              );
              let retryCode = retryPrepared.text;
              if (!addsImportOutsideRange(document.languageId, originalRangeText, retryCode)) {
                if (document.languageId === 'javascript' && retryCode.endsWith(';') && /^[ \t]*;/.test(originalSuffix)) {
                  retryCode = retryCode.slice(0, -1);
                  retryPrepared.text = retryCode;
                }
                const retrySource = composeAiPreview(originalSource, startOffset, endOffset, retryPrepared, document);
                const retryValidation = await validateAiPreview(
                  document.languageId,
                  retrySource,
                  document.fileName,
                  backendUrl,
                  findingData.rule_id,
                  baselineDiagnostics,
                );
                if (!retryValidation.syntaxError) {
                  suggestion = retry;
                  prepared = retryPrepared;
                  secureCode = retryCode;
                  previewSource = retrySource;
                  validation = retryValidation;
                }
              }
            }
          } catch {
            // Keep the first candidate/fallback path; a failed retry must not
            // cause partial edits or hide the original validation result.
          }
        }
        if (validation.syntaxError) {
          const previewChoice = await vscode.window.showWarningMessage(
            `The AI proposal has a syntax issue: ${validation.syntaxError} It cannot be applied, but you can inspect the candidate.`,
            { modal: true },
            'Preview Candidate',
          );
          if (previewChoice !== 'Preview Candidate') return;
          const invalidPreview = await vscode.workspace.openTextDocument({ language: document.languageId, content: previewSource });
          await vscode.commands.executeCommand('vscode.diff', document.uri, invalidPreview.uri, `AI Candidate (syntax review): ${finding.title}`);
          return;
        }
        const scannerReview = [validation.findingRemains, ...(validation.newFindings || [])]
          .filter((message): message is string => Boolean(message))
          .join(' ');
        const applyLabel = 'Apply Fix';
        const originNotice = `Model-generated proposal from ${suggestion.provider || configuredProvider}${configuredModel ? ` (${configuredModel})` : ''}. ${suggestion.explanation || ''}` +
          (scannerReview ? ` Scanner review: ${scannerReview} The model candidate is still available for your review.` : '');
        const dynamicExecutionNotice = ['PY-CODE-EXEC-001', 'PY-CODE-EXEC-002', 'JS-CODE-EXEC-001', 'JS-CODE-EXEC-002'].includes(findingData.rule_id)
          ? ' This finding involves dynamic code execution; review that the candidate removes the unsafe path and preserves intended behavior.'
          : '';
        const confirmed = await vscode.window.showInformationMessage(
          `${originNotice} Focused fix for ${finding.title}.${dynamicExecutionNotice} A short “Why” comment is included where it can be added safely.`,
          { modal: true },
          'Preview Fix',
          applyLabel,
        );
        let apply = confirmed === applyLabel;
        if (confirmed === 'Preview Fix') {
          const previewDocument = await vscode.workspace.openTextDocument({
            language: document.languageId,
            content: previewSource,
          });
          await vscode.commands.executeCommand(
            'vscode.diff',
            document.uri,
            previewDocument.uri,
            `AI Fix Preview: ${finding.title}`,
          );
          apply = (await vscode.window.showWarningMessage(
            'Apply the patch shown in the diff?',
            { modal: true },
            applyLabel,
          )) === applyLabel;
        }
        if (apply) {
          if (document.version !== originalVersion || document.getText() !== originalSource) {
            vscode.window.showWarningMessage('The file changed before the fix was applied. No code was changed; scan again.');
            await rescan();
            return;
          }
          const edit = new vscode.WorkspaceEdit();
          for (const insertion of prepared.importInsertions || []) {
            edit.insert(document.uri, insertion.position, insertion.text);
          }
          if (prepared.commentInsertion) {
            edit.insert(document.uri, prepared.commentInsertion.position, prepared.commentInsertion.text);
          }
          edit.replace(document.uri, range, secureCode);
          const applied = await vscode.workspace.applyEdit(edit);
          if (!applied) {
            vscode.window.showErrorMessage('VS Code could not apply the suggested edit. The file was not changed.');
            return;
          }
          vscode.window.showInformationMessage('Fix applied');
          await rescan();
          const remainingRuleFindings = vscode.languages.getDiagnostics(document.uri).filter((item) =>
            String(item.code || '') === findingData.rule_id,
          ).length;
          if (remainingRuleFindings >= baselineFindingCount) {
            vscode.window.showWarningMessage(
              `The AI candidate was applied, but CodeShield still reports ${findingData.rule_id} after rescanning. Review the changed code, then edit it manually or try another AI fix.`,
            );
          }
        }
      } catch (error) {
        const message = `AI fix failed: ${error}`;
        const action = await vscode.window.showErrorMessage(message, 'Choose Another Model');
        if (action === 'Choose Another Model') await onFixFailure(String(error));
      }
    },
  );
}

function addsImportOutsideRange(languageId: string, originalRange: string, replacement: string): boolean {
  const importPattern = languageId === 'python'
    ? /^\s*(?:import\s+[\w.]+|from\s+[\w.]+\s+import\s+)/m
    : /^\s*import\s+(?:[^;\n]+\s+from\s+)?["'][^"']+["']/m;
  return importPattern.test(replacement) && !importPattern.test(originalRange);
}

async function validateAiPreview(
  languageId: string,
  code: string,
  filename: string,
  backendUrl: string,
  ruleId: string,
  baselineDiagnostics: readonly vscode.Diagnostic[],
): Promise<{ syntaxError?: string; findingRemains?: string; newFindings?: string[] }> {
  const response = await fetch(`${backendUrl}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ language: languageId, code, filename }),
  });
  if (!response.ok) throw new Error(`Could not validate the AI patch (HTTP ${response.status})`);
  const result = await response.json() as { findings?: { rule_id?: string; message?: string; severity?: string }[] };
  const findings = result.findings || [];
  const parseFinding = findings.find((finding) => finding.rule_id === 'PARSE-ERROR');
  if (parseFinding) {
    return { syntaxError: `The patch would leave invalid ${languageId} syntax (${parseFinding.message || 'parse error'}).` };
  }
  const remainingCount = findings.filter((finding) => finding.rule_id === ruleId).length;
  const baselineFindingCount = Math.max(1, baselineDiagnostics.filter((finding) => String(finding.code || '') === ruleId).length);
  if (remainingCount >= baselineFindingCount) {
    return { findingRemains: `The scanner still detects ${ruleId} in the preview (${remainingCount} finding${remainingCount === 1 ? '' : 's'} remain).` };
  }
  const normalizeMessage = (message: string | undefined): string => (message || '')
    .replace(/^\s*\[(?:critical|high|medium|low|info)\]\s*/i, '')
    .replace(/\s*Secure Coding\([^)]+\)\s*$/i, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
  const countByKey = (items: readonly { rule_id?: string; message?: string }[]) => {
    const counts = new Map<string, number>();
    for (const item of items) {
      // VS Code diagnostics decorate the backend message with severity/source;
      // compare normalized rule/message fingerprints to avoid false positives.
      const key = `${item.rule_id || 'UNKNOWN'}\u0000${normalizeMessage(item.message)}`;
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    return counts;
  };
  const beforeCounts = countByKey(baselineDiagnostics.map((item) => ({
    rule_id: String(item.code || 'UNKNOWN'),
    message: item.message,
  })));
  const afterCounts = countByKey(findings);
  const newFindings: string[] = [];
  for (const [key, count] of afterCounts) {
    const excess = count - (beforeCounts.get(key) || 0);
    if (excess > 0) {
      const [newRule] = key.split('\u0000');
      newFindings.push(`The preview introduces ${excess} additional ${newRule} finding(s).`);
    }
  }
  return newFindings.length ? { newFindings } : {};
}
