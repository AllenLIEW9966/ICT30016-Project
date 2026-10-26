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
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const backendManager_1 = require("./backendManager");
// C3: secrets storage, populated during activate
let secretStorage;
function activate(context) {
    console.log('Secure Coding Assistant is now active');
    const backendUrl = vscode.workspace.getConfiguration('secureCoding').get('backendUrl', 'http://localhost:8000');
    const ollamaUrl = vscode.workspace.getConfiguration('secureCoding').get('aiApiBase', 'http://localhost:11434/v1').replace('/v1', '');
    const backend = new backendManager_1.BackendManager(backendUrl, ollamaUrl);
    secretStorage = context.secrets;
    context.subscriptions.push({ dispose: () => backend.dispose() });
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('secureCoding');
    context.subscriptions.push(diagnosticCollection);
    // Keep finding metadata keyed by document URI so hover/fix can access OWASP/CWE/suggestion
    const findingsByUri = new Map();
    let statusBarItem;
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'secureCoding.showSecurityScore';
    statusBarItem.tooltip = 'Security Score';
    statusBarItem.text = '🔒 ?';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);
    // B: AI status bar item
    const aiStatusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 99);
    aiStatusBarItem.command = 'secureCoding.installLocalAI';
    aiStatusBarItem.tooltip = 'Local AI status — click to install Ollama';
    aiStatusBarItem.text = '$(sync~spin) AI';
    aiStatusBarItem.show();
    context.subscriptions.push(aiStatusBarItem);
    let debounceTimer;
    async function scanDocument(document) {
        const language = document.languageId;
        console.log(`[Secure Coding] scanDocument called for ${document.fileName}, language=${language}`);
        if (language !== 'python' && language !== 'javascript') {
            console.log('[Secure Coding] skipped, unsupported language');
            return;
        }
        const code = document.getText();
        console.log(`[Secure Coding] sending ${code.length} chars to ${backendUrl}/scan`);
        try {
            const response = await fetch(`${backendUrl}/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ language, code, filename: document.fileName }),
            });
            console.log(`[Secure Coding] response status=${response.status}`);
            if (!response.ok) {
                return;
            }
            const result = (await response.json());
            const findings = result.findings || [];
            console.log(`[Secure Coding] findings=${findings.length}`, result);
            const diagnostics = findings.map((f) => {
                const startLine = Math.max(0, f.line - 1);
                const endLine = Math.max(0, f.end_line - 1);
                const range = new vscode.Range(startLine, Math.max(0, f.column), endLine, Math.max(0, f.end_column));
                const severity = f.severity === 'critical' || f.severity === 'high'
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
            findingsByUri.set(document.uri, findings);
            const findingsMsg = findings.length > 0
                ? `Found ${findings.length} issue(s): ${findings.map(f => f.rule_id).join(', ')}`
                : 'No issues found';
            vscode.window.showInformationMessage(`🔒 Secure Coding: ${findingsMsg}`);
            updateStatusBar(findings);
        }
        catch (error) {
            console.error(`[Secure Coding] Scan failed: ${error}`);
        }
    }
    function updateStatusBar(findings) {
        const critical = findings.filter((f) => f.severity === 'critical').length;
        const high = findings.filter((f) => f.severity === 'high').length;
        const medium = findings.filter((f) => f.severity === 'medium').length;
        const low = findings.filter((f) => f.severity === 'low').length;
        let score;
        if (critical > 0)
            score = 'F';
        else if (high > 2)
            score = 'D';
        else if (high > 0 || medium > 2)
            score = 'C';
        else if (medium > 0 || low > 2)
            score = 'B';
        else
            score = 'A';
        statusBarItem.text = `🔒 ${score}`;
        statusBarItem.tooltip = `Security Score: ${score}\nCritical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}`;
        statusBarItem.show();
    }
    // Scan on text change (debounced)
    const changeListener = vscode.workspace.onDidChangeTextDocument((event) => {
        const document = event.document;
        if (document.languageId !== 'python' && document.languageId !== 'javascript') {
            return;
        }
        if (debounceTimer) {
            clearTimeout(debounceTimer);
        }
        debounceTimer = setTimeout(() => scanDocument(document), 500);
    });
    // Scan on save
    const saveListener = vscode.workspace.onDidSaveTextDocument((document) => {
        scanDocument(document);
    });
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
    // FR-04: 1-click Quick Fix — lightbulb action on every diagnostic
    const quickFixProvider = vscode.languages.registerCodeActionsProvider(['python', 'javascript'], {
        provideCodeActions(document, range, ctx) {
            const actions = [];
            for (const d of ctx.diagnostics) {
                if (d.source !== 'Secure Coding') {
                    continue;
                }
                const ruleId = String(d.code || '');
                // Rule-based instant fix (no AI round-trip)
                const template = templateFix(document.languageId, d.message, ruleId);
                if (template) {
                    const a = new vscode.CodeAction(`⚡ Quick Fix: ${ruleId}`, vscode.CodeActionKind.QuickFix);
                    a.diagnostics = [d];
                    a.isPreferred = true;
                    a.edit = new vscode.WorkspaceEdit();
                    a.edit.replace(document.uri, d.range, template);
                    actions.push(a);
                }
                // AI fix via backend (O-02 bounded context)
                const ai = new vscode.CodeAction(`🤖 Fix with AI: ${ruleId}`, vscode.CodeActionKind.QuickFix);
                ai.diagnostics = [d];
                ai.command = {
                    command: 'secureCoding.fixDiagnostic',
                    title: 'Fix with AI',
                    arguments: [document.uri.toString(), ruleId],
                };
                actions.push(ai);
            }
            return actions;
        },
    }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] });
    // Resolve a diagnostic + full source, then reuse the AI flow
    const fixDiagnosticCmd = vscode.commands.registerCommand('secureCoding.fixDiagnostic', async (uriStr, ruleId) => {
        const uri = vscode.Uri.parse(uriStr);
        const editor = vscode.window.visibleTextEditors.find((e) => e.document.uri.toString() === uriStr);
        const doc = editor?.document ?? (await vscode.workspace.openTextDocument(uri));
        const diags = (diagnosticCollection.get(uri) || []).filter((d) => String(d.code) === ruleId);
        if (diags.length === 0) {
            vscode.window.showWarningMessage(`No diagnostic ${ruleId} to fix`);
            return;
        }
        const d = diags[0];
        await applyAiFix(doc, d, backendUrl, diagnosticCollection);
    });
    const fixCommand = vscode.commands.registerCommand('secureCoding.fixWithAI', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor');
            return;
        }
        const selection = editor.selection;
        const document = editor.document;
        const diagnostics = diagnosticCollection.get(document.uri) || [];
        const selectedDiagnostics = diagnostics.filter((d) => {
            const range = d.range;
            return range.contains(selection.start) || range.contains(selection.end);
        });
        if (selectedDiagnostics.length === 0) {
            vscode.window.showWarningMessage('No vulnerabilities found at the cursor position');
            return;
        }
        const diagnostic = selectedDiagnostics[0];
        const allFindings = findingsByUri.get(document.uri) || [];
        const matchedFinding = allFindings.find((f) => f.rule_id === diagnostic.code);
        if (!matchedFinding) {
            vscode.window.showErrorMessage('Could not find vulnerability details for this diagnostic');
            return;
        }
        const range = diagnostic.range;
        const findingData = {
            rule_id: matchedFinding.rule_id,
            title: matchedFinding.title,
            severity: matchedFinding.severity,
            cwe_id: matchedFinding.cwe_id,
            owasp_ref: matchedFinding.owasp_ref,
            language: document.languageId,
            code_snippet: document.getText(range),
            context: {},
        };
        const findingRange = range;
        await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: 'Generating secure fix with AI...' }, async () => {
            try {
                const suggestion = await requestSuggestion(findingData, backendUrl);
                if (!suggestion.secure_code) {
                    vscode.window.showWarningMessage('AI could not generate a fix for this issue');
                    return;
                }
                // Show diff preview
                const original = document.getText(findingRange);
                const edit = new vscode.WorkspaceEdit();
                edit.replace(document.uri, findingRange, suggestion.secure_code);
                const confirmed = await vscode.window.showInformationMessage('AI suggests the following fix. Apply it?', { modal: true }, 'Apply Fix', 'Show Explanation');
                if (confirmed === 'Apply Fix') {
                    await vscode.workspace.applyEdit(edit);
                    vscode.window.showInformationMessage('Fix applied');
                }
                else if (confirmed === 'Show Explanation') {
                    const doc = await vscode.workspace.openTextDocument({
                        content: `# ${findingData.title}\n\n${suggestion.explanation}\n\n## Suggested Fix\n\n\`\`\`\n${suggestion.secure_code}\n\`\`\`\n`,
                        language: 'markdown',
                    });
                    await vscode.window.showTextDocument(doc, { preview: true });
                }
            }
            catch (error) {
                vscode.window.showErrorMessage(`AI fix failed: ${error}`);
            }
        });
    });
    // Security score command
    const scoreCommand = vscode.commands.registerCommand('secureCoding.showSecurityScore', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showInformationMessage('Open a file to see security score');
            return;
        }
        const diagnostics = diagnosticCollection.get(editor.document.uri) || [];
        updateStatusBar(diagnosticsToFindings(diagnostics));
        const score = statusBarItem.text || 'N/A';
        const tooltipText = typeof statusBarItem.tooltip === 'string' ? statusBarItem.tooltip : '';
        vscode.window.showInformationMessage(`Security Score: ${score}`, { detail: tooltipText });
    });
    // Hover provider
    const hoverProvider = vscode.languages.registerHoverProvider(['python', 'javascript'], {
        provideHover(document, position) {
            const diagnostics = diagnosticCollection.get(document.uri) || [];
            const relevant = diagnostics.filter((d) => d.range.contains(position));
            if (relevant.length === 0) {
                return null;
            }
            const findings = findingsByUri.get(document.uri) || [];
            const markdown = new vscode.MarkdownString();
            markdown.isTrusted = true;
            markdown.appendMarkdown('## Secure Coding Findings\n\n');
            relevant.forEach((d) => {
                const sev = d.severity === vscode.DiagnosticSeverity.Error ? '❌' : '⚠️';
                const matched = findings.find((f) => f.rule_id === d.code);
                const owasp = matched ? matched.owasp_ref : 'N/A';
                const cwe = matched ? matched.cwe_id : 'N/A';
                const suggestion = matched ? matched.suggestion : 'N/A';
                markdown.appendMarkdown(`${sev} **${d.code}**: ${d.message}\n\n`);
                markdown.appendMarkdown(`> OWASP: ${owasp} | CWE: ${cwe}\n\n`);
                markdown.appendMarkdown(`💡 **Suggestion:** ${suggestion}\n\n`);
            });
            return new vscode.Hover(markdown);
        },
    });
    context.subscriptions.push(changeListener, saveListener, scanCommand, fixCommand, fixDiagnosticCmd, quickFixProvider, scoreCommand, vscode.commands.registerCommand('secureCoding.showBackendLog', () => backend.showLog()), vscode.commands.registerCommand('secureCoding.installLocalAI', async () => {
        const model = vscode.workspace.getConfiguration('secureCoding').get('aiModel', 'qwen2.5-coder:1.5b-instruct');
        const choice = await vscode.window.showInformationMessage('Install local AI (Ollama) for AI-powered fixes?', { modal: true }, 'Open Ollama website', 'Download & install model');
        if (choice === 'Open Ollama website') {
            await vscode.env.openExternal(vscode.Uri.parse('https://ollama.com/download'));
        }
        else if (choice === 'Download & install model') {
            const terminal = vscode.window.createTerminal('Ollama Install');
            terminal.sendText(`ollama pull ${model}`);
            terminal.show();
            vscode.window.showInformationMessage(`Pulling ${model} in terminal. AI fixes will work once the download completes.`);
        }
    }), vscode.commands.registerCommand('secureCoding.fixAllFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('No active editor');
            return;
        }
        await fixAllFile(editor.document, diagnosticCollection, findingsByUri, () => scanDocument(editor.document));
    }), hoverProvider);
    // A1: ensure backend is up before first scan (bundled exe, zero terminal)
    void (async () => {
        const ok = await backend.ensureRunning(context, statusBarItem);
        statusBarItem.text = ok ? '🔒 CodeShield' : '🔒 CodeShield (offline)';
        aiStatusBarItem.text = backend.ollamaStatusText();
        aiStatusBarItem.tooltip = backend.isOllamaModelAvailable()
            ? 'Local AI ready — click to reinstall Ollama'
            : 'Local AI not available — click to install Ollama';
        if (ok) {
            const activeEditor = vscode.window.activeTextEditor;
            if (activeEditor) {
                void scanDocument(activeEditor.document);
            }
        }
    })();
    // Scan active file on activation (after backend ready, see above)
}
function findingsToRequest(diagnostic, document) {
    const range = diagnostic.range;
    const codeSnippet = document.getText(range);
    const findingData = {
        rule_id: diagnostic.code,
        title: diagnostic.title || 'Vulnerability',
        severity: diagnostic.severity === vscode.DiagnosticSeverity.Error ? 'critical' : 'medium',
        cwe_id: 'N/A',
        owasp_ref: 'N/A',
        language: document.languageId,
        code_snippet: codeSnippet,
        context: {},
    };
    return { findingData, range };
}
async function requestSuggestion(findingData, backendUrl) {
    // C3: read AI API key from VS Code secrets (never plaintext config)
    const aiConfig = {
        ai_api_base: vscode.workspace.getConfiguration('secureCoding').get('aiApiBase', 'http://localhost:11434/v1'),
        ai_api_key: await secretStorage?.get('secureCoding.aiApiKey') ?? 'ollama',
        ai_model: vscode.workspace.getConfiguration('secureCoding').get('aiModel', 'codellama:7b-instruct'),
    };
    const response = await fetch(`${backendUrl}/suggest-fix`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...findingData, context: aiConfig }),
    });
    if (!response.ok) {
        const text = await response.text().catch(() => 'Unknown error');
        throw new Error(`AI request failed: ${response.status} ${text}`);
    }
    const data = (await response.json());
    if (!data.secure_code) {
        return data;
    }
    return data;
}
function diagnosticsToFindings(diagnostics) {
    return diagnostics.map((d) => ({
        rule_id: d.code,
        title: d.title || 'Vulnerability',
        severity: d.severity === vscode.DiagnosticSeverity.Error ? 'critical' : 'medium',
        cwe_id: d.cwe_id || 'N/A',
        owasp_ref: d.owasp_ref || 'N/A',
        message: d.message,
        line: d.range.start.line + 1,
        column: d.range.start.character,
        end_line: d.range.end.line + 1,
        end_column: d.range.end.character,
        suggestion: d.suggestion || '',
        code_snippet: '',
    }));
}
// FR-04: Fix All Current File — applies every rule-based template fix at once
async function fixAllFile(document, diagnosticCollection, findingsByUri, rescan) {
    const diagnostics = diagnosticCollection.get(document.uri) || [];
    const edits = [];
    for (const d of diagnostics) {
        if (d.source !== 'Secure Coding')
            continue;
        const ruleId = String(d.code || '');
        const template = templateFix(document.languageId, d.message, ruleId);
        if (template) {
            edits.push({ range: d.range, newText: template });
        }
    }
    if (edits.length === 0) {
        vscode.window.showInformationMessage('No fixable vulnerabilities found in this file');
        return;
    }
    // Sort by start line descending so replacements don't invalidate earlier ranges
    edits.sort((a, b) => b.range.start.line - a.range.start.line || b.range.start.character - a.range.start.character);
    const edit = new vscode.WorkspaceEdit();
    for (const e of edits) {
        edit.replace(document.uri, e.range, e.newText);
    }
    const fixedCount = edits.length;
    const fileName = document.uri.path.split(/[\\/]/).pop() || document.uri.toString();
    const applied = await vscode.workspace.applyEdit(edit);
    if (applied) {
        vscode.window.showInformationMessage(`Applied ${fixedCount} quick fix(es) to ${fileName}`);
        // Re-scan after fixes to clear resolved diagnostics
        void rescan();
    }
    else {
        vscode.window.showErrorMessage('Failed to apply fixes');
    }
}
function deactivate() { }
// FR-04 helpers: instant rule-based templates + shared AI-apply flow
function templateFix(languageId, message, ruleId) {
    const lang = languageId === 'js' ? 'javascript' : languageId;
    if (lang === 'python' && ruleId === 'PY-SQLI-001') {
        return 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))';
    }
    if (lang === 'python' && ruleId === 'PY-SECRETS-001') {
        return 'import os\nPASSWORD = os.environ["DB_PASSWORD"]';
    }
    if (lang === 'javascript' && ruleId === 'JS-SQLI-001') {
        return "db.query('SELECT * FROM users WHERE id = ?', [userId])";
    }
    if (lang === 'javascript' && ruleId === 'JS-XSS-001') {
        return 'el.textContent = msg;';
    }
    if (lang === 'javascript' && ruleId === 'JS-SECRETS-001') {
        return 'const API_KEY = process.env.API_KEY;';
    }
    return null;
}
async function applyAiFix(document, diagnostic, backendUrl, diagnosticCollection) {
    const allFindings = diagnosticCollection
        ? []
        : [];
    void allFindings;
    const range = diagnostic.range;
    const line = range.start.line + 1;
    const findingData = {
        rule_id: String(diagnostic.code || ''),
        title: 'Vulnerability',
        severity: diagnostic.severity === vscode.DiagnosticSeverity.Error ? 'critical' : 'medium',
        cwe_id: 'N/A',
        owasp_ref: 'N/A',
        language: document.languageId,
        code_snippet: document.getText(range),
        context: {
            line,
            end_line: range.end.line + 1,
            full_source: document.getText(),
        },
    };
    await vscode.window.withProgress({ location: vscode.ProgressLocation.Window, title: 'Generating secure fix with AI...' }, async () => {
        try {
            const suggestion = await requestSuggestion(findingData, backendUrl);
            if (!suggestion.secure_code) {
                vscode.window.showWarningMessage('AI could not generate a fix for this issue');
                return;
            }
            const edit = new vscode.WorkspaceEdit();
            edit.replace(document.uri, range, suggestion.secure_code);
            const confirmed = await vscode.window.showInformationMessage('AI suggests the following fix. Apply it?', { modal: true }, 'Apply Fix', 'Show Explanation');
            if (confirmed === 'Apply Fix') {
                await vscode.workspace.applyEdit(edit);
                vscode.window.showInformationMessage('Fix applied');
            }
            else if (confirmed === 'Show Explanation') {
                const doc = await vscode.workspace.openTextDocument({
                    content: `# Fix\n\n${suggestion.explanation}\n\n## Suggested Fix\n\n\`\`\`\n${suggestion.secure_code}\n\`\`\`\n`,
                    language: 'markdown',
                });
                await vscode.window.showTextDocument(doc, { preview: true });
            }
        }
        catch (error) {
            vscode.window.showErrorMessage(`AI fix failed: ${error}`);
        }
    });
}
//# sourceMappingURL=extension.js.map