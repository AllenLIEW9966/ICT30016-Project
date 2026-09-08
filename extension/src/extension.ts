import * as vscode from 'vscode';

type Finding = {
  rule_id: string;
  title: string;
  severity: string;
  cwe_id: string;
  owasp_ref: string;
  message: string;
  line: number;
  column: number;
  end_line: number;
  end_column: number;
  suggestion: string;
  code_snippet: string;
};

type SuggestionResponse = {
  explanation: string;
  secure_code: string;
  references: string[];
};

export function activate(context: vscode.ExtensionContext) {
  console.log('Secure Coding Assistant is now active');
  vscode.window.showInformationMessage('🔒 Secure Coding Assistant activated');

  const backendUrl = vscode.workspace.getConfiguration('secureCoding').get<string>('backendUrl', 'http://localhost:8000');
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('secureCoding');
  context.subscriptions.push(diagnosticCollection);

  // Keep finding metadata keyed by document URI so hover/fix can access OWASP/CWE/suggestion
  const findingsByUri = new Map<vscode.Uri, Finding[]>();

  let statusBarItem: vscode.StatusBarItem | undefined;
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = 'secureCoding.showSecurityScore';
  statusBarItem.tooltip = 'Security Score';
  statusBarItem.text = '🔒 ?';
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  let debounceTimer: NodeJS.Timeout | undefined;

  async function scanDocument(document: vscode.TextDocument): Promise<void> {
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

      const result = (await response.json()) as { findings: Finding[] };
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
      findingsByUri.set(document.uri, findings);
      const findingsMsg = findings.length > 0
        ? `Found ${findings.length} issue(s): ${findings.map(f => f.rule_id).join(', ')}`
        : 'No issues found';
      vscode.window.showInformationMessage(`🔒 Secure Coding: ${findingsMsg}`);
      updateStatusBar(findings);
    } catch (error) {
      console.error(`[Secure Coding] Scan failed: ${error}`);
    }
  }

  function updateStatusBar(findings: Finding[]) {
    const critical = findings.filter((f) => f.severity === 'critical').length;
    const high = findings.filter((f) => f.severity === 'high').length;
    const medium = findings.filter((f) => f.severity === 'medium').length;
    const low = findings.filter((f) => f.severity === 'low').length;

    let score: string;
    if (critical > 0) score = 'F';
    else if (high > 2) score = 'D';
    else if (high > 0 || medium > 2) score = 'C';
    else if (medium > 0 || low > 2) score = 'B';
    else score = 'A';

    statusBarItem!.text = `🔒 ${score}`;
    statusBarItem!.tooltip = `Security Score: ${score}\nCritical: ${critical}, High: ${high}, Medium: ${medium}, Low: ${low}`;
    statusBarItem!.show();
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
    debounceTimer = setTimeout(() => scanDocument(document), 800);
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

  // AI Fix command
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

    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: 'Generating secure fix with AI...' },
      async () => {
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

          const confirmed = await vscode.window.showInformationMessage(
            'AI suggests the following fix. Apply it?',
            { modal: true },
            'Apply Fix',
            'Show Explanation',
          );

          if (confirmed === 'Apply Fix') {
            await vscode.workspace.applyEdit(edit);
            vscode.window.showInformationMessage('Fix applied');
          } else if (confirmed === 'Show Explanation') {
            const doc = await vscode.workspace.openTextDocument({
              content: `# ${findingData.title}\n\n${suggestion.explanation}\n\n## Suggested Fix\n\n\`\`\`\n${suggestion.secure_code}\n\`\`\`\n`,
              language: 'markdown',
            });
            await vscode.window.showTextDocument(doc, { preview: true });
          }
        } catch (error) {
          vscode.window.showErrorMessage(`AI fix failed: ${error}`);
        }
      },
    );
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

  context.subscriptions.push(
    changeListener,
    saveListener,
    scanCommand,
    fixCommand,
    scoreCommand,
    hoverProvider,
  );

  // Scan active file on activation
  const activeEditor = vscode.window.activeTextEditor;
  if (activeEditor) {
    scanDocument(activeEditor.document);
  }
}

function findingsToRequest(
  diagnostic: vscode.Diagnostic,
  document: vscode.TextDocument,
): { findingData: { rule_id: string; title: string; severity: string; cwe_id: string; owasp_ref: string; language: string; code_snippet: string; context: any }; range: vscode.Range } | null {
  const range = diagnostic.range;
  const codeSnippet = document.getText(range);

  const findingData = {
    rule_id: diagnostic.code as string,
    title: (diagnostic as any).title || 'Vulnerability',
    severity: diagnostic.severity === vscode.DiagnosticSeverity.Error ? 'critical' : 'medium',
    cwe_id: 'N/A',
    owasp_ref: 'N/A',
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
  language: string;
  code_snippet: string;
  context: any;
}, backendUrl: string): Promise<SuggestionResponse> {
  const aiConfig = {
    ai_api_base: vscode.workspace.getConfiguration('secureCoding').get<string>('aiApiBase', 'http://localhost:11434/v1'),
    ai_api_key: vscode.workspace.getConfiguration('secureCoding').get<string>('aiApiKey', 'ollama'),
    ai_model: vscode.workspace.getConfiguration('secureCoding').get<string>('aiModel', 'codellama:7b-instruct'),
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
    message: d.message,
    line: d.range.start.line + 1,
    column: d.range.start.character,
    end_line: d.range.end.line + 1,
    end_column: d.range.end.character,
    suggestion: (d as any).suggestion || '',
    code_snippet: '',
  }));
}

export function deactivate() {}
