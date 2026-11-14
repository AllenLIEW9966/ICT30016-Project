// Run with VS Code's --extensionTestsPath and an isolated requirements.txt workspace.
const vscode = require('vscode');
const fs = require('node:fs');
const assert = require('node:assert/strict');

exports.run = async () => {
  const resultPath = process.env.CODESHIELD_E2E_RESULT;
  try {
    const extension = vscode.extensions.getExtension('your-name.secure-coding-assistant');
    assert.ok(extension, 'CodeShield extension is registered');
    await extension.activate();
    const uri = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, 'requirements.txt');
    const document = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(document);
    assert.equal(vscode.workspace.getConfiguration('secureCoding').get('osvAdvisories'), true);
    assert.equal(vscode.workspace.isTrusted, true);
    await vscode.commands.executeCommand('secureCoding.scanCurrentFile');
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      const findings = vscode.languages.getDiagnostics(uri).filter(d => d.code === 'CS-A03-OSV');
      if (findings.length) {
        assert.ok(findings.some(d => /CVE-/.test(d.message)), 'Expected CVE alias');
        assert.ok(findings.every(d => d.range.start.line === 0), 'Expected dependency line');
        fs.writeFileSync(resultPath, JSON.stringify({passed: true, uri: uri.toString(), diagnostics: findings.map(d => d.message)}, null, 2));
        return;
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    throw new Error('Timed out waiting for CS-A03-OSV on requirements.txt');
  } catch (error) {
    fs.writeFileSync(resultPath, JSON.stringify({passed: false, error: String(error.stack || error)}, null, 2));
    throw error;
  }
};
