// Run in an isolated Extension Development Host with a synthetic demo.py file.
const vscode = require('vscode');
const fs = require('node:fs');
const assert = require('node:assert/strict');

exports.run = async () => {
  const originalWarning = vscode.window.showWarningMessage;
  const observations = [];
  let decision;
  let mutate = false;
  try {
    await vscode.extensions.getExtension('your-name.secure-coding-assistant').activate();
    const uri = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri,'demo.py');
    const document = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(document);
    async function scan() {
      const deadline = Date.now() + 30000;
      do {
        await vscode.commands.executeCommand('secureCoding.scanCurrentFile');
        if (vscode.languages.getDiagnostics(uri).filter(d => d.code === 'PY-SECRETS-001').length === 2) return;
        await new Promise(resolve => setTimeout(resolve,500));
      } while (Date.now() < deadline);
      throw new Error('Expected two secret findings in synthetic document');
    }
    await scan();
    const warning = async (message, options, ...items) => {
      if (!message.startsWith('Are you sure you want to fix all')) return undefined;
      observations.push({message,options,items});
      assert.equal(message,'Are you sure you want to fix all 2 issues in this file?');
      assert.equal(options.modal,true);
      assert.deepEqual(items,['Confirm']);
      if (mutate) {
        const edit = new vscode.WorkspaceEdit();
        edit.insert(uri,document.positionAt(document.getText().length),'\n# edited during confirmation');
        assert.equal(await vscode.workspace.applyEdit(edit),true);
      }
      return decision;
    };
    // Substitute the dialog response while exercising the real registered command
    // and real VS Code document/edit APIs, without requiring a person to click.
    vscode.window.showWarningMessage = warning;
    assert.equal(vscode.window.showWarningMessage,warning);
    async function invoke() {
      const count = observations.length;
      for (let attempt = 0; attempt < 10; attempt++) {
        await scan();
        await vscode.commands.executeCommand('secureCoding.fixAllFile');
        if (observations.length > count) return;
        // Startup workspace scanning may briefly replace the active-file scan.
        await new Promise(resolve => setTimeout(resolve,250));
      }
      throw new Error('Fix All did not reach its confirmation dialog');
    }
    const before = document.getText();
    await invoke();
    assert.equal(document.getText(),before,'Cancel must leave source unchanged');
    decision = 'Confirm';
    mutate = true;
    await invoke();
    const newline = document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n';
    assert.equal(document.getText(),before+newline+'# edited during confirmation','Stale patches must be rejected');
    mutate = false;
    await scan();
    await invoke();
    assert.ok(document.getText().includes('os.environ['));
    assert.ok(!document.getText().includes('demo-token'));
    assert.ok(!document.getText().includes('demo-password'));
    assert.equal(observations.length,3);
    fs.writeFileSync(process.env.CODESHIELD_E2E_RESULT,JSON.stringify({passed:true,checks:['cancel','stale document','confirm'],dialogs:observations},null,2));
  } catch (error) {
    fs.writeFileSync(process.env.CODESHIELD_E2E_RESULT,JSON.stringify({passed:false,error:String(error.stack||error)},null,2));
    throw error;
  } finally {
    vscode.window.showWarningMessage = originalWarning;
  }
};
