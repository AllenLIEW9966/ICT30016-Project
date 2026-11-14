const vscode = require('vscode');
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

exports.run = async () => {
  try {
    const source = fs.readFileSync(require.resolve('../out/extension'),'utf8');
    const context = {vscode,pythonImports_1:require('../out/pythonImports')};
    vm.createContext(context);
    const indent = source.slice(source.indexOf('function indentReplacement('), source.indexOf('function expandedFixRange('));
    const insert = source.slice(source.indexOf('function addDeterministicReplacement('), source.indexOf('function templateFix('));
    vm.runInContext(indent+insert+'\nthis.add = addDeterministicReplacement;',context);
    const fixtures = [
      'import os\r\n\r\ndef f(data):\r\n    return old(data)\r\n',
      'digest = old(data)',
      'a = old(data)\nb = old(data)\n',
      'import bcrypt\n\ndigest = old(data)\n',
    ];
    for (const content of fixtures) {
      const doc = await vscode.workspace.openTextDocument({language:'python',content});
      const edit = new vscode.WorkspaceEdit();
      for (let line=0;line<doc.lineCount;line++) {
        const text = doc.lineAt(line).text;
        if (!text.includes('old(data)')) continue;
        const indent = text.match(/^\s*/)[0].length;
        const range = new vscode.Range(line,indent,line,text.length);
        context.add(edit,doc,range,text.slice(indent).replace('old(data)','bcrypt.hashpw(data, bcrypt.gensalt())'));
      }
      assert.equal(await vscode.workspace.applyEdit(edit),true);
      const updated = doc.getText();
      assert.equal((updated.match(/^import bcrypt\s*$/gm)||[]).length,1);
      assert.ok(!updated.includes('old(data)'));
      if (content.includes('import os')) {
        assert.ok(updated.startsWith('import os\r\nimport bcrypt\r\n'));
        assert.ok(updated.includes('\r\n    return bcrypt.hashpw'));
      }
    }
    fs.writeFileSync(process.env.CODESHIELD_E2E_RESULT,JSON.stringify({passed:true,fixtures:fixtures.length}));
  } catch(error) {
    fs.writeFileSync(process.env.CODESHIELD_E2E_RESULT,JSON.stringify({passed:false,error:String(error.stack||error)}));
    throw error;
  }
};
