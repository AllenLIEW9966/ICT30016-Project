import sys

with open('c:/Users/User/secure-coding-assistant/extension/src/extension.ts', 'r', encoding='utf-8') as f:
    content = f.read()

old = """          const edit = new vscode.WorkspaceEdit();
          edit.replace(document.uri, findingRange, suggestion.secure_code);"""

new = """        const edit = new vscode.WorkspaceEdit();
        const explanation = suggestion.explanation || 'Security fix applied';
        const secureCode = suggestion.secure_code.trim();
        let replacement: string;
        if (document.languageId === 'python') {
          replacement = `# ${explanation}\n${secureCode}`;
        } else if (document.languageId === 'javascript') {
          replacement = `// ${explanation}\n${secureCode}`;
        } else {
          replacement = secureCode;
        }
        edit.replace(document.uri, findingRange, replacement);"""

if old in content:
    content = content.replace(old, new, 1)
    with open('c:/Users/User/secure-coding-assistant/extension/src/extension.ts', 'w', encoding='utf-8') as f:
        f.write(content)
    print('SUCCESS')
else:
    print('FAILED - old text not found')
    idx = content.find('edit.replace(document.uri, findingRange')
    if idx >= 0:
        print(repr(content[idx:idx+100]))