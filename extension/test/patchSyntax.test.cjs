const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../out/extension.js'),'utf8');

test('AI validation requires parser confirmation and detects syntax errors', async () => {
  let response;
  const context = {fetch:async (_url, options) => {
    assert.equal(JSON.parse(options.body).require_ast,true);
    return {ok:true,json:async()=>response};
  }};
  vm.createContext(context);
  vm.runInContext(source.slice(source.indexOf('async function validateAiPreview('))+ '\nthis.validate = validateAiPreview;',context);
  response = {ast_validated:true,findings:[{rule_id:'PARSE-ERROR',message:'invalid syntax'}]};
  assert.ok((await context.validate('python','bad','a.py','local','rule',[])).syntaxError);
  response = {findings:[]};
  await assert.rejects(context.validate('javascript','bad','a.js','local','rule',[]),/AST syntax validation/);
});

for (const language of ['python','javascript']) {
  test(`invalid ${language} candidate cannot open a preview or apply edits`,async()=>{
    const original = 'original source';
    const range = {start:{line:0,character:0},end:{line:0,character:15}};
    const errors = [];
    let requests = 0;
    const forbidden = () => { throw new Error('Invalid patch reached preview or edit API'); };
    const context = {
      vscode:{
        ProgressLocation:{Window:1},
        window:{withProgress:async (_opts,callback)=>callback(),showErrorMessage:async message=>errors.push(message),
          showInformationMessage:forbidden,showWarningMessage:forbidden},
        workspace:{getConfiguration:()=>({get:(_key,value)=>value}),openTextDocument:forbidden,applyEdit:forbidden},
        commands:{executeCommand:forbidden},WorkspaceEdit:forbidden,
      },
      aiContext_1:require('../out/aiContext'),
      aiFixRange:()=>range,
      requestSuggestion:async()=>{requests++;return {can_fix:true,secure_code:'broken patch',source:'provider'};},
      prepareAiReplacementWithImports:()=>({text:'broken patch'}),
      addsImportOutsideRange:()=>false,
      composeAiPreview:()=> 'invalid candidate source',
      validateAiPreview:async()=>({syntaxError:'invalid syntax'}),
    };
    vm.createContext(context);
    const start = source.indexOf('async function applyAiFix(');
    const end = source.indexOf('\nfunction addsImportOutsideRange',start);
    vm.runInContext(source.slice(start,end)+'\nthis.apply = applyAiFix;',context);
    const document = {languageId:language,version:1,fileName:'synthetic',getText:()=>original,offsetAt:p=>p.character};
    await context.apply(document,{range,code:'test'},{title:'test'},'local',forbidden,forbidden,[],[]);
    assert.equal(requests,2); // A repair retry also failed and stays blocked.
    assert.deepEqual(errors,['AI 返回的修复代码存在语法错误，已自动拦截']);
    assert.equal(document.getText(),original);
  });
}
