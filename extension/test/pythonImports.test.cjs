const {test} = require('node:test');
const assert = require('node:assert/strict');
const {bcryptImportInsertion} = require('../out/pythonImports');
const patch = 'return bcrypt.hashpw(password, bcrypt.gensalt())';

test('missing bcrypt is inserted after the first complete import with CRLF',()=>{
  const source = 'import os\r\n\r\ndef hash_password(password):\r\n    return old(password)\r\n';
  const insertion = bcryptImportInsertion(source,patch,'\r\n');
  assert.equal(insertion.offset,'import os\r\n'.length);
  assert.equal(insertion.text,'import bcrypt\r\n');
});
test('existing module imports are retained without duplicates',()=>{
  for (const source of ['import bcrypt\n','import bcrypt as bcrypt\n','import os, bcrypt\n','import os; import bcrypt\n']) {
    assert.equal(bcryptImportInsertion(source,patch,'\n'),undefined);
  }
});
test('aliased and function imports do not supply the bcrypt module binding',()=>{
  for (const source of ['import bcrypt as bc\n','from bcrypt import hashpw\n','def f():\n    import bcrypt\n']) {
    assert.ok(bcryptImportInsertion(source,patch,'\n'));
  }
});
test('docstrings, comments, future and multiline imports stay intact',()=>{
  const prefix = '#!/usr/bin/python\n# coding: utf-8\n"""import bcrypt\nDocumentation."""\nfrom __future__ import (\n annotations,\n)\nfrom os import (\n path,\n)\n';
  const source = prefix+'\ndef f():\n    return old()\n';
  const insertion = bcryptImportInsertion(source,patch,'\n');
  assert.equal(insertion.offset,prefix.length);
  assert.equal(source.slice(0,insertion.offset)+insertion.text+source.slice(insertion.offset),prefix+'import bcrypt\n\ndef f():\n    return old()\n');
});
test('files without imports and files without a final newline retain valid separators',()=>{
  assert.deepEqual(bcryptImportInsertion('def f():\n    pass',patch,'\n'),{offset:0,text:'import bcrypt\n'});
  assert.deepEqual(bcryptImportInsertion('"module doc"',patch,'\n'),{offset:12,text:'\nimport bcrypt\n'});
});
test('other modules and bcrypt mentions inside strings do not trigger insertion',()=>{
  assert.equal(bcryptImportInsertion('', 'return hashlib.sha256(data)', '\n'),undefined);
  assert.equal(bcryptImportInsertion('', 'return "bcrypt.hashpw(data)"', '\n'),undefined);
});
