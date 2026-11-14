const {test} = require('node:test');
const assert = require('node:assert/strict');
const {aiSourceWindow} = require('../out/aiContext');

const lines = Array.from({length:100}, (_, i) => `line_${i + 1}`);
test('middle finding includes exactly 20 lines on each side with original coordinates', () => {
  const context = aiSourceWindow(lines.join('\r\n'), 50);
  assert.deepEqual(context, {
    source_window: lines.slice(29, 70).join('\n'),
    source_start_line:30, source_end_line:70, source_total_lines:100,
  });
  assert.equal(context.source_window.split('\n')[20], 'line_50');
  assert.equal('full_source' in context, false);
});
test('file boundaries produce complete available lines', () => {
  assert.equal(aiSourceWindow(lines.join('\n'), 1).source_window, lines.slice(0,21).join('\n'));
  assert.equal(aiSourceWindow(lines.join('\n'), 100).source_window, lines.slice(79).join('\n'));
  assert.equal(aiSourceWindow('first\nlast',2).source_window,'first\nlast');
});
test('a long source line is retained in full', () => {
  const longLine = `const message = "${'x'.repeat(3000)}";`;
  assert.equal(aiSourceWindow(longLine,1).source_window,longLine);
});
