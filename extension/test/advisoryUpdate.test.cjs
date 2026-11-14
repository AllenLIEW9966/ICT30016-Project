const test = require('node:test');
const assert = require('node:assert/strict');
const { publishCurrentAdvisories } = require('../out/advisoryUpdate');

for (const changed of [false, true]) {
  test(changed ? 'edited buffer rejects delayed result' : 'unchanged buffer accepts result', async () => {
    let version = 1;
    let resolve;
    const pending = new Promise(done => { resolve = done; });
    const published = [];
    const update = publishCurrentAdvisories(() => pending, async () => true,
      () => version === 1, items => published.push(...items));
    if (changed) version++;
    resolve(['advisory']);
    await update;
    assert.deepEqual(published, changed ? [] : ['advisory']);
  });
}
test('new scan during disk content check wins', async () => {
  let current = true;
  let applied = false;
  await publishCurrentAdvisories(async () => ['old'], async () => {
    current = false;
    return true;
  }, () => current, () => { applied = true; });
  assert.equal(applied, false);
});
