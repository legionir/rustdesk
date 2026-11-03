'use strict';
// Deferred tests. No OS mode changes; real enumeration is opt-in.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');
test('mode inspection requires local consent and bounded index', () => {
  assert.throws(() => core.inspectWindowsDisplayModes(0, false));
  assert.throws(() => core.inspectWindowsDisplayModes(64, true));
});
test('read-only Windows mode query', { skip: process.platform !== 'win32' || process.env.REMOTE_CORE_ALLOW_REAL_CAPTURE !== '1' }, async () => {
  const result = await core.inspectWindowsDisplayModes(0, true);
  assert.ok(result.deviceName.length > 0);
  assert.ok(result.current.width > 0 && result.current.height > 0);
  assert.ok(result.modes.length <= 512);
});
