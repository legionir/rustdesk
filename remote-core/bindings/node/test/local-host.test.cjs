'use strict';
// Deferred argument validation only; invalid calls do not bind a socket.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');
test('rejects invalid local host options before scheduling work', () => {
  assert.throws(() => core.listenLocalHost({ hostId: '', password: 'test', timeoutMs: 1000 }));
  assert.throws(() => core.listenLocalHost({ hostId: 'test', password: '', timeoutMs: 1000 }));
  assert.throws(() => core.listenLocalHost({ hostId: 'test', password: 'test', timeoutMs: 0 }));
});
