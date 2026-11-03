'use strict';
// Separate test file/process: the worker cap is process-local, not global OS
// accounting. Uses only decoder registration and never feeds a native stream.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');
test('trusted workers are capped and reject overlapping operations', async () => {
  const first = core.createTrustedVideoWorker(4096, 4096, true);
  let second;
  try {
    second = core.createTrustedVideoWorker(4096, 4096, true);
    assert.throws(() => core.createTrustedVideoWorker(4096, 4096, true), /maximum/);
    const pending = first.register(0, 'vp9');
    assert.throws(() => first.reset(0), /operation in progress/);
    assert.throws(() => first.close(), /operation in progress/);
    assert.equal((await pending).kind, 'ok');
  } finally {
    first.close(); if (second) second.close();
  }
  // close releases asynchronously. Immediate slot reuse is deliberately not
  // asserted, and blocked native operations cannot be interrupted by close.
});
