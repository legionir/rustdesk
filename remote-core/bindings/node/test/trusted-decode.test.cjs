'use strict';
// Deferred validation only. No real desktop is accessed by these cases.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');
test('requires an explicit trusted-input acknowledgement and a bounded batch', () => {
  assert.throws(() => core.decodeTrustedVideoBatch([Buffer.from([1])], false));
  assert.throws(() => core.decodeTrustedVideoBatch([], true));
  assert.throws(() => core.decodeTrustedVideoBatch(Array(33).fill(Buffer.from([1])), true));
  assert.throws(() => core.decodeTrustedVideoBatch([Buffer.alloc(0)], true));
});
test('invalid protobuf is rejected on the worker', async () => {
  await assert.rejects(core.decodeTrustedVideoBatch([Buffer.from([0xff])], true));
});
