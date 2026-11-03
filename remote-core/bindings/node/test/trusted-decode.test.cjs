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

test('persistent trusted worker validates consent and bounds before starting', () => {
  assert.throws(() => core.createTrustedVideoWorker(1024, 4096, false));
  assert.throws(() => core.createTrustedVideoWorker(0, 4096, true));
  assert.throws(() => core.createTrustedVideoWorker(1024, 33 * 1024 * 1024, true));
});

test('persistent trusted worker owns decoder lifecycle and fails closed', async () => {
  const worker = core.createTrustedVideoWorker(4096, 1024 * 1024, true);
  try {
    assert.throws(() => worker.register(-1, 'vp9'));
    assert.throws(() => worker.register(0, 'h264'));
    assert.throws(() => worker.decode(Buffer.alloc(4097)));
    assert.equal((await worker.register(0, 'vp9')).kind, 'ok');
    // Wire is a synthetic predictive packet; no native decode is attempted
    // because the stream has not seen a keyframe.
    const delta = Buffer.from([0x32, 0x07, 0x32, 0x05, 0x0a, 0x03, 0x0a, 0x01, 0x07]);
    const waiting = await worker.decode(delta);
    assert.equal(waiting.kind, 'awaitKeyframe'); assert.equal(waiting.display, 0);
    assert.equal((await worker.reset(0)).kind, 'ok');
    assert.equal((await worker.remove(1)).kind, 'notFound');
    assert.equal((await worker.remove(0)).kind, 'removed');
    // The malformed protobuf fails before reaching any native bitstream decode.
    await assert.rejects(worker.decode(Buffer.from([0xff])));
    await assert.rejects(async () => worker.register(0, 'vp9'));
  } finally { worker.close(); }
});
