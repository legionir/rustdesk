'use strict';
// Run only after building the native addon and completing extraction.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');
const options = { width: 64, height: 64, stride: 256, codec: 'vp9', pixelFormat: 'bgra', quality: 1, ptsMs: 0 };

test('encodes a synthetic independent frame', async () => {
  const frame = await core.encodeFrame(Buffer.alloc(64 * 64 * 4, 128), options);
  assert.equal(frame.codec, 'vp9');
  assert.ok(frame.packets.length > 0);
  assert.ok(frame.packets.every(p => Buffer.isBuffer(p.data) && p.data.length > 0));
});
test('rejects invalid dimensions, truncated buffers and unknown formats', () => {
  const bytes = Buffer.alloc(64 * 64 * 4);
  assert.throws(() => core.encodeFrame(bytes, { ...options, width: 63 }));
  assert.throws(() => core.encodeFrame(Buffer.alloc(2), options));
  assert.throws(() => core.encodeFrame(bytes, { ...options, pixelFormat: 'xyz' }));
});
test('rejects concurrent pending encodes and permits a later one', async () => {
  const bytes = Buffer.alloc(64 * 64 * 4);
  const first = core.encodeFrame(bytes, options);
  assert.throws(() => core.encodeFrame(bytes, options));
  await first;
  const last = await core.encodeFrame(bytes, options);
  assert.ok(last.packets.length > 0);
});
