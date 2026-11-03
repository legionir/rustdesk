'use strict';
// Synthetic malformed envelopes only; no network or OS display changes.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');

test('display metadata inspection enforces size and message kind', async () => {
  assert.throws(() => core.inspectDisplayChange(Buffer.alloc(0)));
  assert.throws(() => core.inspectDisplayChange(Buffer.alloc(128 * 1024 + 1)));
  const cursor = core.encodeCursorPosition(0, 0);
  await assert.rejects(core.inspectDisplayChange(cursor));
});

test('inspect a source display announcement and mode claims', async () => {
  // Minimal protobuf wire fixture: Message.misc=19, Misc.switch_display=5;
  // source SwitchDisplay fields 1, 4, 5, 7 and 8, Resolution fields 1 and 2.
  function varint(value) {
    const bytes = [];
    do { let b = value & 0x7f; value = Math.floor(value / 128); if (value) b |= 0x80; bytes.push(b); } while (value);
    return Buffer.from(bytes);
  }
  const field = (tag, value) => Buffer.concat([varint(tag << 3), varint(value)]);
  const nested = (tag, value) => Buffer.concat([varint((tag << 3) | 2), varint(value.length), value]);
  const mode = Buffer.concat([field(1, 1920), field(2, 1080)]);
  const modes = nested(1, mode);
  const change = Buffer.concat([field(1, 1), field(4, 1280), field(5, 720), nested(7, modes), nested(8, mode)]);
  const wire = nested(19, nested(5, change));
  const result = await core.inspectDisplayChange(wire);
  assert.equal(result.display, 1);
  assert.equal(result.width, 1280); assert.equal(result.height, 720);
  assert.deepEqual(result.supportedModes, [{ width: 1920, height: 1080 }]);
  assert.deepEqual(result.original, { width: 1920, height: 1080 });
});
