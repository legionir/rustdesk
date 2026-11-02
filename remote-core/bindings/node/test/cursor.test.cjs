'use strict';
// Synthetic protocol cases; no desktop, networking or permission UI.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');

test('RustDesk cursor shape and a full 64-bit ID round trip', async () => {
  const metadata = { id: '18446744073709551615', hotx: 0, hoty: 1, width: 2, height: 2 };
  const rgba = Buffer.from([255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 0, 0, 0, 0]);
  const wire = await core.encodeCursorShape(rgba, metadata);
  const decoded = await core.decodeCursorShape(wire);
  assert.deepEqual(decoded, { ...metadata, rgba });
  assert.ok(core.encodeCursorId(metadata.id).length > 0);
  assert.ok(core.encodeCursorPosition(-20, 100).length > 0);
});

test('rejects invalid lengths, hotspots and noncanonical IDs', () => {
  assert.throws(() => core.encodeCursorId('01'));
  assert.throws(() => core.encodeCursorId('18446744073709551616'));
  assert.throws(() => core.encodeCursorShape(Buffer.alloc(8), { id: '1', hotx: 0, hoty: 0, width: 2, height: 2 }));
  assert.throws(() => core.encodeCursorShape(Buffer.alloc(16), { id: '1', hotx: 2, hoty: 0, width: 2, height: 2 }));
});
