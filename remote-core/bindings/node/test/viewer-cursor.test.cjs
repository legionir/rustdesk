'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');
const meta = id => ({ id, hotx: 0, hoty: 0, width: 1, height: 1 });

test('bounded cursor selection, eviction and explicit stale resend', () => {
  assert.throws(() => core.createViewerCursor(0, 4));
  const cursor = core.createViewerCursor(2, 8);
  assert.equal(cursor.select('18446744073709551615'), false);
  assert.equal(cursor.stats().selectedId, '18446744073709551615');
  assert.ok(cursor.selectedShape() == null);
  cursor.observeShape(meta('1'), Buffer.from([1, 2, 3, 4]), true);
  const image = cursor.selectedShape(); assert.deepEqual([...image.rgba], [1, 2, 3, 4]);
  image.rgba[0] = 9; assert.equal(cursor.selectedShape().rgba[0], 1);
  cursor.observeShape(meta('2'), Buffer.from([5, 6, 7, 8]), true);
  cursor.observeShape(meta('3'), Buffer.from([9, 10, 11, 12]), true);
  assert.equal(cursor.select('1'), false);
  assert.equal(cursor.select('3'), true);
  cursor.observeShape(meta('1'), Buffer.from([1, 2, 3, 4]), false);
  assert.equal(cursor.stats().selectedId, '3');
  assert.throws(() => cursor.observeShape(meta('4'), Buffer.alloc(3), true));
  assert.equal(cursor.stats().selectedId, '3');
  assert.throws(() => cursor.select('01'));
  cursor.observePosition(-40, 5); assert.deepEqual(cursor.position(), { x: -40, y: 5 });
  assert.equal(cursor.stats().retainedBytes, 8);
  cursor.clear(); assert.ok(cursor.selectedShape() == null); assert.ok(cursor.position() == null);
  assert.equal(cursor.stats().cached, 0);
});
