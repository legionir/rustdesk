'use strict';
// Hand-encoded protobuf envelopes with synthetic one-byte packets. These are
// NOT valid VP9 bitstreams and must never be passed to a native decoder.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');
const key = () => Buffer.from([0x32, 0x09, 0x32, 0x07, 0x0a, 0x05, 0x0a, 0x01, 0x07, 0x10, 0x01]);
const delta = () => Buffer.from([0x32, 0x07, 0x32, 0x05, 0x0a, 0x03, 0x0a, 0x01, 0x07]);

test('bounded frame queue invalidates stale in-flight frames on overflow', async () => {
  assert.throws(() => core.createViewerVideoQueue(-1, 'vp9', 2, 1024, 512));
  assert.throws(() => core.createViewerVideoQueue(0, 'rgb', 2, 1024, 512));
  assert.throws(() => core.createViewerVideoQueue(0, 'vp9', 0, 1024, 512));
  const queue = core.createViewerVideoQueue(0, 'vp9', 2, 1024, 512);
  assert.equal((await queue.push(delta())).kind, 'awaitKeyframe');
  assert.deepEqual(await queue.push(key()), { kind: 'keyframe', discarded: 0 });
  const first = queue.pop(); assert.equal(first.keyframe, true); assert.equal(queue.isCurrent(first.token), true);
  assert.throws(() => queue.pop());
  assert.equal((await queue.push(delta())).kind, 'queued');
  assert.deepEqual(await queue.push(delta()), { kind: 'needRefresh', discarded: 2 });
  assert.equal(queue.isCurrent(first.token), false);
  assert.equal(queue.complete(first.token, true), 'stale');
  assert.equal(queue.stats().accountedBytes, 0);
  assert.equal((await queue.push(key())).kind, 'keyframe');
  const fresh = queue.pop(); assert.equal(queue.complete(fresh.token, true), 'applied');
  assert.equal(queue.stats().synced, true);
  assert.throws(() => queue.complete('01', true));
  assert.throws(() => queue.push(Buffer.alloc(513)));
  await assert.rejects(queue.push(Buffer.from([0xff])));
  assert.equal(queue.stats().synced, true);
});

test('caller resets after an input error to invalidate current decode', async () => {
  const queue = core.createViewerVideoQueue(0, 'vp9', 2, 1024, 512);
  await queue.push(key());
  const frame = queue.pop();
  await assert.rejects(queue.push(Buffer.from([0xff])));
  // Errors deliberately do not mutate the queue: the caller must apply loss
  // policy before accepting more frames, even if parsing failed.
  assert.equal(queue.isCurrent(frame.token), true);
  queue.reset();
  assert.equal(queue.isCurrent(frame.token), false);
  assert.equal(queue.complete(frame.token, true), 'stale');
  assert.equal((await queue.push(delta())).kind, 'awaitKeyframe');
});
