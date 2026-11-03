'use strict';
// Deterministic orchestration fixtures only. Not a real network, security,
// native codec, interactive desktop, or pixel-correctness test.
const test = require('node:test');
const assert = require('node:assert/strict');
const { receiveOneFrame, receiveOneReceipt, MAX_CONTROL_MESSAGES, FRAME_WAIT_MS, RECEIPT_WAIT_MS } = require('../examples/two-system-exchange.cjs');
function viewer(messages, notifyError) {
  let reads = 0, acks = 0;
  return {
    async receive(timeout) { assert.ok(timeout > 0 && timeout <= FRAME_WAIT_MS); reads++; return messages.shift(); },
    async notifyVideoReceived(timeout) { assert.equal(timeout, 10000); acks++; if (notifyError) throw notifyError; },
    counts() { return { reads, acks }; },
  };
}
const video = () => ({ kind: 'video', display: 1, codec: 'vp9', data: Buffer.from([1, 2, 3]) });
test('one valid envelope is acknowledged after bounded control messages', async () => {
  const v = viewer([{ kind: 'cursor' }, video()]);
  assert.equal(await receiveOneFrame(v, 1), 3);
  assert.deepEqual(v.counts(), { reads: 2, acks: 1 });
});
test('invalid stream is rejected without sending an acknowledgement', async () => {
  for (const bad of [
    { ...video(), display: 0 }, { ...video(), codec: 'av1' },
    { ...video(), data: Buffer.alloc(0) }, { ...video(), data: [1] },
  ]) {
    const v = viewer([bad]);
    await assert.rejects(receiveOneFrame(v, 1), /unexpected video/);
    assert.deepEqual(v.counts(), { reads: 1, acks: 0 });
  }
});
test('control flood is bounded and no notification is sent', async () => {
  const v = viewer(Array.from({ length: MAX_CONTROL_MESSAGES }, () => ({ kind: 'cursor' })));
  await assert.rejects(receiveOneFrame(v, 1), /control-message limit/);
  assert.deepEqual(v.counts(), { reads: MAX_CONTROL_MESSAGES, acks: 0 });
});
test('uncertain send failure is propagated without retry', async () => {
  const failure = new Error('uncertain'); const v = viewer([video()], failure);
  await assert.rejects(receiveOneFrame(v, 1), error => error === failure);
  assert.deepEqual(v.counts(), { reads: 1, acks: 1 });
});
test('receipt is a single untrusted claim, never retried', async () => {
  let reads = 0;
  await receiveOneReceipt({ async receiveEvent(timeout) { reads++; assert.ok(timeout > 0 && timeout <= RECEIPT_WAIT_MS); return { kind: 'frameReceived' }; } });
  assert.equal(reads, 1);
  await assert.rejects(receiveOneReceipt({ async receiveEvent() { reads++; return { kind: 'mouse' }; } }), /expected/);
  assert.equal(reads, 2);
});

test('receipt tolerates bounded heartbeat traffic but not other control messages', async () => {
  const messages = [{ kind: 'heartbeat' }, { kind: 'heartbeat' }, { kind: 'frameReceived' }];
  let reads = 0;
  await receiveOneReceipt({ async receiveEvent() { reads++; return messages.shift(); } });
  assert.equal(reads, 3);
  await assert.rejects(receiveOneReceipt({ async receiveEvent() { return { kind: 'heartbeat' }; } }), /control-message limit/);
});
test('receive has one shared monotonic deadline, including time spent between messages', async () => {
  let time = 0, reads = 0;
  const clock = () => time;
  await assert.rejects(receiveOneFrame({ async receive() { reads++; time += FRAME_WAIT_MS; return video(); } }, 1, clock), /deadline/);
  assert.equal(reads, 1);
  time = 0; reads = 0;
  await assert.rejects(receiveOneReceipt({ async receiveEvent() { reads++; time += RECEIPT_WAIT_MS; return { kind: 'frameReceived' }; } }, clock), /deadline/);
  assert.equal(reads, 1);
});
