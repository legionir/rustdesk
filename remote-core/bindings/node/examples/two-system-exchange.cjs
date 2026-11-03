'use strict';
// Side-effect-light orchestration for one bounded manual diagnostic. These
// methods trust only the caller's connected API object; they do not establish
// identity, enforce consent, validate compressed video or decode pixels.
const { performance } = require('node:perf_hooks');
const MAX_CONTROL_MESSAGES = 20;
const FRAME_WAIT_MS = 30000;
const RECEIPT_WAIT_MS = 10000;
function remaining(end, now) {
  const ms = Math.ceil(end - now());
  if (ms <= 0) throw new Error('diagnostic receive deadline expired');
  return ms;
}
async function receiveOneFrame(viewer, display, now = () => performance.now()) {
  const end = now() + FRAME_WAIT_MS;
  for (let i = 0; i < MAX_CONTROL_MESSAGES; i++) {
    const message = await viewer.receive(remaining(end, now));
    if (now() >= end) throw new Error('diagnostic receive deadline expired');
    if (message.kind !== 'video') continue;
    if (message.display !== display || message.codec !== 'vp9' || !Buffer.isBuffer(message.data) || message.data.length === 0) {
      throw new Error('unexpected video stream');
    }
    // Existing connection-wide notice is an untrusted claim, not proof of
    // decode or render. It has no stream or sequence; never retry failures.
    // Its send deadline is separate from the receive deadline.
    await viewer.notifyVideoReceived(10000);
    return message.data.length;
  }
  throw new Error('no video within the control-message limit');
}
async function receiveOneReceipt(session, now = () => performance.now()) {
  const end = now() + RECEIPT_WAIT_MS;
  for (let i = 0; i < MAX_CONTROL_MESSAGES; i++) {
    const receipt = await session.receiveEvent(remaining(end, now));
    if (now() >= end) throw new Error('diagnostic receive deadline expired');
    if (receipt.kind === 'frameReceived') return;
    // Heartbeat processing has already occurred in the host binding. Never
    // skip arbitrary peer requests or retry a failed/uncertain send.
    if (receipt.kind !== 'heartbeat') throw new Error('expected frame-received notification');
  }
  throw new Error('no receipt within the control-message limit');
}
module.exports = { receiveOneFrame, receiveOneReceipt, MAX_CONTROL_MESSAGES, FRAME_WAIT_MS, RECEIPT_WAIT_MS };
