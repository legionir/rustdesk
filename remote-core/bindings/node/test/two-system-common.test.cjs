'use strict';
// Validation-only tests for the manual two-system diagnostic. No socket,
// native addon, credential, OS input or screen capture is touched.
const test = require('node:test');
const assert = require('node:assert/strict');
const common = require('../examples/two-system-common.cjs');

test('only literal bound addresses and canonical ports are accepted', () => {
  assert.equal(common.address('192.0.2.5', '0'), '192.0.2.5:0');
  assert.equal(common.address('2001:db8::1', '1234'), '[2001:db8::1]:1234');
  for (const ip of ['localhost', '0.0.0.0', '::', '0:0:0:0:0:0:0:0', '::ffff:0.0.0.0', 'fe80::1%1', 'bad']) assert.throws(() => common.address(ip, '1234'));
  for (const port of ['01', '-1', '+1', '65536', '1.5', '']) assert.throws(() => common.address('127.0.0.1', port));
});
test('peer and display inputs have local bounds', () => {
  assert.equal(common.permittedPeer('192.0.2.7'), '192.0.2.7');
  for (const ip of ['localhost', '0.0.0.0', '::', '0:0:0:0:0:0:0:0', '::ffff:0.0.0.0', 'fe80::1%1']) assert.throws(() => common.permittedPeer(ip));
  assert.equal(common.positiveInteger('63', 63, 'display'), 63);
  for (const value of ['64', '01', '-1', '2.0', '999999999999999999999']) {
    assert.throws(() => common.positiveInteger(value, 63, 'display'));
  }
});
test('demo password length uses UTF-8 bytes, not character count', () => {
  assert.throws(() => common.password(undefined));
  assert.throws(() => common.password('x'.repeat(19)));
  assert.equal(common.password('x'.repeat(20)), 'x'.repeat(20));
  assert.equal(common.password('é'.repeat(10)), 'é'.repeat(10));
  assert.throws(() => common.password('x'.repeat(1025)));
});
test('approval refuses a noninteractive terminal', { skip: process.stdin.isTTY && process.stdout.isTTY }, () => {
  assert.throws(() => common.approve('Allow? '), /interactive/);
});

test('frame count defaults to one and remains strictly bounded', () => {
  assert.equal(common.frameCount(), 1);
  assert.equal(common.frameCount('10'), 10);
  for (const value of ['0', '11', '-1', '01', '1.0']) assert.throws(() => common.frameCount(value));
});

test('diagnostic mode is explicit and bounded', () => {
  assert.equal(common.mode(), 'independent');
  assert.equal(common.mode('ack-burst'), 'ack-burst');
  for (const value of ['', 'auto', 'ACK-BURST']) assert.throws(() => common.mode(value));
});

test('approval abort closes the prompt and ignores a late answer', async () => {
  // Synthetic readline/TTY only; this does not open a terminal or native addon.
  const readline = require('node:readline');
  const { EventEmitter } = require('node:events');
  const oldIn = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  const oldOut = Object.getOwnPropertyDescriptor(process.stdout, 'isTTY');
  const original = readline.createInterface;
  let prompt, closes = 0, opened = 0;
  class FakeTerminal extends EventEmitter {
    question(_text, callback) { prompt = callback; }
    close() { closes++; this.emit('close'); }
  }
  try {
    Object.defineProperty(process.stdin, 'isTTY', { configurable: true, value: true });
    Object.defineProperty(process.stdout, 'isTTY', { configurable: true, value: true });
    readline.createInterface = () => { opened++; return new FakeTerminal(); };
    const before = new AbortController(); before.abort();
    assert.equal(await common.approve('Allow? ', 30000, before.signal), false);
    assert.equal(opened, 0);
    const pending = new AbortController();
    const result = common.approve('Allow? ', 30000, pending.signal);
    assert.equal(opened, 1);
    pending.abort();
    assert.equal(await result, false);
    assert.equal(closes, 1);
    prompt('YES'); // a queued answer cannot resurrect an aborted approval
    assert.equal(closes, 1);
    readline.createInterface = () => {
      const terminal = new FakeTerminal();
      terminal.question = () => { throw new Error('prompt setup failed'); };
      return terminal;
    };
    await assert.rejects(common.approve('Allow? ', 30000, new AbortController().signal), /prompt setup failed/);
    assert.equal(closes, 2);
  } finally {
    readline.createInterface = original;
    if (oldIn) Object.defineProperty(process.stdin, 'isTTY', oldIn); else delete process.stdin.isTTY;
    if (oldOut) Object.defineProperty(process.stdout, 'isTTY', oldOut); else delete process.stdout.isTTY;
  }
});
