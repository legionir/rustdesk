'use strict';
// Deferred validation-only cases: they do not open a socket.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');
const base = {
  address: '127.0.0.1:1', expectedHostId: 'host', hostSigningKey: Buffer.alloc(32),
  viewerId: 'test', viewerName: 'test', wireSessionId: '1', version: 'test',
  password: 'test-only', timeoutMs: 1000, maxMessageBytes: 1024,
};
test('rejects invalid viewer options before scheduling network work', () => {
  assert.throws(() => core.connectViewer({ ...base, address: 'example.com:1234' }));
  assert.throws(() => core.connectViewer({ ...base, hostSigningKey: Buffer.alloc(31) }));
  assert.throws(() => core.connectViewer({ ...base, wireSessionId: '01' }));
  assert.throws(() => core.connectViewer({ ...base, maxMessageBytes: 0 }));
  assert.throws(() => core.connectViewer({ ...base, timeoutMs: 0 }));
});

test('rejects invalid WSS options before scheduling network work', () => {
  const { address, ...rest } = base;
  assert.throws(() => core.connectWssViewer({ ...rest, endpoint: 'ws://example.com/' }));
  assert.throws(() => core.connectWssViewer({ ...rest, endpoint: 'wss://example.com/\npath' }));
  assert.throws(() => core.connectWssViewer({ ...rest, endpoint: `wss://example.com/${'x'.repeat(4096)}` }));
  assert.throws(() => core.connectWssViewer({ ...rest, endpoint: 'wss://user:password@example.com/' }));
  assert.throws(() => core.connectWssViewer({ ...rest, endpoint: 'wss://example.com/?token=secret' }));
  assert.throws(() => core.connectWssViewer({ ...rest, endpoint: 'wss://example.com/', hostSigningKey: Buffer.alloc(31) }));
});

test('two-factor disclosure requires explicit matching opt-in and valid format', () => {
  const bad = [
    { twoFactorCode: '123456' },
    { acknowledgeTwoFactorDisclosure: true },
    { twoFactorCode: '12345x', acknowledgeTwoFactorDisclosure: true },
    { twoFactorCode: '12345', acknowledgeTwoFactorDisclosure: true },
    { twoFactorCode: '123456789', acknowledgeTwoFactorDisclosure: true },
    { twoFactorCode: '123456', acknowledgeTwoFactorDisclosure: false },
  ];
  const { address, ...rest } = base;
  for (const extra of bad) {
    assert.throws(() => core.connectViewer({ ...base, ...extra }));
    assert.throws(() => core.connectWssViewer({ ...rest, endpoint: 'wss://example.com/', ...extra }));
  }
});
