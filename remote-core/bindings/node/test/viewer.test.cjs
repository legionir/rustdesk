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
