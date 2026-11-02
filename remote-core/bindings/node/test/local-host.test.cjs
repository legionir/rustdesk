'use strict';
// Deferred argument validation only; invalid calls do not bind a socket.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');
test('rejects invalid local host options before scheduling work', () => {
  assert.throws(() => core.listenLocalHost({ hostId: '', password: 'test', timeoutMs: 1000 }));
  assert.throws(() => core.listenLocalHost({ hostId: 'test', password: '', timeoutMs: 1000 }));
  assert.throws(() => core.listenLocalHost({ hostId: 'test', password: 'test', timeoutMs: 0 }));
});

// Deferred loopback-only lifecycle cases. No display is captured or input sent.
test('explicit close releases the listener slot without requiring garbage collection', async () => {
  const first = await core.listenLocalHost({ hostId: 'first', password: 'test-only', timeoutMs: 5000 });
  assert.match(first.address(), /^127\.0\.0\.1:\d+$/);
  assert.equal(first.signingPublicKey().length, 32);
  first.close();
  const second = await core.listenLocalHost({ hostId: 'second', password: 'test-only', timeoutMs: 5000 });
  second.close();
});
test('abandoned pending approval expires and closes the viewer', async () => {
  const host = await core.listenLocalHost({ hostId: 'expiry', password: 'test-only', timeoutMs: 5000 });
  let pending;
  try {
    const connecting = core.connectViewer({ address: host.address(), expectedHostId: 'expiry', hostSigningKey: host.signingPublicKey(),
      viewerId: 'test', viewerName: 'test', wireSessionId: '1', version: 'test', password: 'test-only', timeoutMs: 7000, maxMessageBytes: 131072 });
    // Ensure a rejection does not become unhandled while waiting for the timer.
    connecting.catch(() => {});
    pending = await host.accept(3000);
    assert.equal(pending.claims().peerId, 'test');
    await new Promise(resolve => setTimeout(resolve, 3200));
    assert.throws(() => pending.claims());
    await assert.rejects(connecting);
    pending.close();
  } finally {
    if (pending) pending.close();
    host.close();
  }
});
