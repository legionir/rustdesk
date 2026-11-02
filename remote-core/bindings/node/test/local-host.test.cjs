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
    await assert.rejects(pending.approveView(true, 1000));
    await assert.rejects(connecting);
    pending.close();
  } finally {
    if (pending) pending.close();
    host.close();
  }
});

test('opt-in interactive local screen host to viewer single frame',
  { skip: process.env.REMOTE_CORE_ALLOW_REAL_CAPTURE !== '1' }, async () => {
    // This reads a real screen. Run only with explicit owner authorization on
    // a disposable interactive desktop. No frame is written to disk or logged.
    const password = 'local-test-only';
    const host = await core.listenLocalHost({ hostId: 'interactive-test', password, timeoutMs: 30000 });
    let session, viewer;
    try {
      const connecting = core.connectViewer({ address: host.address(), expectedHostId: 'interactive-test', hostSigningKey: host.signingPublicKey(),
        viewerId: 'test', viewerName: 'test', wireSessionId: '1', version: 'test', password, timeoutMs: 30000, maxMessageBytes: 8 * 1024 * 1024 });
      connecting.catch(() => {});
      session = await host.accept(30000);
      await session.approveView(true, 30000);
      viewer = await connecting;
      const permission = await viewer.receive(30000);
      assert.equal(permission.kind, 'permission'); assert.equal(permission.enabled, false);
      const incoming = viewer.receive(30000); incoming.catch(() => {});
      await session.sendOneVp9Frame(0, true, 2000, 30000);
      const event = await incoming;
      assert.equal(event.kind, 'video'); assert.equal(event.codec, 'vp9'); assert.ok(event.data.length > 0);
      // A burst keeps its encoder only for this call. Receive concurrently so
      // a bounded socket does not deadlock waiting for the peer to drain it.
      const burstFrame = viewer.receive(30000); burstFrame.catch(() => {});
      const burst = session.sendVp9Burst(0, true, 10, 1, 5000, 500, 5000);
      const count = await burst;
      if (count === 1) {
        const frame = await burstFrame;
        assert.equal(frame.kind, 'video'); assert.equal(frame.codec, 'vp9');
      } else {
        // No changed frame was captured; closing the viewer cancels receive.
        viewer.close(); await assert.rejects(burstFrame); viewer = null;
      }
    } finally {
      if (viewer) viewer.close();
      if (session) session.close();
      host.close();
    }
  });
