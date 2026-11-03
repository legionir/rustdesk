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
test('listener close request cancels a pending accept and preserves explicit lease cleanup', async () => {
  const host = await core.listenLocalHost({ hostId: 'cancel-listener', password: 'test-only', timeoutMs: 5000 });
  try {
    const pending = host.accept(5000); pending.catch(() => {});
    host.requestClose();
    await assert.rejects(pending, /listener close requested/);
    assert.throws(() => host.accept(1000), /listener close requested/);
  } finally { host.close(); }
  const replacement = await core.listenLocalHost({ hostId: 'replacement', password: 'test-only', timeoutMs: 5000 });
  replacement.close();
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
    assert.throws(() => pending.enableCursorAnnouncements(false), /cache misses/);
    assert.throws(() => pending.enableCursorAnnouncements(true), /not approved/);
    await assert.rejects(pending.sendDelayProbe(0, 0, 1000), /not approved/);
    await assert.rejects(pending.receiveEvent(1000), /not approved/);
    await assert.rejects(pending.tryReceiveEvent(1000), /not approved/);
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

test('one-shot viewer connect request cancels pending owner approval', async () => {
  const host = await core.listenLocalHost({ hostId: 'cancel-connect', password: 'test-only', timeoutMs: 5000 });
  let session;
  const options = { address: host.address(), expectedHostId: 'cancel-connect', hostSigningKey: host.signingPublicKey(),
    viewerId: 'test', viewerName: 'test', wireSessionId: '1', version: 'test', password: 'test-only', timeoutMs: 5000, maxMessageBytes: 131072 };
  try {
    const request = new core.ViewerConnectRequest();
    const connecting = request.connectTcp(options); connecting.catch(() => {});
    session = await host.accept(5000);
    assert.throws(() => request.connectTcp(options), /already used/);
    request.cancel(); request.cancel();
    await assert.rejects(connecting, /connection cancelled/);
    assert.throws(() => request.connectTcp(options), /cancelled/);
    session.close(); session = null;
    const cancelled = new core.ViewerConnectRequest(); cancelled.cancel();
    assert.throws(() => cancelled.connectTcp(options), /cancelled/);
    const invalid = new core.ViewerConnectRequest();
    assert.throws(() => invalid.connectTcp({ ...options, address: 'invalid' }));
    assert.throws(() => invalid.connectTcp(options), /already used/);
    const wss = new core.ViewerConnectRequest();
    assert.throws(() => wss.connectWss({ ...options, endpoint: 'ws://not-wss.test' }));
    assert.throws(() => wss.connectTcp(options), /already used/);
  } finally { if (session) session.close(); host.close(); }
});

test('pending host session can be terminally closed without approval', async () => {
  const host = await core.listenLocalHost({ hostId: 'close-pending', password: 'test-only', timeoutMs: 5000 });
  let session;
  try {
    const connecting = core.connectViewer({ address: host.address(), expectedHostId: 'close-pending', hostSigningKey: host.signingPublicKey(),
      viewerId: 'test', viewerName: 'test', wireSessionId: '1', version: 'test', password: 'test-only', timeoutMs: 5000, maxMessageBytes: 131072 });
    connecting.catch(() => {});
    session = await host.accept(5000);
    session.requestClose();
    assert.throws(() => session.claims(), /close requested/);
    session.close(); session = null;
    await assert.rejects(connecting);
  } finally { if (session) session.close(); host.close(); }
});

test('close-requested pending session retains its lease past approval deadline', async () => {
  const host = await core.listenLocalHost({ hostId: 'lease-on-close', password: 'test-only', timeoutMs: 5000 });
  let session;
  try {
    const connecting = core.connectViewer({ address: host.address(), expectedHostId: 'lease-on-close', hostSigningKey: host.signingPublicKey(),
      viewerId: 'test', viewerName: 'test', wireSessionId: '1', version: 'test', password: 'test-only', timeoutMs: 6000, maxMessageBytes: 131072 });
    connecting.catch(() => {});
    session = await host.accept(3000);
    session.requestClose();
    await assert.rejects(connecting);
    await new Promise(resolve => setTimeout(resolve, 3200));
    assert.throws(() => host.accept(1000), /session already exists/);
    session.close(); session = null;
  } finally { if (session) session.close(); host.close(); }
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
      const approving = session.approveView(true, 30000);
      // Busy is acquired synchronously before scheduling; the worker's
      // checked-out session must not allow a concurrent close or query.
      assert.throws(() => session.claims(), /operation in progress/);
      assert.throws(() => session.close(), /operation in progress/);
      await approving;
      assert.throws(() => session.enableCursorAnnouncements(false), /cache misses/);
      session.enableCursorAnnouncements(true);
      assert.throws(() => session.enableCursorAnnouncements(true), /already selected/);
      assert.equal(await session.resendCursorShape('0', 5000), false);
      assert.ok(session.idleRemainingMs() == null);
      assert.throws(() => session.enableIdleTimeout(0));
      session.enableIdleTimeout(1);
      assert.ok(session.idleRemainingMs() > 0 && session.idleRemainingMs() <= 61000);
      assert.equal(session.pollIdleTimeout(), false);
      assert.ok(session.receiveWatchdogRemainingMs() == null);
      session.enableReceiveWatchdog();
      assert.throws(() => session.sendWindowsFocusHint(false, true, 1000));
      assert.throws(() => session.sendWindowsFocusHint(true, false, 1000));
      assert.throws(() => session.sendWindowsCursorFollowHint(0, false, false, true, 1000));
      assert.throws(() => session.sendWindowsCursorFollowHint(0, false, true, false, 1000));
      assert.throws(() => session.setWindowsScanModeEnabled(true, false));
      assert.throws(() => session.setWindowsTranslateModeEnabled(true, false));
      assert.throws(() => session.setWindowsKeyRepeatEnabled(true, false));
      session.resetWindowFocus();
      assert.ok(session.receiveWatchdogRemainingMs() > 0 && session.receiveWatchdogRemainingMs() <= 30000);
      assert.equal(session.pollReceiveWatchdog(), false);
      viewer = await connecting;
      // Validation only: these do not send or inject keyboard events.
      assert.throws(() => viewer.sendWindowsTranslateText('sample', false, 1000), /acknowledged/);
      assert.throws(() => viewer.sendWindowsTranslateText('', true, 1000));
      assert.throws(() => viewer.sendWindowsTranslateText('a\0b', true, 1000));
      assert.throws(() => viewer.sendWindowsTranslateText('x'.repeat(4097), true, 1000));
      assert.ok((await viewer.windowsSessions()) == null); // this prototype does not advertise Windows sessions
      const originals = await viewer.originalResolutions();
      assert.equal(originals.length, viewer.peerInfo().displays.length);
      assert.ok(originals.every(value => value.present === false));
      assert.ok((await viewer.supportedModes()) == null);
      const permission = await viewer.receive(30000);
      assert.equal(permission.kind, 'permission'); assert.equal(permission.enabled, false);
      assert.throws(() => session.enableDuplexReadAhead(false));
      assert.throws(() => viewer.enableDuplexReadAhead(false));
      await session.enableDuplexReadAhead(true);
      await viewer.enableDuplexReadAhead(true);
      assert.equal(session.initialVideoAckRequired(), false);
      assert.throws(() => session.sendVp9AckBurstToTrustedSink(0, false, true, 10, 1, 1000, 100, 1000), /non-decoding/);
      await assert.rejects(session.sendVp9AckBurstToTrustedSink(0, true, true, 10, 1, 1000, 100, 1000), /did not request/);
      const cursorEvent = session.receiveEvent(5000);
      await viewer.sendCursorPreferences({ showRemoteCursor: true, followRemoteCursor: false }, 5000);
      const cursor = await cursorEvent;
      assert.equal(cursor.kind, 'cursorPreferences'); assert.equal(cursor.showRemoteCursor, true); assert.equal(cursor.followRemoteCursor, false);
      const fps = core.createViewerFpsController(); fps.setDisplays([0]);
      const plan = fps.tick(true, null, [{ display: 0, receivedFps: 30, decodeFps: 30, queueLen: 0, queueCapacity: 10 }]);
      const fpsEvent = session.receiveEvent(5000);
      assert.equal(await viewer.dispatchFpsDecision(plan, true, 5000), 1);
      const fpsRequest = await fpsEvent;
      assert.equal(fpsRequest.kind, 'videoPreferences'); assert.equal(fpsRequest.customFps, 27);
      assert.throws(() => viewer.dispatchFpsDecision({ customFps: 121, refresh: [], minDecodeFps: 30 }, true, 5000));
      assert.throws(() => viewer.dispatchFpsDecision({ refresh: [0, 0] }, true, 5000));
      const inputEvent = session.receiveEvent(5000);
      await viewer.sendDisableKeyboard(true, 5000);
      const input = await inputEvent;
      assert.equal(input.kind, 'inputPreference'); assert.equal(input.disableKeyboard, true);
      // The viewer echoes a host probe. Fields are untrusted wire claims and
      // success does not establish RTT authenticity or apply QoS policy.
      assert.throws(() => session.sendDelayProbe(60001, 0, 5000));
      assert.throws(() => session.sendDelayProbe(0, 100000001, 5000));
      const incomingProbe = viewer.receive(5000); incomingProbe.catch(() => {});
      // Native viewer is checked out without its data mutex during I/O; the
      // busy gate still rejects close/overlapping operations rather than
      // pretending a blocking receive can be cancelled from JavaScript.
      assert.throws(() => viewer.close(), /operation in progress/);
      assert.throws(() => viewer.notifyVideoReceived(5000), /operation in progress/);
      await session.sendDelayProbe(12, 3456, 5000);
      const seenProbe = await incomingProbe;
      assert.equal(seenProbe.kind, 'testDelay'); assert.equal(seenProbe.probeTime, '0');
      assert.equal(seenProbe.probeFromClient, false); assert.equal(seenProbe.probeLastDelay, 12);
      assert.equal(seenProbe.probeTargetBitrate, 3456);
      const probeReply = await session.receiveEvent(5000);
      assert.equal(probeReply.kind, 'heartbeat');
      assert.equal(probeReply.probeTime, '0');
      assert.equal(probeReply.probeLastDelay, 12); assert.equal(probeReply.probeTargetBitrate, 3456);
      assert.ok((await session.tryReceiveEvent(5000)) == null);
      assert.ok((await viewer.tryReceive(5000)) == null);
      assert.throws(() => session.sendOneVp9EnvelopeToTrustedSink(0, false, 1000, 5000), /acknowledgement/);
      assert.throws(() => session.sendOneVp9EnvelopeToTrustedSink(0, true, 0, 5000), /captureTimeoutMs/);
      const incoming = viewer.receive(30000); incoming.catch(() => {});
      await session.sendOneVp9EnvelopeToTrustedSink(0, true, 2000, 30000);
      const event = await incoming;
      assert.equal(event.kind, 'video'); assert.equal(event.codec, 'vp9'); assert.ok(event.data.length > 0);
      const images = await core.decodeTrustedVideoBatch([event.data], true);
      assert.equal(images.length, 1); assert.ok(images[0].width > 0 && images[0].height > 0);
      assert.equal(images[0].stride, images[0].width * 4);
      assert.equal(images[0].data.length, images[0].stride * images[0].height);
      // Separate thread-confined persistent decoder; the frame was produced
      // locally and is not a malicious network bitstream.
      const decoder = core.createTrustedVideoWorker(8 * 1024 * 1024, 32 * 1024 * 1024, true);
      const queue = core.createViewerVideoQueue(0, 'vp9', 4, 16 * 1024 * 1024, 8 * 1024 * 1024);
      try {
        assert.equal((await decoder.register(0, 'vp9')).kind, 'ok');
        assert.equal((await queue.push(event.data)).kind, 'keyframe');
        const queued = queue.pop(); assert.equal(queue.isCurrent(queued.token), true);
        const decoded = await decoder.decode(queued.data);
        assert.equal(decoded.kind, 'image'); assert.equal(decoded.display, 0);
        assert.equal(decoded.data.length, decoded.stride * decoded.height);
        assert.equal(queue.complete(queued.token, true), 'applied');
        assert.equal(queue.stats().accountedBytes, 0);
        assert.equal((await decoder.invalidate(0)).kind, 'ok');
        assert.equal((await decoder.reset(0)).kind, 'ok');
        assert.equal((await decoder.invalidateAll()).kind, 'ok');
        assert.equal((await decoder.reset(0)).kind, 'ok');
        assert.equal((await decoder.remove(0)).kind, 'removed');
      } finally { decoder.close(); }
      // A burst keeps its encoder only for this call. Receive concurrently so
      // a bounded socket does not deadlock waiting for the peer to drain it.
      const burstFrame = viewer.receive(10000); burstFrame.catch(() => {});
      const burst = session.sendVp9Burst(0, true, 10, 1, 5000, 500, 5000);
      assert.throws(() => session.close(), /operation in progress/);
      const count = await burst;
      if (count === 1) {
        const frame = await burstFrame;
        assert.equal(frame.kind, 'video'); assert.equal(frame.codec, 'vp9');
      } else {
        // No changed frame was captured; the receive deadline closes it.
        await assert.rejects(burstFrame); viewer.close(); viewer = null;
      }
      if (viewer) {
        // A pending receive is cancelled cooperatively, not retried. This does
        // not assert a hard deadline or make any claim about delivery.
        const pendingReceive = viewer.receive(5000); pendingReceive.catch(() => {});
        viewer.requestClose();
        await assert.rejects(pendingReceive, /close requested/);
        assert.throws(() => viewer.notifyVideoReceived(1000), /close requested/);
        viewer.close(); viewer = null;
      }
    } finally {
      if (viewer) viewer.close();
      if (session) session.close();
      host.close();
    }
  });

test('ACK-requested sessions reject serialized bursts',
  { skip: process.env.REMOTE_CORE_ALLOW_REAL_CAPTURE !== '1' }, async () => {
    // Approval enumerates real display metadata, but no frame is captured here.
    const host = await core.listenLocalHost({ hostId: 'ack-test', password: 'test-only', timeoutMs: 30000 });
    let session, viewer;
    try {
      const connecting = core.connectViewer({ address: host.address(), expectedHostId: 'ack-test', hostSigningKey: host.signingPublicKey(),
        viewerId: 'test', viewerName: 'test', wireSessionId: '2', version: 'test', password: 'test-only', timeoutMs: 30000,
        maxMessageBytes: 8 * 1024 * 1024, videoAckRequired: true });
      connecting.catch(() => {});
      session = await host.accept(30000);
      await session.approveView(true, 30000); viewer = await connecting;
      assert.equal(session.initialVideoAckRequired(), true);
      assert.equal(await session.resendCursorShape('0', 1000), false);
      assert.throws(() => session.enableCursorAnnouncements(true), /already selected/);
      await assert.rejects(session.sendVp9Burst(0, true, 10, 2, 1000, 100, 1000), /ACK-paced bursts/);
      assert.throws(() => session.sendVp9AckBurst(0, true, false, 10, 1, 5000, 500, 5000), /acknowledgement/);
      await assert.rejects(session.sendVp9AckBurst(0, true, true, 10, 1, 5000, 500, 5000), /duplex/);
      const permission = await viewer.receive(30000); assert.equal(permission.kind, 'permission');
      await session.enableDuplexReadAhead(true);
      const receiving = (async () => {
        const frame = await viewer.receive(7000);
        assert.equal(frame.kind, 'video'); assert.equal(frame.codec, 'vp9');
        // Synthetic receipt only: this does not decode or render the frame.
        await viewer.notifyVideoReceived(1000);
      })(); receiving.catch(() => {});
      const burst = await session.sendVp9AckBurst(0, true, true, 10, 1, 5000, 500, 5000);
      if (burst.sent === 1) { await receiving; assert.equal(burst.reason, 'frameLimit'); assert.equal(burst.connectionClosed, false); }
      else { assert.equal(burst.reason, 'deadline'); await assert.rejects(receiving); viewer.close(); viewer = null; }
    } finally { if (viewer) viewer.close(); if (session) session.close(); host.close(); }
  });


test('host close request cancels pending receive after view approval',
  { skip: process.env.REMOTE_CORE_ALLOW_REAL_CAPTURE !== '1' }, async () => {
    const host = await core.listenLocalHost({ hostId: 'cancel-host', password: 'test-only', timeoutMs: 30000 });
    let session, viewer;
    try {
      const connecting = core.connectViewer({ address: host.address(), expectedHostId: 'cancel-host', hostSigningKey: host.signingPublicKey(),
        viewerId: 'test', viewerName: 'test', wireSessionId: '1', version: 'test', password: 'test-only', timeoutMs: 30000, maxMessageBytes: 8 * 1024 * 1024 });
      connecting.catch(() => {});
      session = await host.accept(30000);
      await session.approveView(true, 30000); viewer = await connecting;
      assert.equal((await viewer.receive(30000)).kind, 'permission');
      const pending = session.receiveEvent(5000); pending.catch(() => {});
      session.requestClose();
      await assert.rejects(pending, /close requested/);
      assert.throws(() => session.claims(), /close requested/);
      session.close(); session = null;
      await assert.rejects(viewer.receive(5000));
    } finally { if (viewer) viewer.close(); if (session) session.close(); host.close(); }
  });


test('source close notifications terminate either end without retry',
  { skip: process.env.REMOTE_CORE_ALLOW_REAL_CAPTURE !== '1' }, async () => {
    for (const sender of ['viewer', 'host']) {
      const host = await core.listenLocalHost({ hostId: 'close-notify', password: 'test-only', timeoutMs: 30000 });
      let session, viewer;
      try {
        const connecting = core.connectViewer({ address: host.address(), expectedHostId: 'close-notify', hostSigningKey: host.signingPublicKey(),
          viewerId: 'test', viewerName: 'test', wireSessionId: '1', version: 'test', password: 'test-only', timeoutMs: 30000, maxMessageBytes: 8 * 1024 * 1024 });
        connecting.catch(() => {});
        session = await host.accept(30000);
        await session.approveView(true, 30000); viewer = await connecting;
        assert.equal((await viewer.receive(30000)).kind, 'permission');
        if (sender === 'viewer') {
          assert.throws(() => viewer.sendCloseReason('x'.repeat(513), 1000));
          const receiving = session.receiveEvent(5000); receiving.catch(() => {});
          await viewer.sendCloseReason('done', 5000);
          await assert.rejects(receiving);
          assert.throws(() => viewer.sendCloseReason('again', 1000), /close requested/);
        } else {
          assert.throws(() => session.sendCloseReason('x'.repeat(513), 1000));
          const receiving = viewer.receive(5000); receiving.catch(() => {});
          await session.sendCloseReason('done', 5000);
          await assert.rejects(receiving);
          assert.throws(() => session.claims(), /close requested/);
        }
      } finally { if (viewer) viewer.close(); if (session) session.close(); host.close(); }
    }
  });
