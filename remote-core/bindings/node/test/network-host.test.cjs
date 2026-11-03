'use strict';
// Synthetic loopback only: no real display capture or OS input.
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const core = require('..');
const options = { address: '127.0.0.1:0', allowedPeerIp: '127.0.0.1', hostId: 'network-test', password: 'test-only', timeoutMs: 5000, acknowledgeNetworkExposure: true };
test('requires explicit exposure acknowledgement and literal peer', () => {
  assert.throws(() => core.listenNetworkHost({ ...options, acknowledgeNetworkExposure: false }));
  assert.throws(() => core.listenNetworkHost({ ...options, allowedPeerIp: 'localhost' }));
  assert.throws(() => core.listenNetworkHost({ ...options, allowedPeerIp: '0.0.0.0' }));
  assert.throws(() => core.listenNetworkHost({ ...options, address: 'localhost:0' }));
});
test('checks socket peer before source handshake and frees listener on close', async () => {
  const host = await core.listenNetworkHost({ ...options, allowedPeerIp: '127.0.0.2' });
  try {
    const [ip, port] = host.address().split(':');
    const accepting = host.accept(5000); accepting.catch(() => {});
    // Checkout releases the internal mutex, but the public listener is still
    // serialized: concurrent close/accept must be rejected rather than block.
    assert.throws(() => host.close(), /operation in progress/);
    assert.throws(() => host.accept(5000), /operation in progress/);
    const socket = net.connect({ host: ip, port: Number(port) });
    socket.on('error', () => {});
    await assert.rejects(accepting, /peer address not permitted/);
    socket.destroy();
    // A rejected peer does not consume the listener. A new accept can wait
    // and time out normally; this does not prove full network interoperability.
    await assert.rejects(host.accept(30));
  } finally { host.close(); }
});
test('explicitly allowed loopback can reach pending login without approval', async () => {
  const host = await core.listenNetworkHost(options);
  let session;
  try {
    const connecting = core.connectViewer({ address: host.address(), expectedHostId: options.hostId, hostSigningKey: host.signingPublicKey(),
      viewerId: 'viewer', viewerName: 'viewer', wireSessionId: '1', version: 'test', password: options.password, timeoutMs: 5000, maxMessageBytes: 131072 });
    connecting.catch(() => {});
    session = await host.accept(5000);
    assert.equal(session.claims().peerId, 'viewer');
    session.close(); session = null;
    await assert.rejects(connecting);
  } finally { if (session) session.close(); host.close(); }
});
