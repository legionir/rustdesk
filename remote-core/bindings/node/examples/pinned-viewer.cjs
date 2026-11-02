'use strict';
// Manual integration example. It connects to a host and can receive private
// screen data. This is not tested, audited, or a production security example.
// Pin provisioning and local owner approval must already be completed.
const fs = require('node:fs');
const core = require('..');
const [confirm, address, hostId, pinFile] = process.argv.slice(2);
if (confirm !== '--confirm-trusted-peer' || !address || !hostId || !pinFile) {
  console.error('Usage: node examples/pinned-viewer.cjs --confirm-trusted-peer IP:PORT HOST_ID PIN_FILE');
  process.exitCode = 2;
} else {
  const password = process.env.REMOTE_CORE_DEMO_PASSWORD;
  if (!password) {
    console.error('REMOTE_CORE_DEMO_PASSWORD is required (environment variables are not secure credential storage).');
    process.exitCode = 2;
  } else {
    const pin = fs.readFileSync(pinFile);
    if (pin.length !== 32) throw new Error('PIN_FILE must contain exactly 32 raw Ed25519 public-key bytes');
    (async () => {
      const viewer = await core.connectViewer({
        address, expectedHostId: hostId, hostSigningKey: pin,
        viewerId: 'manual-viewer', viewerName: 'manual-viewer', wireSessionId: '1', version: 'demo',
        password, timeoutMs: 30000, maxMessageBytes: 8 * 1024 * 1024,
      });
      try {
        const peer = viewer.peerInfo();
        // Avoid logging user, machine, display name, secret or frame bytes.
        console.log(`Connected; host reported ${peer.displays.length} display(s).`);
        const event = await viewer.receive(30000);
        console.log(`Received ${event.kind}${event.data ? ` (${event.data.length} bytes)` : ''}.`);
        // The video event is a RustDesk envelope, not an image. This example
        // intentionally does not invoke the unaudited native decoder.
      } finally {
        viewer.close();
      }
    })().catch(error => { console.error('Viewer failed:', error.message); process.exitCode = 1; });
  }
}
