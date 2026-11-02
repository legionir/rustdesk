'use strict';
// Captures one real local screen frame. Never run without explicit local consent.
// Fixed credentials and same-process key distribution are for this demo only.
const core = require('..');
if (process.argv[2] !== '--confirm-local-screen-capture') {
  console.error('Pass --confirm-local-screen-capture on an authorized interactive desktop.');
  process.exitCode = 2;
} else {
  (async () => {
    let host, session, viewer;
    try {
      const password = 'local-demo-only';
      host = await core.listenLocalHost({ hostId: 'local-demo', password, timeoutMs: 30000 });
      // Pin is transferred directly within this process. Real key distribution
      // needs an independently trusted channel and lifecycle policy.
      const connecting = core.connectViewer({
        address: host.address(), expectedHostId: 'local-demo', hostSigningKey: host.signingPublicKey(),
        viewerId: 'local-demo-viewer', viewerName: 'local-demo-viewer', wireSessionId: '1', version: 'demo',
        password, timeoutMs: 30000, maxMessageBytes: 8 * 1024 * 1024,
      });
      // Attach a rejection handler immediately, before potentially awaiting UI.
      connecting.catch(() => {});
      session = await host.accept(30000);
      // CLI confirmation stands in for a real, trusted local consent UI.
      await session.approveView(true, 30000);
      viewer = await connecting;
      const permission = await viewer.receive(30000);
      if (permission.kind !== 'permission' || permission.permission !== 0 || permission.enabled !== false) {
        throw new Error('Expected the local host to announce disabled input');
      }
      const incoming = viewer.receive(30000);
      incoming.catch(() => {});
      // VP9 support is an explicit demo assumption, not auto-detected.
      await session.sendOneVp9Frame(0, true, 2000, 30000);
      const frame = await incoming;
      console.log(`Received ${frame.kind}, ${frame.data ? frame.data.length : 0} wire bytes.`);
      // This is compressed wire data, not a decoded image; do not save or log it.
    } finally {
      if (viewer) viewer.close();
      if (session) session.close();
      if (host) host.close();
    }
  })().catch(error => { console.error('Demo failed:', error.message); process.exitCode = 1; });
}
