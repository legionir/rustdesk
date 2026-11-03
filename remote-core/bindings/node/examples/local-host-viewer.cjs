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
      // Compressed wire data can be decoded only with an extra local-only opt-in.
      // Never use this native decoder for remote/untrusted/compressed input.
      if (process.argv.includes('--decode-trusted-local-frame')) {
        if (frame.kind !== 'video' || frame.codec !== 'vp9' || frame.display !== 0 || !frame.data) {
          throw new Error('Unexpected local frame');
        }
        const queue = core.createViewerVideoQueue(0, 'vp9', 4, 16 * 1024 * 1024, 8 * 1024 * 1024);
        const decoder = core.createTrustedVideoWorker(8 * 1024 * 1024, 32 * 1024 * 1024, true);
        try {
          await decoder.register(0, 'vp9');
          const accepted = await queue.push(frame.data);
          if (accepted.kind !== 'keyframe') throw new Error('Expected local first keyframe');
          const item = queue.pop();
          if (!item || !queue.isCurrent(item.token)) throw new Error('Stale queue item');
          const output = await decoder.decode(item.data);
          if (output.kind !== 'image') throw new Error(`Unexpected decode result: ${output.kind}`);
          if (!queue.isCurrent(item.token)) throw new Error('Decode result became stale');
          console.log(`Decoded trusted local image: ${output.width} x ${output.height}.`);
          // No pixels are logged, saved, transmitted or rendered in this demo.
          queue.complete(item.token, true);
        } finally { decoder.close(); }
      }
    } finally {
      if (viewer) viewer.close();
      if (session) session.close();
      if (host) host.close();
    }
  })().catch(error => { console.error('Demo failed:', error.message); process.exitCode = 1; });
}
