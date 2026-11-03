'use strict';
// Manual, bounded one-session, view-only LAN diagnostic. Unreviewed; never expose to
// the internet or use against an untrusted viewer. Captures private pixels.
const fs = require('node:fs');
const crypto = require('node:crypto');
const core = require('..');
const { address, permittedPeer, password, positiveInteger, frameCount, mode, approve } = require('./two-system-common.cjs');
const { receiveOneReceipt } = require('./two-system-exchange.cjs');
const args = process.argv.slice(2);
if ((args.length !== 7 && args.length !== 8 && args.length !== 9) || args[0] !== '--acknowledge-network-exposure') {
  console.error('Usage: node examples/two-system-host.cjs --acknowledge-network-exposure BIND_IP PORT ALLOWED_PEER_IP HOST_ID PIN_FILE DISPLAY_INDEX [FRAME_COUNT_1_TO_10 [independent|ack-burst]]');
  process.exitCode = 2;
} else {
  (async () => {
    const [, bindIp, port, peerIp, hostId, pinPath, displayText, frameText, modeText] = args;
    const bind = address(bindIp, port);
    permittedPeer(peerIp);
    const display = positiveInteger(displayText, 63, 'display index');
    const frames = frameCount(frameText);
    const selectedMode = mode(modeText);
    const secret = password(process.env.REMOTE_CORE_DEMO_PASSWORD);
    if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('interactive terminal required');
    let host, session;
    const abort = new AbortController();
    const onInterrupt = () => {
      abort.abort();
      // Both requests are sticky; even if cleanup reports an error, the
      // finally block will retry explicit close after the active task returns.
      try { if (session) session.requestClose(); } catch { console.error('Close request could not finish; explicit cleanup will be retried.'); }
      try { if (host) host.requestClose(); } catch { console.error('Close request could not finish; explicit cleanup will be retried.'); }
    };
    process.on('SIGINT', onInterrupt);
    try {
      host = await core.listenNetworkHost({ address: bind, allowedPeerIp: peerIp, hostId, password: secret,
        timeoutMs: 180000, acknowledgeNetworkExposure: true });
      if (abort.signal.aborted) throw new Error('diagnostic cancelled');
      const pin = host.signingPublicKey();
      // Never overwrite or follow an existing path. This is a public key, but
      // integrity and independent, authenticated transfer are essential.
      fs.writeFileSync(pinPath, pin, { flag: 'wx', mode: 0o600 });
      console.log(`Listening at ${host.address()}; expected socket peer ${peerIp}.`);
      console.log(`Public key saved to ${pinPath}; SHA-256 ${crypto.createHash('sha256').update(pin).digest('hex')}.`);
      console.log('Verify the fingerprint and transfer the pin over a separate trusted channel. The key changes on every run.');
      console.log('The observed IP and login claims are not verified viewer identities. Waiting for one connection.');
      session = await host.accept(180000);
      // Never log peer-controlled claims. This interactive assertion is not an
      // OS-protected consent UI and cannot prevent another process capturing.
      const confirmed = await approve(`Allow this connection to capture display ${display} and send up to ${frames} VP9 envelopes (${selectedMode} mode)? Type YES: `, 30000, abort.signal);
      if (!confirmed) throw new Error('local approval declined or expired');
      await session.approveView(true, 30000);
      if (session.initialVideoAckRequired() !== (selectedMode === 'ack-burst')) throw new Error('viewer and host modes do not match');
      if (selectedMode === 'ack-burst') {
        await session.enableDuplexReadAhead(true);
        const report = await session.sendVp9AckBurstToTrustedSink(display, true, true, 10, frames, 5000, 500, 5000);
        if (report.reason !== 'frameLimit' || report.sent !== frames || report.connectionClosed) throw new Error('ACK burst ended before the requested count');
        console.log(`Sent ${report.sent} envelopes with untrusted receipt claims; no decode, render or pixel correctness was checked.`);
      } else {
        for (let n = 1; n <= frames; n++) {
          await session.sendOneVp9EnvelopeToTrustedSink(display, true, 2000, 30000);
          console.log(`Frame ${n}/${frames} sent locally; waiting for an untrusted receipt notification.`);
          await receiveOneReceipt(session);
          console.log('Peer reported receipt; this does not prove decoding, rendering or pixel correctness.');
        }
      }
    } finally {
      process.removeListener('SIGINT', onInterrupt);
      try { if (session) session.close(); }
      finally { if (host) host.close(); }
    }
  })().catch(error => { console.error(`Host diagnostic failed: ${error.message}`); process.exitCode = 1; });
}
