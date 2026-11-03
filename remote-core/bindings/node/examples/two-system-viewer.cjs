'use strict';
// Manual, view-only diagnostic. This does not decode, render or save screen data.
// A pin authenticates the configured host key only if its provisioning is sound.
const fs = require('node:fs');
const crypto = require('node:crypto');
const core = require('..');
const { address, password, positiveInteger, frameCount, mode } = require('./two-system-common.cjs');
const { receiveOneFrame } = require('./two-system-exchange.cjs');
const args = process.argv.slice(2);
if ((args.length !== 7 && args.length !== 8 && args.length !== 9) || args[0] !== '--acknowledge-trusted-host') {
  console.error('Usage: node examples/two-system-viewer.cjs --acknowledge-trusted-host HOST_IP PORT HOST_ID PIN_FILE EXPECTED_SHA256 DISPLAY_INDEX [FRAME_COUNT_1_TO_10 [independent|ack-burst]]');
  process.exitCode = 2;
} else {
  (async () => {
    const [, ip, port, hostId, pinPath, expected, displayText, frameText, modeText] = args;
    const target = address(ip, port);
    if (port === '0') throw new Error('viewer needs the actual nonzero listening port');
    const display = positiveInteger(displayText, 63, 'display index');
    const frames = frameCount(frameText);
    const selectedMode = mode(modeText);
    const secret = password(process.env.REMOTE_CORE_DEMO_PASSWORD);
    if (!/^[0-9a-f]{64}$/.test(expected)) throw new Error('expected fingerprint must be 64 lowercase hex characters');
    // Do not read an unbounded caller-supplied path into memory. Hash checking
    // below still cannot replace authenticated out-of-band key distribution.
    const fd = fs.openSync(pinPath, 'r');
    let pin;
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.size !== 32) throw new Error('host pin must be a regular 32-byte file');
      pin = Buffer.alloc(32);
      if (fs.readSync(fd, pin, 0, pin.length, 0) !== 32) throw new Error('host pin read was incomplete');
    } finally { fs.closeSync(fd); }
    const digest = crypto.createHash('sha256').update(pin).digest();
    if (!crypto.timingSafeEqual(digest, Buffer.from(expected, 'hex'))) throw new Error('host pin fingerprint mismatch');
    let viewer;
    const request = new core.ViewerConnectRequest();
    const onInterrupt = () => {
      request.cancel();
      try { if (viewer) viewer.requestClose(); } catch { console.error('Close request could not finish; explicit cleanup will be retried.'); }
    };
    process.on('SIGINT', onInterrupt);
    try {
      viewer = await request.connectTcp({ address: target, expectedHostId: hostId, hostSigningKey: pin,
        viewerId: 'manual-diagnostic', viewerName: 'manual-diagnostic', wireSessionId: '1', version: 'diagnostic',
        password: secret, timeoutMs: 180000, maxMessageBytes: 8 * 1024 * 1024, videoAckRequired: selectedMode === 'ack-burst' });
      console.log(`Connected; peer reports ${viewer.peerInfo().displays.length} display(s).`);
      // Bounded control handling: do not decode untrusted network bitstreams.
      for (let n = 1; n <= frames; n++) {
        const length = await receiveOneFrame(viewer, display);
        console.log(`Received VP9 envelope ${n}/${frames} (${length} bytes) for display ${display}.`);
        console.log('Sent a receipt notification; the frame was not decoded, rendered or saved.');
      }
    } finally {
      process.removeListener('SIGINT', onInterrupt);
      if (viewer) viewer.close();
    }
  })().catch(error => { console.error(`Viewer diagnostic failed: ${error.message}`); process.exitCode = 1; });
}
