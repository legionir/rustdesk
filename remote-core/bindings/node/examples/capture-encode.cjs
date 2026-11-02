'use strict';
// This captures the active desktop. It does not send or persist image data.
const core = require('..');
if (process.argv[2] !== '--confirm-capture') {
  console.error('Captures your first display. Use a disposable desktop and pass --confirm-capture.');
  process.exitCode = 1;
} else {
  (async () => {
    const displays = await core.listDisplays();
    if (!displays.length) throw new Error('No display available');
    const frame = await core.captureDisplay(displays[0].index, 2000);
    if (!['bgra', 'rgba'].includes(frame.format)) throw new Error(`Unsupported pixel format: ${frame.format}`);
    const encoded = await core.encodeFrame(frame.data, {
      width: frame.width, height: frame.height, stride: frame.strides[0],
      codec: 'vp9', pixelFormat: frame.format, quality: 1, ptsMs: 0,
    });
    console.log(`Encoded ${frame.width}x${frame.height}; ${encoded.packets.length} packet(s); ${encoded.packets.reduce((n, p) => n + p.data.length, 0)} bytes`);
  })().catch(error => { console.error(error.message); process.exitCode = 1; });
}
