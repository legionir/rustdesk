'use strict';
// Deferred CPU-only planner tests; no native capture or network is started.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('..');

test('viewer FPS planner is bounded, explicit and independent', () => {
  const fps = core.createViewerFpsController();
  fps.setDisplays([0]);
  const sample = { display: 0, receivedFps: 30, decodeFps: 30, queueLen: 0, queueCapacity: 10 };
  const first = fps.tick(true, null, [sample]);
  assert.equal(first.customFps, 27);
  assert.equal(first.minDecodeFps, 30);
  assert.deepEqual(first.refresh, []);
  assert.ok(fps.tick(true, null, [sample]).customFps == null);
  fps.noteManualFpsUpdate();
  assert.equal(fps.tick(true, 20, [sample]).customFps, 20);
  assert.throws(() => fps.tick(true, null, [{ ...sample, queueLen: 11 }]));
  assert.throws(() => fps.setDisplays([0, 0]));
  assert.throws(() => fps.tick(true, null, []));
  fps.reset(); fps.setDisplays([0]);
  assert.equal(fps.tick(false, 2, [sample]).customFps, 24);
});

test('decode FPS meter skips warmup and preserves source format-change estimate', () => {
  const meter = core.createViewerDecodeFps();
  assert.ok(meter.estimate() == null);
  for (let i = 0; i < 12; i++) assert.ok(meter.record(false, 20000) == null);
  assert.equal(meter.record(false, 20000), 50);
  assert.equal(meter.estimate(), 50);
  assert.ok(meter.record(true, 20000) == null);
  assert.equal(meter.estimate(), 50);
  assert.throws(() => meter.record(true, 60000001));
  assert.equal(meter.estimate(), 50);
  meter.reset(); assert.ok(meter.estimate() == null);
});

test('source-style frame-rate sample retains subsecond counts', () => {
  const rate = core.createViewerFrameRate();
  for (let i = 0; i < 30; i++) rate.recordFrame();
  assert.ok(rate.sample(999) == null);
  assert.throws(() => rate.sample(86400001));
  assert.equal(rate.sample(1500), 20);
  assert.equal(rate.sample(1000), 0);
  rate.recordFrame(); rate.reset(); assert.equal(rate.sample(1000), 0);
});
