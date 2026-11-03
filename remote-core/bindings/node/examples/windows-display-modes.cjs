'use strict';
// Manual read-only Windows example; do not expose the results without local
// consent. A name/index is not a stable identity, and this never sets a mode.
// Unbuilt and untested; requires a separately built experimental addon.
const core = require('..');
async function main() {
  if (process.platform !== 'win32' || process.argv[2] !== '--confirm-local-display-inspection') {
    throw new Error('Run on Windows only after explicit local display-inspection consent');
  }
  const displays = await core.listDisplays();
  if (!displays.length || displays.length > 64) throw new Error('invalid display count');
  for (const display of displays) {
    if (!display.online) continue;
    const result = await core.inspectWindowsDisplayModes(display.index, true);
    console.log(`Display ${display.index}: ${result.current.width}x${result.current.height}, ${result.modes.length} modes, truncated=${result.truncated}`);
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
