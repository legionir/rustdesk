'use strict';
// Build the native addon for the current host only. RustDesk native codec and
// capture prerequisites still apply; this is not a portable prebuilt package.
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const workspace = path.resolve(__dirname, '../..');
const args = ['build', '--manifest-path', path.join(workspace, 'Cargo.toml'), '-p', 'remote-node'];
if (process.platform === 'linux' && process.env.REMOTE_CORE_LINUX_PKG_CONFIG === '1') args.push('--features', 'linux-pkg-config');
const result = spawnSync('cargo', args, { stdio: 'inherit', cwd: workspace });
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status || 1);
const target = process.env.CARGO_TARGET_DIR ? path.resolve(workspace, process.env.CARGO_TARGET_DIR) : path.join(workspace, 'target');
const filename = process.platform === 'win32' ? 'remote_node.dll' : process.platform === 'darwin' ? 'libremote_node.dylib' : 'libremote_node.so';
fs.copyFileSync(path.join(target, 'debug', filename), path.join(__dirname, 'remote_core.node'));
