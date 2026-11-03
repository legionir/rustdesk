'use strict';
// Helpers for a narrowly scoped, manual, trusted-network diagnostic. This is
// not a security policy, authentication service, consent UI or product SDK.
const net = require('node:net');
const readline = require('node:readline');

function specificIp(ip) {
  const family = net.isIP(ip);
  if (!family) return 0;
  if (family === 4) return ip === '0.0.0.0' ? 0 : family;
  // URL parsing canonicalizes alternate textual representations of IPv6;
  // reject scopes rather than silently dropping an interface identifier.
  if (ip.includes('%')) return 0;
  let canonical;
  try { canonical = new URL(`http://[${ip}]/`).hostname; } catch { return 0; }
  return canonical === '[::]' || canonical === '[::ffff:0:0]' ? 0 : family;
}
function address(ip, portText) {
  const family = specificIp(ip);
  if (!family) throw new Error('bind IP must be a specific literal address');
  if (!/^(0|[1-9][0-9]{0,4})$/.test(portText)) throw new Error('port must be a decimal integer from 0 through 65535');
  const port = Number(portText);
  if (port > 65535) throw new Error('invalid port');
  return family === 6 ? `[${ip}]:${port}` : `${ip}:${port}`;
}
function permittedPeer(ip) {
  if (!specificIp(ip)) throw new Error('peer must be a specific literal IP');
  return ip;
}
function password(value) {
  // Length is only a local floor, not a strength estimator. Use a unique,
  // high-entropy secret delivered to each operator through a secure channel.
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 20 || Buffer.byteLength(value, 'utf8') > 1024) {
    throw new Error('REMOTE_CORE_DEMO_PASSWORD must be 20–1024 UTF-8 bytes');
  }
  return value;
}
function positiveInteger(text, limit, name) {
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error(`invalid ${name}`);
  const number = Number(text);
  if (!Number.isSafeInteger(number) || number > limit) throw new Error(`invalid ${name}`);
  return number;
}
function frameCount(text = '1') {
  const value = positiveInteger(text, 10, 'frame count');
  if (value === 0) throw new Error('frame count must be 1 through 10');
  return value;
}
function mode(value = 'independent') {
  if (value !== 'independent' && value !== 'ack-burst') throw new Error('mode must be independent or ack-burst');
  return value;
}
function approve(question, timeoutMs = 30000, signal) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('an interactive terminal is required for local approval');
  if (signal?.aborted) return Promise.resolve(false);
  return new Promise((resolve, reject) => {
    const terminal = readline.createInterface({ input: process.stdin, output: process.stdout });
    let completed = false;
    const onAbort = () => finish(false);
    const finish = (value, error) => {
      if (completed) return;
      completed = true; clearTimeout(timer); signal?.removeEventListener('abort', onAbort);
      try { terminal.close(); } catch (closeError) { error ||= closeError; }
      if (error) reject(error); else resolve(value);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    terminal.once('close', () => finish(false));
    terminal.once('SIGINT', () => finish(false));
    try {
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) finish(false);
      else terminal.question(question, answer => finish(answer === 'YES'));
    } catch (error) { finish(false, error); }
  });
}
module.exports = { address, permittedPeer, password, positiveInteger, frameCount, mode, approve };
