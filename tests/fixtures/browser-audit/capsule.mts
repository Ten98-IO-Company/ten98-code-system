import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createCapsuleCloseIntent } from '../../../browser-audit-capsule.mjs';
const capability = 'a'.repeat(64), identity = '/devtools/browser/11111111-1111-1111-1111-111111111111';
const armed = () => { const intent = createCapsuleCloseIntent(capability); intent.prepare(capability, identity, identity, 1, 100); return intent; };
test('only an armed exact browser with a live tunnel and clean child exit succeeds', () => {
  const intent = armed(); assert.equal(intent.disconnected(200), true); assert.equal(intent.exit(0, null, 300), true);
  assert.equal(intent.exit(0, null, 300), false);
});
test('wrong capability, browser and tunnel count cannot arm completion', () => {
  for (const [cap, path, tunnels] of [['b'.repeat(64), identity, 1], [capability, identity + 'x', 1], [capability, identity, 0], [capability, identity, 2]] as const) {
    const intent = createCapsuleCloseIntent(capability);
    assert.throws(() => intent.prepare(cap, path, identity, tunnels, 100));
    assert.equal(intent.exit(0, null, 200), false);
  }
});
test('intent is single use and cannot be replayed or refreshed', () => {
  const intent = armed(); assert.throws(() => intent.prepare(capability, identity, identity, 1, 200), /replayed/);
  assert.equal(intent.exit(0, null, 3100), false);
});
test('disconnect or clean child exit without intent is failure', () => {
  const intent = createCapsuleCloseIntent(capability); assert.equal(intent.disconnected(), false); assert.equal(intent.exit(0, null), false);
  assert.throws(() => intent.prepare(capability, identity, identity, 1));
});
test('nonzero, signal, elapsed deadline and cleanup failure remain failures after intent', () => {
  assert.equal(armed().exit(1, null, 200), false);
  assert.equal(armed().exit(null, 'SIGTERM', 200), false);
  assert.equal(armed().exit(0, 'SIGKILL', 200), false);
  assert.equal(armed().exit(0, null, 3100), false);
  const intent = armed(); intent.fail(); assert.equal(intent.exit(0, null, 200), false);
});
test('missing or malformed capability fails before Chromium launch', () => {
  for (const capability of ['', 'a', 'G'.repeat(64)]) {
    const child = spawnSync(process.execPath, ['--experimental-strip-types', fileURLToPath(new URL('../../../browser-audit-capsule.mjs', import.meta.url))], {
      env: { ...process.env, TEN98_CAPSULE_CLOSE_CAPABILITY: capability }, encoding: 'utf8', timeout: 2000, windowsHide: true,
    });
    assert.equal(child.status, 1); assert.match(child.stdout, /close-capability-invalid/); assert.doesNotMatch(child.stdout, /ready/);
  }
});
