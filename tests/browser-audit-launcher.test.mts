import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import test, { type TestContext } from 'node:test';
import { runBrowserAuditLauncherGate } from '../browser-audit-launcher-gate.mjs';

const token = 'a1'.repeat(32);
const digest = createHash('sha256').update(token).digest('hex');
const frame = Buffer.from(token + '\n');
const timedContexts = new WeakSet<TestContext>();
function fixture(t: TestContext, extra: Record<string, string> = {}) {
  if (!timedContexts.has(t)) { t.mock.timers.enable({ apis: ['setTimeout'] }); timedContexts.add(t); }
  const input = new PassThrough();
  const environment = { TEN98_CAPSULE_START_SHA256: digest, TEN98_CAPSULE_CLOSE_CAPABILITY: 'b'.repeat(64), ...extra };
  const stopped: boolean[] = [];
  let launches = 0, forced = 0;
  let childEnvironment: NodeJS.ProcessEnv | undefined;
  const gate = runBrowserAuditLauncherGate({ input, environment,
    run: async () => { launches++; childEnvironment = { ...environment }; },
    terminate: released => { stopped.push(released); }, forceExit: () => { forced++; },
  });
  t.after(() => input.destroy());
  return { input, environment, stopped, gate, get launches() { return launches; }, get forced() { return forced; }, get childEnvironment() { return childEnvironment; } };
}

for (const [name, invalid] of Object.entries({ uppercase: token.toUpperCase() + '\n', wrong: 'b'.repeat(64) + '\n', crlf: token + '\r\n', oversized: token + '\nX', earlyNewline: token.slice(1) + '\n', nonAscii: 'é'.repeat(32) + '\n', nul: token + '\0' })) {
  test(`start gate rejects ${name} without launching`, t => {
    const f = fixture(t); f.input.write(invalid);
    assert.equal(f.launches, 0); assert.equal(f.gate.phase, 'failed'); assert.deepEqual(f.stopped, [false]);
    assert.equal(f.environment.TEN98_CAPSULE_CLOSE_CAPABILITY, 'b'.repeat(64));
  });
}

test('fragmented exact frame releases once and removes gate configuration before invocation', async t => {
  const f = fixture(t, { TEN98_CAPSULE_START_TOKEN: 'accidental-secret', TEN98_CAPSULE_START_CONFIG: 'unused' });
  for (const byte of frame.subarray(0, 64)) f.input.write(Buffer.from([byte]));
  assert.equal(f.launches, 0); f.input.write(frame.subarray(64)); await Promise.resolve();
  assert.equal(f.launches, 1); assert.equal(f.gate.phase, 'released');
  assert.deepEqual(f.childEnvironment, { TEN98_CAPSULE_CLOSE_CAPABILITY: 'b'.repeat(64) });
  assert.ok(!JSON.stringify(f.childEnvironment).includes(token));
  f.input.write(frame); assert.equal(f.launches, 1); assert.deepEqual(f.stopped, [true]);
  t.mock.timers.tick(4_000); assert.equal(f.forced, 1);
});

test('missing or partial input expires at30s without launch or a refreshed deadline', t => {
  const f = fixture(t); t.mock.timers.tick(29_999); f.input.write(token.slice(0, 10));
  assert.equal(f.gate.phase, 'waiting'); t.mock.timers.tick(1);
  assert.equal(f.launches, 0); assert.deepEqual(f.stopped, [false]);
});

for (const event of ['end', 'close', 'error'] as const) {
  test(`${event} fails closed before and after release`, t => {
    const f = fixture(t); f.input.emit(event, new Error('private detail'));
    assert.equal(f.launches, 0); assert.deepEqual(f.stopped, [false]);
    const released = fixture(t); released.input.write(frame); released.input.emit(event, new Error('private detail'));
    assert.equal(released.launches, 1); assert.deepEqual(released.stopped, [true]);
    t.mock.timers.tick(4_000); assert.equal(released.forced, 1);
  });
}

test('absolute lifetime survives the capsule readiness return and includes shutdown grace', async t => {
  const f = fixture(t); t.mock.timers.tick(20_000); f.input.write(frame); await Promise.resolve();
  t.mock.timers.tick(155_999); assert.deepEqual(f.stopped, []); assert.equal(f.gate.phase, 'released');
  t.mock.timers.tick(1); assert.deepEqual(f.stopped, [true]);
  t.mock.timers.tick(3_999); assert.equal(f.forced, 0);
  t.mock.timers.tick(1); assert.equal(f.forced, 1);
});

test('malformed or missing digest fails without reading or launching and is scrubbed', t => {
  for (const value of ['', 'a'.repeat(63), 'A'.repeat(64), digest + '\n']) {
    const f = fixture(t, { TEN98_CAPSULE_START_SHA256: value });
    assert.equal(f.gate.phase, 'failed'); assert.equal(f.launches, 0); assert.equal(f.input.listenerCount('data'), 0);
    assert.equal('TEN98_CAPSULE_START_SHA256' in f.environment, false);
  }
});

test('synchronous and asynchronous capsule startup failures terminate permanently', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  for (const run of [() => { throw Error('secret'); }, async () => { throw Error('secret'); }]) {
    const input = new PassThrough(), stopped: boolean[] = [];
    const gate = runBrowserAuditLauncherGate({ input, environment: { TEN98_CAPSULE_START_SHA256: digest }, run,
      terminate: released => { stopped.push(released); }, forceExit: () => {} });
    input.write(frame); await Promise.resolve(); await Promise.resolve();
    assert.equal(gate.phase, 'failed'); assert.deepEqual(stopped, [true]); input.destroy();
  }
});

const entry = new URL('../browser-audit-launcher-gate.mjs', import.meta.url);
test('import is passive even with invalid configuration and a closed stdin', () => {
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(entry.href)}); console.log('imported');`], {
    encoding: 'utf8', timeout: 5_000, windowsHide: true, env: { ...process.env, TEN98_CAPSULE_START_SHA256: '' },
  });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout.trim(), 'imported');
});

test('fixed process entry rejects bad input and EOF without capsule startup or capability output', () => {
  for (const input of ['', token.slice(0, 20), token.toUpperCase() + '\n', token + '\nX']) {
    const result = spawnSync(process.execPath, [fileURLToPath(entry)], {
      input, encoding: 'utf8', timeout: 5_000, windowsHide: true,
      env: { ...process.env, TEN98_CAPSULE_START_SHA256: digest, TEN98_CAPSULE_CLOSE_CAPABILITY: '' },
    });
    assert.equal(result.status, 1, result.stderr); assert.equal(result.stdout, ''); assert.equal(result.stderr, '');
  }
});

test('real stdin keeps a ready child alive, excludes gate secrets, and terminates on EOF', async t => {
  const code = `import {runBrowserAuditLauncherGate} from ${JSON.stringify(entry.href)};
    runBrowserAuditLauncherGate({run:async()=>{console.log(JSON.stringify({ready:true,gateKeys:Object.keys(process.env).filter(k=>k.startsWith('TEN98_CAPSULE_START_'))}));},terminate:released=>process.exit(released?19:18)});`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, TEN98_CAPSULE_START_SHA256: digest, TEN98_CAPSULE_START_TOKEN: 'must-not-reach-capsule' },
  });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  const deadline = setTimeout(() => child.kill(), 5_000); t.after(() => clearTimeout(deadline));
  const closed = once(child, 'close'); const output = once(child.stdout, 'data');
  child.stdin.write(frame);
  const [data] = await output;
  assert.deepEqual(JSON.parse(String(data)), { ready: true, gateKeys: [] });
  assert.equal(child.exitCode, null); child.stdin.end();
  const [codeResult] = await closed; assert.equal(codeResult, 19);
});
