import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import * as browser from '@ten98/runtime/browser';
import * as runtime from '../index.mjs';

const BROWSER_EXPORTS = ['addMoney', 'allocateMoney', 'compareMoney', 'csvCell', 'csvRow', 'formatMoney', 'mayGrantWorkspaceRole', 'mayManageWorkspaceMember', 'multiplyMoney', 'parseMoney', 'percentOfMoney', 'readResponseBytes', 'readResponseText', 'subtractMoney', 'toCsv', 'workspaceRoles'];

test('the browser entry exports roles and response readers, the same functions as the main entry', () => {
  assert.deepEqual(Object.keys(browser).sort(), BROWSER_EXPORTS);
  for (const name of BROWSER_EXPORTS) assert.equal((browser as Record<string, unknown>)[name], (runtime as Record<string, unknown>)[name]);
  const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.deepEqual(manifest.exports['./browser'], { types: './browser.d.mts', import: './browser.mjs' });
});

test('the browser entry loads with every Node built-in blocked', () => {
  // A loader hook that refuses node: and bare built-in specifiers, as a browser bundle without shims would.
  const blocker = `data:text/javascript,${encodeURIComponent(`
    import { builtinModules } from 'node:module';
    const builtins = new Set(builtinModules);
    export async function resolve(specifier, context, next) {
      if (context.parentURL && !context.parentURL.startsWith('data:') && (specifier.startsWith('node:') || builtins.has(specifier))) throw new Error('blocked ' + specifier);
      return next(specifier, context);
    }`)}`;
  const register = `data:text/javascript,${encodeURIComponent(`import { register } from 'node:module'; register(${JSON.stringify(blocker)});`)}`;
  const probe = (entry: URL) => spawnSync(process.execPath, ['--import', register, '--input-type=module', '-e', `const m = await import(${JSON.stringify(entry.href)}); console.log(Object.keys(m).length);`], { encoding: 'utf8', timeout: 10000, windowsHide: true });
  const loaded = probe(new URL('../browser.mjs', import.meta.url));
  assert.equal(loaded.status, 0, loaded.stderr);
  assert.equal(loaded.stdout.trim(), String(BROWSER_EXPORTS.length));
  // The same hook refuses the main entry, which needs node:crypto and others, so the block is real.
  const refused = probe(new URL('../index.mjs', import.meta.url));
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /blocked node:/);
  for (const file of ['browser-audit.mjs', 'browser-audit-capsule.mjs']) {
    const serverOnly = probe(new URL('../' + file, import.meta.url));
    assert.notEqual(serverOnly.status, 0);
    assert.match(serverOnly.stderr, /blocked node:/);
  }
});

test('the server facade omits capsule startup and importing the capsule does not launch it', () => {
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', "const api=await import('@ten98/runtime/browser-audit'); const capsule=await import('@ten98/runtime/browser-audit-capsule'); if('runCapsule' in api || typeof capsule.runCapsule !== 'function') process.exit(2); console.log('loaded');"], {cwd:new URL('../',import.meta.url),encoding:'utf8',timeout:5000,windowsHide:true,env:{...process.env,TEN98_CAPSULE_CLOSE_CAPABILITY:''}});
  assert.equal(child.status,0,child.stderr); assert.equal(child.stdout.trim(),'loaded');
});
