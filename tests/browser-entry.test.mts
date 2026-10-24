import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import * as browser from '@ten98/runtime/browser';
import * as runtime from '../index.mjs';

const BROWSER_EXPORTS = ['mayGrantWorkspaceRole', 'mayManageWorkspaceMember', 'readResponseBytes', 'readResponseText', 'workspaceRoles'];

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
});
