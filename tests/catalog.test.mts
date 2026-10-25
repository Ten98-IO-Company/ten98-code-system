import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as runtime from '../index.mjs';

interface Implementation { source: string; entrypoints?: string[]; tests?: string[] }
interface Catalog {
  sources: Record<string, { repository: string; tag: string }>;
  portableImports: { runtime: { exports: string[]; tests: string[] }; auth: { exports: string[]; tests: string[] } };
  features: { id: string; implementations: Implementation[]; portable?: string[]; portableAuth?: string[] }[];
}
const catalog: Catalog = JSON.parse(readFileSync(new URL('../features/catalog.json', import.meta.url), 'utf8'));

test('every runtime export and test file the catalogue names exists in this package', () => {
  const exported = new Set(Object.keys(runtime));
  const named = [...catalog.portableImports.runtime.exports, ...catalog.features.flatMap(feature => feature.portable ?? [])];
  assert.deepEqual(named.filter(name => !exported.has(name)), []);
  assert.deepEqual(catalog.portableImports.runtime.tests.filter(path => !existsSync(new URL(`../${path}`, import.meta.url))), []);
});

test('every auth-entry export and test file the catalogue names exists', async () => {
  const exported = new Set(Object.keys(await import('../auth.mjs')));
  const named = [...catalog.portableImports.auth.exports, ...catalog.features.flatMap(feature => feature.portableAuth ?? [])];
  assert.deepEqual(named.filter(name => !exported.has(name)), []);
  assert.deepEqual(catalog.portableImports.auth.tests.filter(path => !existsSync(new URL(`../${path}`, import.meta.url))), []);
});

test('every implementation names a declared source', () => {
  const unknown = catalog.features.flatMap(feature => feature.implementations.filter(impl => !catalog.sources[impl.source]).map(impl => `${feature.id}:${impl.source}`));
  assert.deepEqual(unknown, []);
});

// App sources are checked against their tagged trees when a sibling checkout holds the tag (local development;
// TEN98_REPOS_DIR points elsewhere, for example from a worktree). CI has no checkouts, so it skips this part.
const repos = process.env.TEN98_REPOS_DIR ? pathToFileURL(`${process.env.TEN98_REPOS_DIR}/`) : new URL('../../', import.meta.url);
for (const [key, { repository, tag }] of Object.entries(catalog.sources)) {
  const checkout = new URL(`${repository}/`, repos);
  const tree = (() => {
    if (!existsSync(new URL('.git', checkout))) return null;
    try { return new Set(execFileSync('git', ['-C', fileURLToPath(checkout), 'ls-tree', '-r', '--name-only', `refs/tags/${tag}`], { encoding: 'utf8', maxBuffer: 64 << 20 }).split('\n')); }
    catch { return null; }
  })();
  test(`catalogue paths for ${key} exist at ${repository}@${tag}`, { skip: tree ? false : `no local ${repository} checkout with ${tag}` }, () => {
    const missing = catalog.features.flatMap(feature => feature.implementations.filter(impl => impl.source === key)
      .flatMap(impl => [...(impl.entrypoints ?? []), ...(impl.tests ?? [])]).filter(path => !tree!.has(path)).map(path => `${feature.id}: ${path}`));
    assert.deepEqual(missing, []);
  });
}
