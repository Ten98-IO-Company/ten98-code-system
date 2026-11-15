import assert from 'node:assert/strict';
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { checkPresentation, updatePresentationBaseline } from '../check.mjs';

const fixtures = new URL('./fixtures/presentation/', import.meta.url);
const profile = 'ten98-campaign';
const baselineName = 'presentation-baseline.json';

// rolldown arrives through this package's pinned vite devDependency, resolved the way the checker resolves it in a
// consumer: from the package itself, then from vite's own scope (pnpm's strict layout).
const runtime = createRequire(new URL('../package.json', import.meta.url));
const parserPath = [() => runtime.resolve('rolldown/parseAst'), () => createRequire(runtime.resolve('vite/package.json')).resolve('rolldown/parseAst')].map(find => {
  try { return find(); } catch { return undefined; }
}).find(Boolean);
const parseAst = parserPath ? runtime(parserPath).parseAst : undefined;
// CI never skips: a missing parser fails these tests there instead of passing them silently.
const needsParser = { skip: parseAst || process.env.CI ? false : 'rolldown/parseAst is not installed; run pnpm install' };

test('the parser resolves through the pinned vite whenever CI is set', { skip: process.env.CI ? false : 'only enforced when CI is set' }, () => {
  assert.equal(typeof parseAst, 'function', 'rolldown/parseAst must resolve through the vite devDependency in CI');
});

function consumer(files: string[], baseline: Record<string, Record<string, number>> | undefined, run: (root: string) => void) {
  const root = mkdtempSync(join(tmpdir(), 'ten98-presentation-'));
  try {
    mkdirSync(join(root, 'src'));
    for (const file of files) copyFileSync(new URL(file, fixtures), join(root, 'src', file));
    if (baseline) writeFileSync(join(root, baselineName), JSON.stringify(baseline));
    run(root);
  } finally { rmSync(root, { recursive: true, force: true }); }
}

const check = (root: string) => checkPresentation(root, profile, { parseAst });

test('only @ten98/ui imports and Ui.* members pass with strict zero', needsParser, () => consumer(['pass.tsx'], undefined, root => {
  assert.deepEqual(check(root), []);
}));

for (const [file, rule] of [
  ['element.tsx', 'element'], ['other-package.tsx', 'element'], ['styling.tsx', 'styling'], ['styling-spread.tsx', 'styling'],
  ['stylesheet.tsx', 'stylesheet'], ['create-element.tsx', 'create-element'], ['inner-html.tsx', 'inner-html'],
]) {
  test(`${file} violates ${rule}`, needsParser, () => consumer([file], undefined, root => {
    assert.deepEqual(check(root), [`src/${file}: ${rule} 1 exceeds baseline 0 (presentation is owned by @ten98/ui).`]);
  }));
}

test('ratchet allows counts within the baseline and rejects a rise or a new file', needsParser, () => {
  consumer(['element-twice.tsx'], { 'src/element-twice.tsx': { element: 2 } }, root => assert.deepEqual(check(root), []));
  consumer(['element-twice.tsx'], { 'src/element-twice.tsx': { element: 1 } }, root => {
    assert.match(check(root).join('\n'), /element 2 exceeds baseline 1/);
  });
  consumer(['element-twice.tsx', 'element.tsx'], { 'src/element-twice.tsx': { element: 2 } }, root => {
    assert.match(check(root).join('\n'), /src\/element\.tsx: element 1 exceeds baseline 0/);
  });
});

test('a missing baseline file is strict', needsParser, () => consumer(['element.tsx'], undefined, root => {
  assert.equal(existsSync(join(root, baselineName)), false);
  assert.equal(check(root).length, 1);
}));

test('update mode lowers counts, removes cleared entries and refuses to raise them', needsParser, () => {
  const stored = (root: string) => JSON.parse(readFileSync(join(root, baselineName), 'utf8'));
  consumer(['element.tsx'], { 'src/element.tsx': { element: 3 }, 'src/gone.tsx': { styling: 2 } }, root => {
    assert.deepEqual(updatePresentationBaseline(root, profile, { parseAst }), []);
    assert.deepEqual(stored(root), { 'src/element.tsx': { element: 1 } });
  });
  consumer(['element-twice.tsx'], { 'src/element-twice.tsx': { element: 1 } }, root => {
    assert.match(updatePresentationBaseline(root, profile, { parseAst }).join('\n'), /element 2 exceeds baseline 1/);
    assert.deepEqual(stored(root), { 'src/element-twice.tsx': { element: 1 } });
  });
});

test('update mode records a missing baseline once from current counts', needsParser, () => consumer(['element-twice.tsx', 'pass.tsx'], undefined, root => {
  assert.deepEqual(updatePresentationBaseline(root, profile, { parseAst }), []);
  assert.deepEqual(JSON.parse(readFileSync(join(root, baselineName), 'utf8')), { 'src/element-twice.tsx': { element: 2 } });
  assert.deepEqual(check(root), []);
}));

test('namespaced JSX tags are raw elements', needsParser, () => consumer(['namespaced.tsx'], undefined, root => {
  assert.deepEqual(check(root), ['src/namespaced.tsx: element 1 exceeds baseline 0 (presentation is owned by @ten98/ui).']);
}));

test('rolldown is resolved through vite when a strict layout keeps it out of the consumer scope', () => consumer(['pass.tsx'], undefined, root => {
  // pnpm layout: the consumer sees only vite; rolldown is reachable from vite's own node_modules.
  const rolldown = join(root, 'node_modules', 'vite', 'node_modules', 'rolldown');
  mkdirSync(rolldown, { recursive: true });
  writeFileSync(join(root, 'package.json'), '{"name":"fixture"}');
  writeFileSync(join(root, 'node_modules', 'vite', 'package.json'), '{"name":"vite","version":"8.3.4"}');
  writeFileSync(join(rolldown, 'package.json'), '{"name":"rolldown","exports":{"./parseAst":"./parse-ast.cjs"}}');
  writeFileSync(join(rolldown, 'parse-ast.cjs'), "exports.parseAst = () => ({ type: 'Program', body: [] });");
  assert.deepEqual(checkPresentation(root, profile), []);
}));

test('presentation checking fails closed when the consumer cannot resolve rolldown', () => consumer(['pass.tsx'], undefined, root => {
  assert.match(checkPresentation(root, profile).join('\n'), /Cannot resolve rolldown\/parseAst/);
}));
