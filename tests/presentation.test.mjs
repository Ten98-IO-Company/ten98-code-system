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

// rolldown is not a dependency of this package; borrow it from a checkout that has it installed.
const parseAst = ['..', '../../ten98-campaign', '../../../../../ten98-campaign', '../../ten98-design-system', '../../../../../ten98-design-system'].map(folder => {
  try { return createRequire(new URL(`${folder}/package.json`, import.meta.url))('rolldown/parseAst').parseAst; } catch { /* not installed here */ }
}).find(Boolean);
const needsParser = { skip: parseAst ? false : 'rolldown/parseAst is not installed in any known checkout' };

function consumer(files, baseline, run) {
  const root = mkdtempSync(join(tmpdir(), 'ten98-presentation-'));
  try {
    mkdirSync(join(root, 'src'));
    for (const file of files) copyFileSync(new URL(file, fixtures), join(root, 'src', file));
    if (baseline) writeFileSync(join(root, baselineName), JSON.stringify(baseline));
    run(root);
  } finally { rmSync(root, { recursive: true, force: true }); }
}

const check = root => checkPresentation(root, profile, { parseAst });

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
  const stored = root => JSON.parse(readFileSync(join(root, baselineName), 'utf8'));
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
