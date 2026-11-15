import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import test from 'node:test';
import type { TestContext } from 'node:test';
import { pathToFileURL } from 'node:url';
import { checkPresentation, inspectWaivers, presentationTotals, recordSharedFlows, updatePresentationBaseline } from '../check.mjs';
import type { TotalsReport } from '../check.mjs';

const fixtures = new URL('./fixtures/presentation/', import.meta.url);
const profile = 'ten98-campaign';
const baselineName = 'presentation-baseline.json';
const registerName = 'shared-flows.json';
// The design system's list, copied unchanged from ten98-design-system main d77ce68 (PR #226), to ship in @ten98/ui 0.40.0.
const uiList = readFileSync(new URL('./fixtures/shared-flows/ui-list.json', import.meta.url), 'utf8');
const listed: Record<string, { exports: { name: string; entry: string }[] }> = JSON.parse(uiList).features;
const firstUi: string = JSON.parse(readFileSync(new URL('../architecture.json', import.meta.url), 'utf8')).appStack.presentation.sharedFlows.firstUiVersion;
const adapterSource = "import { useBlocker } from '@tanstack/react-router';\nexport const useAppBlocker = useBlocker;\n";
const ratchetRules = ['native-dialog', 'router-blocker', 't98-selector', 't98-class', 't98-dom'];
const owned = '(presentation is owned by @ten98/ui).';

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

type Register = { leaveGuardAdapter?: unknown; features: Record<string, unknown> };
type Baseline = Record<string, unknown>;
interface Setup {
  files?: string[];
  sources?: Record<string, string>;
  // An object is written as JSON; a string is written as given.
  baseline?: Baseline | string;
  // undefined writes every listed feature as absent; null writes no register; a string is written as given.
  register?: Register | null | string;
  // The installed @ten98/ui: its version and list text, or null for a release without the list.
  ui?: { version?: string; list?: string | null };
}

const absentRegister = (): Register => ({
  leaveGuardAdapter: 'src/leave-guard.ts',
  features: Object.fromEntries(Object.keys(listed).map(id => [id, { status: 'absent', reason: 'Not in this fixture.' }])),
});

function consumer({ files = [], sources = {}, baseline, register, ui = {} }: Setup, run: (root: string) => void) {
  const root = mkdtempSync(join(tmpdir(), 'ten98-presentation-'));
  try {
    mkdirSync(join(root, 'src'));
    for (const file of files) copyFileSync(new URL(file, fixtures), join(root, 'src', file));
    for (const [path, text] of Object.entries({ 'src/leave-guard.ts': adapterSource, ...sources })) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), text);
    }
    if (baseline !== undefined) writeFileSync(join(root, baselineName), typeof baseline === 'string' ? baseline : JSON.stringify(baseline));
    if (register !== null) writeFileSync(join(root, registerName), typeof register === 'string' ? register : JSON.stringify(register ?? absentRegister()));
    const uiFolder = join(root, 'node_modules', '@ten98', 'ui');
    mkdirSync(uiFolder, { recursive: true });
    const exports = ui.list === null ? { '.': './index.js' } : { '.': './index.js', './shared-flows.json': './shared-flows.json' };
    writeFileSync(join(uiFolder, 'package.json'), JSON.stringify({ name: '@ten98/ui', version: ui.version ?? firstUi, exports }));
    if (ui.list !== null) writeFileSync(join(uiFolder, 'shared-flows.json'), ui.list ?? uiList);
    run(root);
  } finally { rmSync(root, { recursive: true, force: true }); }
}

const check = (root: string) => checkPresentation(root, profile, { parseAst });
const update = (root: string) => updatePresentationBaseline(root, profile, { parseAst });
// A register with every feature absent, then changed; a further argument replaces the adapter, and undefined removes it.
const register = (change: (features: Record<string, unknown>) => void, ...adapter: unknown[]): Register => {
  const { features, leaveGuardAdapter } = absentRegister();
  change(features);
  if (!adapter.length) return { leaveGuardAdapter, features };
  return adapter[0] === undefined ? { features } : { leaveGuardAdapter: adapter[0], features };
};
const list = (change: (features: Record<string, any>) => void): string => {
  const parsed = JSON.parse(uiList);
  change(parsed.features);
  return JSON.stringify(parsed);
};
// The ratchet totals one run reports, and its errors.
function run(root: string): { totals: Record<string, number>; errors: string[] } {
  let report = { unavailable: 'not reported' } as TotalsReport;
  const errors = checkPresentation(root, profile, { parseAst, onTotals: reported => { report = reported; } });
  return { totals: 'totals' in report ? report.totals : {}, errors };
}
const totalsFor = (sources: Record<string, string>, setup: Setup = {}): Record<string, number> => {
  let totals: Record<string, number> = {};
  consumer({ ...setup, sources }, root => { totals = run(root).totals; });
  return totals;
};

test('only @ten98/ui imports and Ui.* members pass with strict zero', needsParser, () => consumer({ files: ['pass.tsx'] }, root => {
  assert.deepEqual(check(root), []);
}));

for (const [file, rule] of [
  ['element.tsx', 'element'], ['other-package.tsx', 'element'], ['styling.tsx', 'styling'], ['styling-spread.tsx', 'styling'],
  ['stylesheet.tsx', 'stylesheet'], ['create-element.tsx', 'create-element'], ['inner-html.tsx', 'inner-html'],
]) {
  test(`${file} violates ${rule}`, needsParser, () => consumer({ files: [file] }, root => {
    assert.deepEqual(check(root), [`src/${file}: ${rule} 1 exceeds baseline 0 ${owned}`]);
  }));
}

test('the five JSX rules still count JSX files only', needsParser, () => consumer({ sources: { 'src/main.ts': "import './app.css';\nimport { createElement } from 'react';\ncreateElement('div');\n" } }, root => {
  assert.deepEqual(check(root), []);
}));

test('ratchet allows counts within the baseline and rejects a rise or a new file', needsParser, () => {
  consumer({ files: ['element-twice.tsx'], baseline: { 'src/element-twice.tsx': { element: 2 } } }, root => assert.deepEqual(check(root), []));
  consumer({ files: ['element-twice.tsx'], baseline: { 'src/element-twice.tsx': { element: 1 } } }, root => {
    assert.match(check(root).join('\n'), /element 2 exceeds baseline 1/);
  });
  consumer({ files: ['element-twice.tsx', 'element.tsx'], baseline: { 'src/element-twice.tsx': { element: 2 } } }, root => {
    assert.match(check(root).join('\n'), /src\/element\.tsx: element 1 exceeds baseline 0/);
  });
});

test('a missing baseline file is strict', needsParser, () => consumer({ files: ['element.tsx'] }, root => {
  assert.equal(existsSync(join(root, baselineName)), false);
  assert.equal(check(root).length, 1);
}));

const stored = (root: string) => JSON.parse(readFileSync(join(root, baselineName), 'utf8'));
const allRules = ['element', 'styling', 'inner-html', 'create-element', 'stylesheet', ...ratchetRules];

test('update mode lowers counts, removes cleared entries and refuses to raise them', needsParser, () => {
  consumer({ files: ['element.tsx'], baseline: { $rules: allRules, 'src/element.tsx': { element: 3 }, 'src/gone.tsx': { styling: 2 } } }, root => {
    assert.deepEqual(update(root), []);
    assert.deepEqual(stored(root), { $rules: allRules, 'src/element.tsx': { element: 1 } });
  });
  consumer({ files: ['element-twice.tsx'], baseline: { $rules: allRules, 'src/element-twice.tsx': { element: 1 } } }, root => {
    assert.match(update(root).join('\n'), /element 2 exceeds baseline 1/);
    assert.deepEqual(stored(root), { $rules: allRules, 'src/element-twice.tsx': { element: 1 } });
  });
});

test('update mode records a missing baseline once from current counts, and reports the totals', needsParser, () => consumer({ files: ['element-twice.tsx', 'pass.tsx'] }, root => {
  let report: TotalsReport | undefined;
  assert.deepEqual(updatePresentationBaseline(root, profile, { parseAst, onTotals: reported => { report = reported; } }), []);
  assert.deepEqual(report, { totals: Object.fromEntries(ratchetRules.map(rule => [rule, 0])) });
  assert.deepEqual(stored(root), { $rules: allRules, 'src/element-twice.tsx': { element: 2 } });
  assert.deepEqual(check(root), []);
}));

test('update mode records the ratchet rules once on a baseline from before them, then only lowers them', needsParser, () => consumer({
  sources: { 'src/ask.tsx': "export const ask = () => window.confirm('Leave?') && window.alert('Bye');\n" },
  baseline: { 'src/ask.tsx': { element: 0 } },
}, root => {
  // The old baseline allows no native dialogs, so the check refuses until the new rules are recorded.
  assert.match(check(root).join('\n'), /src\/ask\.tsx: native-dialog 2 exceeds baseline 0/);
  assert.deepEqual(update(root), []);
  assert.deepEqual(stored(root), { $rules: allRules, 'src/ask.tsx': { 'native-dialog': 2 } });
  assert.deepEqual(check(root), []);
  // Recorded once: a rise is now refused, and a fall is recorded.
  writeFileSync(join(root, 'src/ask.tsx'), "export const ask = () => window.confirm('a') && window.alert('b') && window.prompt('c');\n");
  assert.match(update(root).join('\n'), /native-dialog 3 exceeds baseline 2/);
  writeFileSync(join(root, 'src/ask.tsx'), "export const ask = () => window.confirm('a');\n");
  assert.deepEqual(update(root), []);
  assert.deepEqual(stored(root), { $rules: allRules, 'src/ask.tsx': { 'native-dialog': 1 } });
}));

test('a baseline from before "$rules" still refuses a rise in an older rule', needsParser, () => consumer({
  files: ['element-twice.tsx'], baseline: { 'src/element-twice.tsx': { element: 1 } },
}, root => {
  assert.match(update(root).join('\n'), /element 2 exceeds baseline 1/);
  assert.deepEqual(stored(root), { 'src/element-twice.tsx': { element: 1 } });
}));

test('a hand-edited "$rules" never lets the update record a rise', needsParser, () => {
  const dialogs = (count: number) => ({ 'src/a.ts': `${"window.confirm('a');\n".repeat(count)}` });
  const missing = `${baselineName} has entries for native-dialog but no "$rules"; restore "$rules".`;
  const invalid = `${baselineName}: "$rules" must list known rules, including element, styling, inner-html, create-element, stylesheet and every rule its entries use.`;
  for (const [baseline, sources, expected] of [
    // The key deleted by hand while an entry still uses a ratchet rule.
    [{ 'src/a.ts': { 'native-dialog': 2 } }, dialogs(6), missing],
    // An empty list, a new file with host tags.
    [{ $rules: [], 'src/a.ts': { 'native-dialog': 1 } }, { ...dialogs(1), 'src/x.tsx': 'export const X = () => <><b /><i /></>;\n' }, invalid],
    // Not a list.
    [{ $rules: 'all', 'src/a.ts': { 'native-dialog': 1 } }, dialogs(2), invalid],
    // An unknown rule, and a list without a rule an entry uses.
    [{ $rules: [...allRules, 'elemnt'], 'src/a.ts': { 'native-dialog': 1 } }, dialogs(1), invalid],
    [{ $rules: ['element', 'styling', 'inner-html', 'create-element', 'stylesheet'], 'src/a.ts': { 'native-dialog': 1 } }, dialogs(2), invalid],
  ] satisfies [Baseline, Record<string, string>, string][]) {
    consumer({ baseline, sources }, root => {
      const before = readFileSync(join(root, baselineName), 'utf8');
      assert.ok(update(root).includes(expected), JSON.stringify(baseline));
      assert.ok(check(root).includes(expected), JSON.stringify(baseline));
      assert.equal(readFileSync(join(root, baselineName), 'utf8'), before);
    });
  }
});

test('a repeated key in the baseline or the register is refused', needsParser, () => {
  consumer({ baseline: '{ "$rules": [], "src/a.ts": { "element": 1 }, "src/a.ts": { "element": 5 } }' }, root => {
    assert.ok(check(root).includes(`${baselineName}: key "src/a.ts" appears more than once in one object.`));
  });
  const text = JSON.stringify(absentRegister()).replace('"team":{"status":', '"team":{"status":"uses","status":');
  consumer({ register: text }, root => {
    // A refused register names no adapter, so the adapter's own import counts as well.
    assert.deepEqual(check(root), [`${registerName}: key "status" appears more than once in one object.`, `src/leave-guard.ts: router-blocker 1 exceeds baseline 0 ${owned}`]);
  });
});

test('update mode refuses while the register has errors', needsParser, () => consumer({ files: ['element.tsx'], register: register(() => undefined, '') }, root => {
  assert.match(update(root).join('\n'), /leaveGuardAdapter, when given, must name/);
  assert.equal(existsSync(join(root, baselineName)), false);
}));

test('namespaced JSX tags are raw elements', needsParser, () => consumer({ files: ['namespaced.tsx'] }, root => {
  assert.deepEqual(check(root), [`src/namespaced.tsx: element 1 exceeds baseline 0 ${owned}`]);
}));

test('rolldown is resolved through vite when a strict layout keeps it out of the consumer scope', () => consumer({ files: ['pass.tsx'] }, root => {
  // pnpm layout: the consumer sees only vite; rolldown is reachable from vite's own node_modules.
  const rolldown = join(root, 'node_modules', 'vite', 'node_modules', 'rolldown');
  mkdirSync(rolldown, { recursive: true });
  writeFileSync(join(root, 'package.json'), '{"name":"fixture"}');
  writeFileSync(join(root, 'node_modules', 'vite', 'package.json'), '{"name":"vite","version":"8.3.4"}');
  writeFileSync(join(rolldown, 'package.json'), '{"name":"rolldown","exports":{"./parseAst":"./parse-ast.cjs"}}');
  writeFileSync(join(rolldown, 'parse-ast.cjs'), "exports.parseAst = () => ({ type: 'Program', body: [] });");
  assert.deepEqual(checkPresentation(root, profile), []);
}));

test('presentation checking fails closed when the consumer cannot resolve rolldown', () => consumer({ files: ['pass.tsx'] }, root => {
  assert.match(checkPresentation(root, profile).join('\n'), /Cannot resolve rolldown\/parseAst/);
  assert.match(String((presentationTotals(root, profile) as { unavailable: string }).unavailable), /Cannot resolve rolldown\/parseAst/);
}));

test('the totals are unavailable when a root is missing or a file cannot be parsed', needsParser, () => {
  consumer({ sources: { 'src/broken.ts': 'const = ;\n' } }, root => {
    assert.match(String((presentationTotals(root, profile, { parseAst }) as { unavailable: string }).unavailable), /src\/broken\.ts: cannot parse/);
    rmSync(join(root, 'src'), { recursive: true });
    assert.match(String((presentationTotals(root, profile, { parseAst }) as { unavailable: string }).unavailable), /Required presentation root missing: src/);
  });
  assert.equal(presentationTotals('.', '@ten98/runtime', { parseAst }), undefined);
});

// Ratchet rules. Each case is a source and how many the rule counts in it.
const ruleCases: [string, string, string, number][] = [
  ['native-dialog', 'src/a.tsx', "window.confirm('a');", 1],
  ['native-dialog', 'src/a.tsx', "globalThis.alert('a'); self.prompt('a');", 2],
  ['native-dialog', 'src/a.tsx', "window.confirm?.('a'); window?.alert('a'); (window?.prompt)('a');", 3],
  ['native-dialog', 'src/a.tsx', "window['confirm']('a'); window[`prompt`]('a');", 2],
  ['native-dialog', 'src/a.ts', "window.confirm!('a'); (window.alert)('a');", 2],
  ['native-dialog', 'src/a.ts', "(window as any).confirm('a'); (<any>window).alert('a'); (window satisfies Window).prompt('a');", 3],
  ['native-dialog', 'src/a.ts', "window.confirm.call(window, 'a'); window.alert.apply(window, ['a']); const ask = window.prompt.bind(window); confirm.call(null, 'a');", 4],
  ['native-dialog', 'src/a.ts', "window.window.confirm('a'); globalThis.window.alert('a'); self.globalThis.prompt('a');", 3],
  ['native-dialog', 'src/a.tsx', "confirm('a'); alert('b'); prompt('c');", 3],
  ['native-dialog', 'src/a.js', 'self.prompt`name`;', 1],
  // A comment or a string mentioning a dialog, a locally declared name, another object, a computed key, a variable.
  ['native-dialog', 'src/a.tsx', "// window.confirm('a')\n/* alert('b') */ const text = \"window.confirm('a')\";", 0],
  ['native-dialog', 'src/a.tsx', "function confirm(text: string) { return text; }\nconfirm('a');", 0],
  ['native-dialog', 'src/a.tsx', "import { alert } from './toast';\nconst { prompt } = api;\nalert('a'); prompt('b');", 0],
  ['native-dialog', 'src/a.ts', "function ask(confirm: (text: string) => boolean) { return confirm('a'); }", 0],
  ['native-dialog', 'src/a.ts', "try { run(); } catch (alert) { alert('a'); }", 0],
  ['native-dialog', 'src/a.ts', "import prompt from './prompt';\nimport * as confirm from './confirm';\nprompt('a'); confirm('b');", 0],
  ['native-dialog', 'src/a.tsx', "dialog.confirm('a'); window[name]('a'); const ask = window.confirm; ask('a');", 0],
  // Listed in the guide as not seen: other window references and a dialog passed as a value.
  ['native-dialog', 'src/a.ts', "top.confirm('a'); parent.alert('a'); frames.confirm('a'); document.defaultView.confirm('a'); run(window.confirm); (0, window.alert)('a');", 0],
  ['router-blocker', 'src/a.tsx', "import { useBlocker } from '@tanstack/react-router';", 1],
  ['router-blocker', 'src/a.tsx', "import { useBlocker as block } from 'react-router';", 1],
  ['router-blocker', 'src/a.ts', "import { Link, useBlocker } from 'react-router-dom';", 1],
  ['router-blocker', 'src/a.tsx', "import { Block } from '@tanstack/react-router';\nimport { usePrompt, unstable_usePrompt, unstable_useBlocker } from 'react-router-dom';", 4],
  ['router-blocker', 'src/a.ts', "const { useBlocker } = require('react-router');\nconst router = await import('react-router-dom');", 2],
  // Type-only, another package, the namespace form, history blocking and beforeunload, none of which it sees.
  ['router-blocker', 'src/a.ts', "import type { useBlocker } from '@tanstack/react-router';\nimport { type useBlocker as B } from 'react-router';", 0],
  ['router-blocker', 'src/a.ts', "import { useBlocker } from './blocker';\nimport * as Router from '@tanstack/react-router';\nRouter.useBlocker({});\nrequire('./router');", 0],
  ['router-blocker', 'src/a.ts', "router.history.block(() => true);\nwindow.addEventListener('beforeunload', stop);", 0],
  ['t98-class', 'src/a.tsx', 'export const A = () => <Card className="t98-card" />;', 1],
  ['t98-class', 'src/a.tsx', 'export const A = () => <Card className={`t98-card ${wide}`} />;', 1],
  ['t98-class', 'src/a.tsx', "export const A = () => <Card className={cx('t98-a', on && 't98-b', 'c')} />;", 2],
  ['t98-class', 'src/a.tsx', 'export const A = () => <div class="t98-a" />;', 1],
  ['t98-class', 'src/a.tsx', "export const A = () => <Card className={'t98' + '-button'} />; export const B = () => <Card className={'wide ' + 't98-a'} />;", 2],
  ['t98-class', 'src/a.tsx', "export const A = () => <Card className=\"wide\" title=\"t98-card\" data-x={'t98-a'} />;", 0],
  // Substitutions break a name, and a longer name or a custom property is not a library class.
  ['t98-class', 'src/a.tsx', "export const A = () => <Card className={`t98${x}-a`} />; export const B = () => <Card className={'t9' + x + '8-a'} />; export const C = () => <Card className=\"not-t98-x --t98-y\" />;", 0],
  // Listed in the guide as not seen: an object-literal spread and other props.
  ['t98-class', 'src/a.tsx', "export const A = () => <Card {...{ className: 't98-a' }} classNames={{ root: 't98-c' }} contentClassName=\"t98-d\" />;", 0],
  ['t98-dom', 'src/a.ts', "el.querySelector('.t98-card'); document.querySelectorAll(`[data-t98]`);", 2],
  ['t98-dom', 'src/a.ts', "el.closest('.t98-a'); el.matches('.t98-a'); document.getElementsByClassName('t98-a');", 3],
  ['t98-dom', 'src/a.ts', "el.classList.add('t98-a'); el.classList.remove(`t98-${x}`); el?.classList.toggle('t98-a');", 3],
  ['t98-dom', 'src/a.ts', "el.classList.contains('t98-a'); el.classList.replace('a', 't98-b'); el.classList.add('x', 't98-a');", 3],
  ['t98-dom', 'src/a.ts', "el.className = 't98-a'; el.setAttribute('class', 't98-a'); el.getAttribute('data-t98-part'); el.querySelector('.t98' + '-x');", 4],
  ['t98-dom', 'src/a.ts', "el.querySelector('button'); el.querySelector(selector); el.classList.add('wide'); set.add('t98-a'); el.closest(`t98${x}-a`);", 0],
  // A selector call counts an attribute selector on class as a stylesheet does, in any of its operators and in a list.
  ['t98-dom', 'src/a.ts', "el.querySelector('[class*=\"t98\"]'); el.querySelectorAll('[class^=t98]'); el.closest('[class|=t98]'); el.matches('div[class~=\"t98\"]');", 4],
  ['t98-dom', 'src/a.ts', "el.querySelector('p, [class$=\"t98\"]'); document.querySelectorAll(`[class*='t98']`);", 2],
  // Another class, another attribute, a name that only ends in t98, and calls that take a name rather than a selector.
  ['t98-dom', 'src/a.ts', "el.querySelector('[class*=\"theme\"]'); el.matches('[title*=\"t98\"]'); el.closest('[data-theme], .x-t98-y'); el.getAttribute('[class*=\"t98\"]'); el.getElementsByClassName('t98');", 0],
  // Public: the theme attributes and the --t98-* custom properties. Not seen: the dataset form.
  ['t98-dom', 'src/a.ts', "el.setAttribute('data-theme', 'dark'); el.style.setProperty('--t98-accent', 'red'); el.matches('[data-density]'); el.setAttribute('style', '--t98-accent: red'); el.dataset.t98Part;", 0],
  // Declaration files are not scanned.
  ['native-dialog', 'src/types.d.ts', "window.confirm('a');", 0],
];

for (const [rule, path, source, expected] of ruleCases) {
  test(`${rule} counts ${expected} in ${path}: ${JSON.stringify(source)}`, needsParser, () => {
    assert.equal(totalsFor({ [path]: `${source}\n` })[rule], expected);
  });
}

test('every run reports each ratchet rule total, including zeros, and refuses a new file', needsParser, () => consumer({
  sources: { 'src/a.tsx': "window.confirm('a');\n", 'src/b.ts': "el.classList.add('t98-x');\n", 'src/c.css': '.t98-x {}\n' },
}, root => {
  const { totals, errors } = run(root);
  assert.deepEqual(totals, { 'native-dialog': 1, 'router-blocker': 0, 't98-selector': 1, 't98-class': 0, 't98-dom': 1 });
  assert.deepEqual([...errors].sort(), [
    `src/a.tsx: native-dialog 1 exceeds baseline 0 ${owned}`,
    `src/b.ts: t98-dom 1 exceeds baseline 0 ${owned}`,
    `src/c.css: t98-selector 1 exceeds baseline 0 ${owned}`,
  ]);
}));

test('test files under the roots count for the ratchets', needsParser, () => {
  assert.equal(totalsFor({ 'src/a.test.tsx': "window.confirm('a');\n" })['native-dialog'], 1);
});

test('the leave-guard adapter alone may import useBlocker', needsParser, () => {
  consumer({ sources: { 'src/page.tsx': adapterSource, 'src/lazy.ts': "await import('@tanstack/react-router');\n" } }, root => {
    assert.deepEqual(check(root).sort(), [`src/lazy.ts: router-blocker 1 exceeds baseline 0 ${owned}`, `src/page.tsx: router-blocker 1 exceeds baseline 0 ${owned}`]);
  });
  // The adapter's own dynamic import and require are exempt too.
  consumer({ sources: { 'src/leave-guard.ts': `${adapterSource}const router = require('react-router');\nawait import('react-router-dom');\n` } }, root => assert.deepEqual(check(root), []));
  // With an adapter that names no real file, the adapter file is counted too.
  consumer({ register: register(() => undefined, 'src/missing.ts') }, root => {
    assert.match(check(root).join('\n'), /src\/leave-guard\.ts: router-blocker 1 exceeds baseline 0/);
  });
});

const cssCases: [string, number][] = [
  ['.t98-button { color: red; }', 1],
  ['.a, .t98-b {}', 1],
  ['.t98-a, .t98-b > span {}', 2],
  [':is(.t98-a, .b) {}', 1],
  [':is(.t98-a, .t98-b) {}', 1],
  ['@media (min-width: 40rem) { .t98-a { } .b { } }', 1],
  ['@supports (display: grid) { @layer app { .t98-a {} } }', 1],
  ['.a { color: red; .t98-b { color: blue; } }', 1],
  // Attribute selectors on class, with or without the hyphen, quoted or not, in any case.
  ['[class*="t98-"] {}', 1],
  ['[class*="t98"] {}', 1],
  ['[class^=t98] {}', 1],
  ['[class|=t98] {}', 1],
  ['div[CLASS~="t98-card"] {}', 1],
  ['@scope (.t98-card) to (.content) { p { color: red; } }', 1],
  // A brace or a semicolon inside a string does not end the selector, and an unterminated string ends at its line.
  ['[title="{"] .t98-a {} [data-x=";"] .t98-b {}', 2],
  ['.a { content: "oops\n} .t98-b {}', 1],
  ['/* .t98-a {} */ .a {}', 0],
  ['.a::after { content: ".t98-a {"; } .b {}', 0],
  ['.a { content: "t98-"; }', 0],
  ['@layer t98-overrides { .a {} } @import "t98-x.css";', 0],
  // An at-rule's own prelude is not a selector list, even when it names a class; only @scope's is.
  ['@supports selector(.t98-a) { .b {} }', 0],
  ['.x-t98-y, #t98-id, [class] {}', 0],
  // Other attributes, private or public, and the public custom properties never count.
  ["div[data-t98-part='x'], [title*=\"t98\"] {}", 0],
  ['[data-theme="dark"] { --t98-accent: red; color: var(--t98-space-4); }', 0],
  ['[data-density] {} .theme { --t98-accent: red; } .a { padding: var(--t98-space-4); }', 0],
];
for (const [css, expected] of cssCases) {
  test(`t98-selector counts ${expected} in ${JSON.stringify(css)}`, needsParser, () => {
    assert.equal(totalsFor({ 'src/styles/app.css': css })['t98-selector'], expected);
  });
}

test('t98-selector reads .pcss files', needsParser, () => {
  assert.equal(totalsFor({ 'src/styles/app.pcss': '.t98-a {}' })['t98-selector'], 1);
});

test('the stylesheet scanner stays linear on a large and hostile input', needsParser, () => {
  const rules = '.a { color: red; }\n.t98-b, .c { margin: 0; }\n'.repeat(40_000);
  const hostile = `${'['.repeat(200_000)}${'"'.repeat(200_000)}${'('.repeat(200_000)} {} .t98-z {}\n/* unterminated ${'*'.repeat(200_000)}`;
  const started = performance.now();
  // 40,000 from the rules, and the one `.t98-z` after the hostile prelude closes.
  assert.equal(totalsFor({ 'src/big.css': rules, 'src/hostile.css': hostile })['t98-selector'], 40_001);
  assert.ok(performance.now() - started < 10_000, 'scanning took too long');
});

// The shared-flow register.
const sourceSets = (...sets: Record<string, string>[]): Record<string, string>[] => sets;
const usesTeam = register(features => { features.team = { status: 'uses' }; });
const teamRefused = `${registerName}: team is "uses", but no non-test file under src renders or calls TeamFlow imported from @ten98/ui (shared since @ten98/ui 0.5.0).`;
const teamAbsentRefused = `${registerName}: team is "absent", but TeamFlow is imported from @ten98/ui.`;
// `export * from '@ten98/ui'` imports every export, so it also refuses the fixture's absent entries, and a member tag
// counts as a host element; only team's entry matters in the barrel cases.
const teamOnly = (errors: string[]): string[] => errors.filter(error => !/is "absent", but| element \d+ exceeds/u.test(error));

test('the register refuses a listed feature it leaves out and a feature the list does not have', needsParser, () => consumer({
  register: register(features => { delete features.team; features['setup-checklist'] = { status: 'absent', reason: 'No checklist.' }; }),
}, root => {
  assert.deepEqual(check(root), [
    `${registerName}: team is missing; declare it "uses", "absent" or "exception" (TeamFlow from @ten98/ui, shared since @ten98/ui 0.5.0).`,
    `${registerName}: setup-checklist is not a shared flow in @ten98/ui ${firstUi}; remove it.`,
  ]);
}));

test('"uses" needs the export rendered or called, outside tests', needsParser, () => {
  for (const sources of sourceSets(
    { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const Page = () => null;" },
    { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui/app';\nexport const Page = () => <TeamFlow />;" },
    { 'src/page.tsx': "import type { TeamFlow } from '@ten98/ui';\ntype Props = typeof TeamFlow;" },
    { 'src/page.tsx': "import { TeamFlow as Flow } from '@ten98/ui';\nexport const Page = () => <TeamFlow />;" },
    // A value, a member, `void` and a re-export alone are not a use.
    { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const routes = { team: TeamFlow, name: TeamFlow.displayName };\nvoid TeamFlow;" },
    { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui';\nexport { TeamFlow };\nexport { TeamFlow as Team } from '@ten98/ui';" },
    // A shadowing parameter or declaration is not the import.
    { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui';\nexport function f(TeamFlow: () => null) { return TeamFlow(); }\nexport const P = () => { const TeamFlow = () => null; return <TeamFlow />; };" },
    // Test and story files never satisfy it.
    { 'src/page.test.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const T = () => <TeamFlow />;", 'src/page.stories.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const S = () => <TeamFlow />;",
      'src/__tests__/team.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const U = () => <TeamFlow />;", 'src/page.spec.ts': "import * as Ui from '@ten98/ui';\nUi.TeamFlow({});" },
    // Nor do files under tests/ or __mocks__/, a test-utils file, or a story named in the singular.
    { 'src/tests/team.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const T = () => <TeamFlow />;", 'src/lib/tests/deep/team.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const D = () => <TeamFlow />;" },
    { 'src/__mocks__/ui.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const M = () => <TeamFlow />;" },
    { 'src/test-utils.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const R = () => <TeamFlow />;", 'src/lib/test-utils.jsx': "import { TeamFlow } from '@ten98/ui';\nexport const W = () => <TeamFlow />;" },
    { 'src/Page.story.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const S = () => <TeamFlow />;" },
    // A flow handed on under another or a computed key, to another call, as a later argument or as a shadowing parameter is not rendered.
    { 'src/routes.ts': "import { TeamFlow } from '@ten98/ui';\nexport const a = { components: TeamFlow, element: TeamFlow, [component]: TeamFlow };\nexport const b = memoize(TeamFlow);\nexport const c = memo(Other, TeamFlow);\nexport const d = utils.memo(TeamFlow);" },
    { 'src/routes.ts': "import { TeamFlow } from '@ten98/ui';\nexport function f(TeamFlow: unknown) { return { component: TeamFlow, view: memo(TeamFlow) }; }" },
  )) {
    consumer({ register: usesTeam, sources }, root => assert.deepEqual(check(root), [teamRefused], JSON.stringify(sources)));
  }
  for (const sources of sourceSets(
    { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const Page = () => <TeamFlow />;" },
    { 'src/page.tsx': "import { TeamFlow as Flow } from '@ten98/ui';\nexport const Page = () => <Flow members={[]} />;" },
    { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const Page = () => <TeamFlow.Section />;" },
    { 'src/page.tsx': "import * as Ui from '@ten98/ui';\nexport const Page = () => <Ui.TeamFlow />;" },
    { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui';\nexport function f(other: number) { return other; }\nexport const P = () => { if (on) { const x = 1; } return <TeamFlow />; };" },
    // A namespace destructured, and app barrels: `export *`, a named re-export, and an import exported again.
    { 'src/page.tsx': "import * as Ui from '@ten98/ui';\nconst { TeamFlow } = Ui;\nexport const Page = () => <TeamFlow />;" },
    { 'src/ui/index.ts': "export * from '@ten98/ui';", 'src/page.tsx': "import { TeamFlow } from './ui';\nexport const Page = () => <TeamFlow />;" },
    { 'src/ui.ts': "export { TeamFlow as Team } from '@ten98/ui';", 'src/pages/team.tsx': "import { Team } from '../ui.js';\nexport const Page = () => <Team />;" },
    { 'src/ui.ts': "import { TeamFlow } from '@ten98/ui';\nexport { TeamFlow };", 'src/kit.ts': "export * from './ui';", 'src/page.tsx': "import * as Kit from './kit';\nexport const Page = () => <Kit.TeamFlow />;" },
    // A specifier with a trailing slash names the folder's index.
    { 'src/ui/index.ts': "export * from '@ten98/ui';", 'src/page.tsx': "import { TeamFlow } from './ui/';\nexport const Page = () => <TeamFlow />;" },
    // A route config's component, memo and createElement render a flow as <TeamFlow /> does.
    { 'src/routes.ts': "import { TeamFlow } from '@ten98/ui';\nexport const route = createRoute({ path: '/team', component: TeamFlow });" },
    { 'src/routes.ts': "import { TeamFlow } from '@ten98/ui';\nexport const routes = [{ path: '/team', Component: TeamFlow }];" },
    { 'src/routes.ts': "import { TeamFlow } from '@ten98/ui';\nexport const route = { 'component': TeamFlow };" },
    { 'src/routes.ts': "import * as Ui from '@ten98/ui';\nexport const route = { component: Ui.TeamFlow };" },
    { 'src/page.ts': "import { memo } from 'react';\nimport { TeamFlow } from '@ten98/ui';\nexport const Page = memo(TeamFlow);" },
    { 'src/page.ts': "import React from 'react';\nimport { TeamFlow } from '@ten98/ui';\nexport const Page = React.memo(TeamFlow as never);" },
    { 'src/page.ts': "import { createElement } from 'react';\nimport { TeamFlow } from '@ten98/ui';\nexport const Page = () => createElement(TeamFlow, {});" },
    { 'src/page.ts': "import React from 'react';\nimport { TeamFlow } from '@ten98/ui';\nexport const Page = () => React.createElement(TeamFlow);" },
    // Names that only look like test files: a folder that merely ends in "tests", a prefixed helper, "story" without a dot before it.
    { 'src/contests/team.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const T = () => <TeamFlow />;" },
    { 'src/my-test-utils.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const T = () => <TeamFlow />;" },
    { 'src/story.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const T = () => <TeamFlow />;" },
  )) {
    consumer({ register: usesTeam, sources }, root => assert.deepEqual(teamOnly(check(root)), [], JSON.stringify(sources)));
  }
});

test('a barrel\'s own export of a name shadows its "export *", so only a genuine re-export of the flow is a use', needsParser, () => {
  const importer = { 'src/page.tsx': "import { TeamFlow } from './ui';\nexport const Page = () => <TeamFlow />;" };
  for (const barrel of sourceSets(
    // The two forms from the review: a declaration beside the star, and a re-export of the app's own component.
    { 'src/ui.tsx': "export * from '@ten98/ui';\nexport const TeamFlow = () => <div />;" },
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport { TeamFlow } from './mine';", 'src/mine.tsx': 'export const TeamFlow = () => null;' },
    // Any other way of exporting the name itself.
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport function TeamFlow() { return null; }" },
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport class TeamFlow {}" },
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport const { TeamFlow } = { TeamFlow: () => null };" },
    { 'src/ui.ts': "export * from '@ten98/ui';\nconst TeamFlow = () => null;\nexport { TeamFlow };" },
    { 'src/ui.ts': "export * from '@ten98/ui';\nconst Mine = () => null;\nexport { Mine as TeamFlow };" },
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport { Mine as TeamFlow } from './mine';", 'src/mine.ts': 'export const Mine = () => null;' },
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport * as TeamFlow from './mine';", 'src/mine.ts': 'export const x = 1;' },
    // The star may come before or after, and the shadow may sit at either barrel of a chain.
    { 'src/ui.ts': "export const TeamFlow = () => null;\nexport * from '@ten98/ui';" },
    { 'src/ui.ts': "export * from './kit';", 'src/kit.ts': "export * from '@ten98/ui';\nexport const TeamFlow = () => null;" },
    { 'src/ui.ts': "export * from './kit';\nexport const TeamFlow = () => null;", 'src/kit.ts': "export * from '@ten98/ui';" },
    // A re-export that leads back to the app's own component, however far.
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport { TeamFlow } from './again';", 'src/again.ts': "export { TeamFlow } from './mine';", 'src/mine.ts': 'export const TeamFlow = () => null;' },
  )) {
    consumer({ register: usesTeam, sources: { ...importer, ...barrel } }, root => assert.deepEqual(teamOnly(check(root)), [teamRefused], JSON.stringify(barrel)));
  }
  for (const barrel of sourceSets(
    // The star alone, and beside an export of another name.
    { 'src/ui.ts': "export * from '@ten98/ui';" },
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport const Other = () => null;" },
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport { Other } from './mine';", 'src/mine.ts': 'export const Other = 1;' },
    // The genuine flow named beside the star, directly or through another module, even beside a star of the app's own.
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport { TeamFlow } from '@ten98/ui';" },
    { 'src/ui.ts': "export * from '@ten98/ui';\nexport { TeamFlow } from './again';", 'src/again.ts': "export { TeamFlow } from '@ten98/ui';" },
    { 'src/ui.ts': "import { TeamFlow } from '@ten98/ui';\nexport * from './mine';\nexport { TeamFlow };", 'src/mine.ts': 'export const TeamFlow = () => null;' },
    { 'src/ui.ts': "export * from './kit';\nexport * from '@ten98/ui';", 'src/kit.ts': 'export const Mine = 1;' },
  )) {
    consumer({ register: usesTeam, sources: { ...importer, ...barrel } }, root => assert.deepEqual(teamOnly(check(root)), [], JSON.stringify(barrel)));
  }
});

test('a named re-export is followed only under the name it exports', needsParser, () => {
  const renamed = { 'src/ui.ts': "export { TeamFlow as Team, ApiKeysFlow as Keys } from '@ten98/ui';" };
  const both = register(features => { features.team = { status: 'uses' }; features['api-keys'] = { status: 'uses' }; });
  const apiKeysRefused = `${registerName}: api-keys is "uses", but no non-test file under src renders or calls ApiKeysFlow imported from @ten98/ui (shared since @ten98/ui 0.5.0).`;
  for (const [page, expected] of [
    ["import { Team, Keys } from './ui';\nexport const Page = () => <><Team /><Keys /></>;", []],
    ["import { Team as T } from './ui';\nimport { Keys as K } from './ui';\nexport const Page = () => <><T /><K /></>;", []],
    // Only the exported name is found: not the original one, another name, or the same name in another case.
    ["import { Keys } from './ui';\nexport const Page = () => <Keys />;", [teamRefused]],
    ["import { Team } from './ui';\nexport const Page = () => <Team />;", [apiKeysRefused]],
    ["import { TeamFlow, ApiKeysFlow } from './ui';\nexport const Page = () => <><TeamFlow /><ApiKeysFlow /></>;", [teamRefused, apiKeysRefused]],
    ["import { Other, team, keys } from './ui';\nexport const Page = () => <><Other /><team /><keys /></>;", [teamRefused, apiKeysRefused]],
  ] satisfies [string, string[]][]) {
    consumer({ register: both, sources: { ...renamed, 'src/page.tsx': page } }, root => assert.deepEqual(check(root).filter(error => !/ element \d+ exceeds/u.test(error)), expected, page));
  }
});

test('barrels that re-export each other end the search instead of looping', needsParser, () => {
  const importer = { 'src/page.tsx': "import { TeamFlow } from './a';\nexport const Page = () => <TeamFlow />;" };
  for (const [barrels, found] of [
    // Stars in a ring, with the package starred from one of them.
    [{ 'src/a.ts': "export * from './b';\nexport * from '@ten98/ui';", 'src/b.ts': "export * from './a';" }, true],
    [{ 'src/a.ts': "export * from './b';", 'src/b.ts': "export * from './c';", 'src/c.ts': "export * from './a';\nexport * from '@ten98/ui';" }, true],
    [{ 'src/a.ts': "export * from './a';\nexport * from '@ten98/ui';" }, true],
    // Named re-exports in a ring, and one of a module's own name, lead nowhere.
    [{ 'src/a.ts': "export { TeamFlow } from './b';", 'src/b.ts': "export { TeamFlow } from './a';" }, false],
    [{ 'src/a.ts': "export { TeamFlow } from './a';" }, false],
    [{ 'src/a.ts': "export * from './b';\nexport { TeamFlow } from './b';", 'src/b.ts': "export * from './a';" }, false],
  ] satisfies [Record<string, string>, boolean][]) {
    consumer({ register: usesTeam, sources: { ...importer, ...barrels } }, root => assert.deepEqual(teamOnly(check(root)), found ? [] : [teamRefused], JSON.stringify(barrels)));
  }
});

test('"export * as" is not followed as a use of the names it holds, though it counts as an import', needsParser, () => {
  const barrel = { 'src/ui.ts': "export * as Ui from '@ten98/ui';" };
  for (const page of [
    "import { TeamFlow } from './ui';\nexport const Page = () => <TeamFlow />;",
    "import { Ui } from './ui';\nexport const Page = () => <Ui.TeamFlow />;",
  ]) {
    consumer({ register: usesTeam, sources: { ...barrel, 'src/page.tsx': page } }, root => assert.deepEqual(teamOnly(check(root)), [teamRefused], page));
  }
  consumer({ sources: barrel }, root => assert.ok(check(root).includes(teamAbsentRefused)));
});

test('"uses" counts hooks and functions that are called', needsParser, () => {
  consumer({
    register: register(features => { features.confirm = { status: 'uses' }; features.export = { status: 'uses' }; features['leave-guard'] = { status: 'uses' }; }),
    sources: { 'src/hooks.ts': "import * as Ui from '@ten98/ui';\nimport { useConfirmDialog, saveFile as save } from '@ten98/ui';\nexport const useAsk = () => useConfirmDialog();\nexport const download = (blob: Blob) => save.call(null, blob);\nexport const useGuard = () => Ui.useLeaveGuard({});\n" },
  }, root => assert.deepEqual(check(root), []));
  consumer({
    register: register(features => { features.export = { status: 'uses' }; }),
    sources: { 'src/hooks.ts': "import { saveFile } from '@ten98/ui';\nexport const bound = saveFile.bind(null);\n" },
  }, root => assert.match(check(root).join('\n'), /export is "uses", but no non-test file under src renders or calls saveFile/));
});

test('"uses" needs every export of a feature', needsParser, () => consumer({
  ui: { list: list(features => { features.team.exports.push({ name: 'TeamInviteFlow', entry: '@ten98/ui', since: '0.40.0' }); }) },
  register: usesTeam, sources: { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const Page = () => <TeamFlow />;" },
}, root => {
  assert.deepEqual(check(root), [`${registerName}: team is "uses", but no non-test file under src renders or calls TeamInviteFlow imported from @ten98/ui (shared since @ten98/ui 0.40.0).`]);
}));

test('"absent" needs a reason and no import of the export, in any form the check sees', needsParser, () => {
  consumer({ register: register(features => { features.team = { status: 'absent' }; features.sessions = { status: 'absent', reason: '  ' }; }) }, root => {
    assert.deepEqual(check(root), [`${registerName}: sessions needs a reason of 1 to 500 characters.`, `${registerName}: team needs a reason of 1 to 500 characters.`]);
  });
  for (const sources of sourceSets(
    { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const unused = 1;" },
    { 'src/page.tsx': "import * as Ui from '@ten98/ui';\nexport const name = Ui.TeamFlow.name;" },
    { 'src/page.tsx': "import * as Ui from '@ten98/ui';\nconst { TeamFlow: Flow } = Ui;" },
    { 'src/ui/index.ts': "export * from '@ten98/ui';" },
    { 'src/ui/index.ts': "export * as Ui from '@ten98/ui';" },
    { 'src/ui/index.ts': "export { TeamFlow } from '@ten98/ui';" },
    { 'src/ui/index.ts': "export { TeamFlow as Team } from '@ten98/ui';", 'src/kit.ts': "export { Team as Flow } from './ui/index';" },
    { 'src/test/team.test.tsx': "import { TeamFlow } from '@ten98/ui';" },
  )) {
    consumer({ sources }, root => assert.ok(check(root).includes(teamAbsentRefused), JSON.stringify(sources)));
  }
  // Listed in the guide as not seen: dynamic import, require and a deep path. A type-only re-export imports nothing.
  consumer({ sources: { 'src/page.ts': "const ui = await import('@ten98/ui');\nconst kit = require('@ten98/ui');\nimport { TeamFlow } from '@ten98/ui/dist/index.js';",
    'src/types.ts': "export type { TeamFlow } from '@ten98/ui';\nexport { type TeamFlow as Team } from '@ten98/ui';" } }, root => {
    assert.deepEqual(check(root), []);
  });
});

test('"absent" also refuses a namespace import that is passed on whole or read by a computed key', needsParser, () => {
  const page = (use: string) => ({ 'src/page.tsx': `import * as Ui from '@ten98/ui';\n${use}\n` });
  for (const use of [
    'export const all = Ui;',
    'export default Ui;',
    'export { Ui };',
    'export { Ui as Kit };',
    'export const names = Object.keys(Ui);',
    'register(Ui);',
    'export const list = [Ui], map = { ui: Ui }, copy = { ...Ui };',
    'export const cast = Ui as never;',
    'export const view = <Provider ui={Ui} />;',
    'export const alone = <Ui />;',
    'export const flow = Ui[name];',
    "export const flow = Ui['Team' + 'Flow'];",
    'export const found = lookup[Ui];',
    'export const { ...rest } = Ui;',
    'export const { [name]: flow } = Ui;',
    'let flow;\n({ TeamFlow: flow } = Ui as never);',
  ]) consumer({ sources: page(use) }, root => assert.ok(check(root).includes(teamAbsentRefused), use));
  // A literal member or destructuring names the exports it reaches, so the rest of the package stays absent; a name
  // that is shadowed, a property of the same name, an attribute and a type are not the namespace.
  for (const use of [
    'export const name = Ui.ApiKeysFlow.name;',
    "export const name = Ui['ApiKeysFlow'], other = Ui?.ApiKeysFlow;",
    'export const { ApiKeysFlow, SessionListFlow: Sessions = null } = Ui;',
    'export const view = <Ui.ApiKeysFlow />;',
    'export const f = (Ui: number) => Ui;\nexport function g() { const Ui = 1; return Ui; }',
    'export const h = other.Ui + { Ui: 1 }.Ui;',
    'const value = 1;\nexport { value as Ui };',
    "export { Ui } from './kit';",
    "export * as Ui from './kit';",
    'export const view = <a Ui="x" />;',
    'type T = typeof Ui.ApiKeysFlow;\nexport const t: typeof Ui | null = null;\nexport const u = (x: unknown) => x as typeof Ui;',
    // Types in every other position: a return type, a type parameter, type arguments, a heritage clause.
    'export function f(): typeof Ui | null { return null; }',
    'export function g<T extends typeof Ui>(x: T) { return x; }',
    'export const m = new Map<string, typeof Ui>();\nexport const r = useRef<typeof Ui>(null);',
    'class B<T> {}\nexport class A extends B<typeof Ui> {}',
    'export class C implements Ui.Contract {}',
    'export enum E { Ui = 1 }',
  ]) consumer({ sources: page(use) }, root => assert.ok(!check(root).includes(teamAbsentRefused), use));
});

test('"exception" needs a reason and a bounded review trigger that has not come due', needsParser, () => {
  const exception = (entry: Record<string, unknown>) => register(features => { features.team = { status: 'exception', ...entry }; });
  const [major, minor] = firstUi.split('.').map(Number);
  const next = `${major}.${minor! + 1}.0`, furthest = `${major}.${minor! + 2}.9`, beyond = `${major}.${minor! + 3}.0`;
  const triggerMissing = `${registerName}: team needs a review trigger, { "ui": "<x.y.z>" } or { "issue": "https://github.com/Ten98-IO-Company/<repo>/issues/<n>" }.`;
  const due = (installed: string, trigger: string) => `${registerName}: team is due for review: @ten98/ui ${installed} has reached ${trigger}; move it to "uses" or record a new reason and trigger.`;
  // The rule exactly: the installed major release, at most two minor releases ahead, so a later major is out of range too.
  const unbounded = (trigger: string) => `${registerName}: team's review trigger ${trigger} is out of range for the installed @ten98/ui ${firstUi}: a trigger stays in the same major release and at most two minor releases ahead, up to ${major}.${minor! + 2}.z; choose a nearer review point.`;
  for (const [entry, expected] of [
    [{ reason: 'Waits for F3.', review: { ui: next } }, []],
    [{ reason: 'Waits for F3.', review: { ui: furthest } }, []],
    [{ reason: 'Waits for F3.', review: { issue: 'https://github.com/Ten98-IO-Company/ten98-design-system/issues/220' } }, []],
    [{ reason: 'x'.repeat(500), review: { ui: next } }, []],
    [{ review: { ui: next } }, [`${registerName}: team needs a reason of 1 to 500 characters.`]],
    [{ reason: 'x'.repeat(501), review: { ui: next } }, [`${registerName}: team needs a reason of 1 to 500 characters.`]],
    [{ reason: 'Waits for F3.' }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { ui: 'soon' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { ui: `${next}-rc.1` } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { issue: 'http://github.com/Ten98-IO-Company/ten98-design-system/issues/220' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { issue: 'https://example.com/1' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { issue: 'https://github.com/someone-else/repo/issues/1' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { issue: 'https://github.com/Ten98-IO-Company/ten98-design-system/issues/0' } }, [triggerMissing]],
    // A repository that is no repository: a path segment of dots, or nothing at all.
    [{ reason: 'Waits for F3.', review: { issue: 'https://github.com/Ten98-IO-Company/../issues/1' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { issue: 'https://github.com/Ten98-IO-Company/./issues/1' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { issue: 'https://github.com/Ten98-IO-Company/.../issues/1' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { issue: 'https://github.com/Ten98-IO-Company//issues/1' } }, [triggerMissing]],
    // Real repository names with dots in them, one of them starting with a dot.
    [{ reason: 'Waits for F3.', review: { issue: 'https://github.com/Ten98-IO-Company/.github/issues/7' } }, []],
    [{ reason: 'Waits for F3.', review: { issue: 'https://github.com/Ten98-IO-Company/a.b-c_d/issues/7' } }, []],
    [{ reason: 'Waits for F3.', review: { ui: next, issue: 'https://github.com/Ten98-IO-Company/ten98-design-system/issues/220' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { ui: firstUi } }, [due(firstUi, firstUi)]],
    [{ reason: 'Waits for F3.', review: { ui: beyond } }, [unbounded(beyond)]],
    [{ reason: 'Waits for F3.', review: { ui: `${major! + 1}.0.0` } }, [unbounded(`${major! + 1}.0.0`)]],
  ] satisfies [Record<string, unknown>, string[]][]) {
    consumer({ register: exception(entry) }, root => assert.deepEqual(check(root), expected, JSON.stringify(entry)));
  }
  // SemVer precedence: the patch part counts, a prerelease is below its release, and build metadata is ignored.
  for (const [installed, trigger, expected] of [
    [`${major}.${minor}.3`, `${major}.${minor}.2`, [due(`${major}.${minor}.3`, `${major}.${minor}.2`)]],
    [`${major}.${minor}.3`, `${major}.${minor}.4`, []],
    [`${major}.${minor! + 1}.3`, next, [due(`${major}.${minor! + 1}.3`, next)]],
    [`${major}.${minor! + 1}.0-rc.1`, next, []],
    [`${major}.${minor}.5+build.1`, next, []],
    [`${major}.${minor}.5+build.1`, `${major}.${minor}.5`, [due(`${major}.${minor}.5+build.1`, `${major}.${minor}.5`)]],
  ] satisfies [string, string, string[]][]) {
    consumer({ register: exception({ reason: 'Waits for F3.', review: { ui: trigger } }), ui: { version: installed } }, root => assert.deepEqual(check(root), expected, `${installed} ${trigger}`));
  }
  // An installed version that is not SemVer makes every ui trigger due.
  consumer({ register: exception({ reason: 'Waits for F3.', review: { ui: next } }), ui: { version: 'banana' } }, root => {
    assert.deepEqual(check(root), [`${registerName}: team counts as due for review: the installed @ten98/ui version banana is not a SemVer version, so its trigger cannot be compared.`]);
  });
});

test('the register refuses an unknown status', needsParser, () => consumer({ register: register(features => { features.team = { status: 'partial', reason: 'Half.' }; features.sessions = {}; }) }, root => {
  assert.deepEqual(check(root), [
    `${registerName}: sessions has unknown status (none); use "uses", "absent" or "exception".`,
    `${registerName}: team has unknown status "partial"; use "uses", "absent" or "exception".`,
  ]);
}));

test('a given leave-guard adapter must be a script file under the roots', needsParser, () => {
  for (const adapter of ['', 'src/missing.ts', 'scripts/leave-guard.ts', '../leave-guard.ts', 'src/styles.css', 42, null]) {
    consumer({ register: register(() => undefined, adapter), sources: { 'scripts/leave-guard.ts': adapterSource, 'src/styles.css': '' } }, root => {
      assert.match(check(root).join('\n'), new RegExp(`${registerName}: leaveGuardAdapter, when given, must name the app's leave-guard adapter, a script file under src\\.`), String(adapter));
    });
  }
  consumer({ register: register(() => undefined, './src/leave-guard.ts') }, root => assert.deepEqual(check(root), []));
});

test('the leave-guard adapter is optional, and without one every useBlocker import counts', needsParser, () => consumer({
  register: register(() => undefined, undefined), sources: { 'src/page.tsx': adapterSource },
}, root => {
  assert.equal(JSON.parse(readFileSync(join(root, registerName), 'utf8')).leaveGuardAdapter, undefined);
  assert.deepEqual(check(root).sort(), [`src/leave-guard.ts: router-blocker 1 exceeds baseline 0 ${owned}`, `src/page.tsx: router-blocker 1 exceeds baseline 0 ${owned}`]);
}));

test('the register itself must exist, parse and declare features', needsParser, () => {
  consumer({ register: null }, root => {
    // Without a register there is no adapter, so its useBlocker import is counted as well.
    assert.deepEqual(check(root), [`${registerName} is missing; record it once with check.mjs --record-shared-flows, then write each reason.`,
      `src/leave-guard.ts: router-blocker 1 exceeds baseline 0 ${owned}`]);
  });
  for (const [text, expected] of [
    ['{ "features": ', /shared-flows\.json cannot be parsed/],
    ['{ "team": { "status": "uses" } }', /shared-flows\.json must hold/],
    ['{ "features": {} }', /shared-flows\.json declares no features\./],
  ] satisfies [string, RegExp][]) {
    consumer({ register: text }, root => assert.match(check(root).join('\n'), expected));
  }
});

test('the installed list fails closed when missing, unparseable, of another schema, empty or with an entry without exports', needsParser, () => {
  const broken = (change: (parsed: Record<string, any>) => void): string => { const parsed = JSON.parse(uiList); change(parsed); return JSON.stringify(parsed); };
  for (const [ui, expected] of [
    [{ version: '0.39.2', list: null }, `The installed @ten98/ui ships no shared-flows.json; the shared-flow register needs @ten98/ui ${firstUi} or later.`],
    [{ list: '{ "schemaVersion": 1, ' }, `@ten98/ui ${firstUi} shared-flows.json cannot be parsed`],
    [{ list: broken(parsed => { parsed.schemaVersion = 2; }) }, `@ten98/ui ${firstUi} shared-flows.json has schemaVersion 2; this checker reads schemaVersion 1.`],
    [{ list: broken(parsed => { delete parsed.features; }) }, `@ten98/ui ${firstUi} shared-flows.json has no features map.`],
    [{ list: broken(parsed => { parsed.features = {}; }) }, `@ten98/ui ${firstUi} shared-flows.json lists no features.`],
    [{ list: broken(parsed => { parsed.features.team.exports = []; }) }, `@ten98/ui ${firstUi} shared-flows.json: feature team has no exports with a name and an entry.`],
    [{ list: broken(parsed => { delete parsed.features.team.exports; }) }, `@ten98/ui ${firstUi} shared-flows.json: feature team has no exports with a name and an entry.`],
    [{ list: broken(parsed => { parsed.features.team.exports = [{ name: 'TeamFlow' }]; }) }, `@ten98/ui ${firstUi} shared-flows.json: feature team has no exports with a name and an entry.`],
  ] satisfies [Setup['ui'], string][]) {
    consumer({ ui }, root => {
      const errors = check(root);
      assert.ok(errors.some(error => error.startsWith(expected)), `${expected}\n${errors.join('\n')}`);
    });
  }
  // No @ten98/ui installed at all.
  consumer({}, root => {
    rmSync(join(root, 'node_modules'), { recursive: true });
    assert.match(check(root).join('\n'), new RegExp(`needs @ten98/ui ${firstUi.replaceAll('.', '\\.')} or later`));
  });
});

test('record writes the first register once, marking uses and leaving empty exceptions to be written', needsParser, () => consumer({
  register: null,
  sources: { 'src/team.tsx': "import { TeamFlow, ApiKeysFlow } from '@ten98/ui';\nexport const Team = () => <TeamFlow />;\n" },
}, root => {
  const errors = recordSharedFlows(root, profile, { parseAst });
  const written = JSON.parse(readFileSync(join(root, registerName), 'utf8'));
  // The adapter is left out, so no file is exempt until someone names it.
  assert.deepEqual(Object.keys(written), ['features']);
  assert.deepEqual(Object.keys(written.features), Object.keys(listed));
  assert.deepEqual(written.features.team, { status: 'uses' });
  assert.deepEqual(written.features['api-keys'], { status: 'exception', reason: '' });
  assert.deepEqual(written.features.sessions, { status: 'exception', reason: '' });
  // Every exception fails until its reason and trigger are written.
  assert.doesNotMatch(errors.join('\n'), /leaveGuardAdapter/);
  assert.match(errors.join('\n'), /src\/leave-guard\.ts: router-blocker 1 exceeds baseline 0/);
  assert.match(errors.join('\n'), /api-keys needs a reason of 1 to 500 characters\./);
  assert.match(errors.join('\n'), /sessions needs a review trigger/);
  assert.doesNotMatch(errors.join('\n'), /: team /);
  assert.deepEqual(recordSharedFlows(root, profile, { parseAst }), [`${registerName} already exists; edit it instead of recording it again.`]);
  assert.deepEqual(JSON.parse(readFileSync(join(root, registerName), 'utf8')), written);
}));

test('record marks "uses" only when every export of a feature is used', needsParser, () => consumer({
  register: null, ui: { list: list(features => { features.team.exports.push({ name: 'TeamInviteFlow', entry: '@ten98/ui', since: '0.40.0' }); }) },
  sources: { 'src/team.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const Team = () => <TeamFlow />;\n" },
}, root => {
  recordSharedFlows(root, profile, { parseAst });
  assert.deepEqual(JSON.parse(readFileSync(join(root, registerName), 'utf8')).features.team, { status: 'exception', reason: '' });
}));

test('record refuses without the installed list and writes nothing', needsParser, () => consumer({ register: null, ui: { list: null } }, root => {
  assert.match(recordSharedFlows(root, profile, { parseAst }).join('\n'), /ships no shared-flows\.json/);
  assert.equal(existsSync(join(root, registerName)), false);
}));

test('check.mjs prints the remaining ratchet counts on every run, even when an earlier check fails', needsParser, () => {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-presentation-cli-'));
  try {
    const checker = join(directory, 'checker');
    mkdirSync(checker);
    for (const name of ['check.mjs', 'database-policy.mjs']) writeFileSync(join(checker, name), readFileSync(new URL(`../${name}`, import.meta.url)));
    const contract = JSON.parse(readFileSync(new URL('../architecture.json', import.meta.url), 'utf8'));
    // A minimal non-app profile with the app stack's presentation policy, so the fixture needs no installed compiler.
    contract.profiles['fixture-presentation'] = { dependencies: {}, devDependencies: {}, sharedDependencies: [], sharedDevDependencies: [], peerDependencies: {}, checkScripts: ['test'],
      presentation: contract.appStack.presentation, database: { engine: 'postgresql' } };
    writeFileSync(join(checker, 'architecture.json'), JSON.stringify(contract));
    consumer({ register: null, sources: { 'src/a.tsx': "window.confirm('a');\n" } }, root => {
      const manifest = { name: 'fixture-presentation', type: 'module', packageManager: 'pnpm@11.19.0', engines: { node: '>=24.22.1 <25' },
        scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'pnpm check:architecture && node --test' } };
      writeFileSync(join(root, 'package.json'), JSON.stringify(manifest));
      const rolldown = join(root, 'node_modules', 'rolldown');
      mkdirSync(rolldown);
      writeFileSync(join(rolldown, 'package.json'), '{"name":"rolldown","exports":{"./parseAst":"./parse-ast.cjs"}}');
      writeFileSync(join(rolldown, 'parse-ast.cjs'), `module.exports = require(${JSON.stringify(parserPath)});`);
      const cli = (...args: string[]) => spawnSync(process.execPath, [join(checker, 'check.mjs'), ...args, root], { encoding: 'utf8', timeout: 20_000, windowsHide: true });
      const remaining = /presentation counts remaining: native-dialog 1, router-blocker 0, t98-selector 0, t98-class 0, t98-dom 0\./;
      const recorded = cli('--record-shared-flows');
      assert.equal(recorded.status, 1);
      // The recorded register names no adapter, so the adapter's useBlocker import is counted until it is named.
      assert.match(recorded.stdout, /presentation counts remaining: native-dialog 1, router-blocker 1, t98-selector 0, t98-class 0, t98-dom 0\./);
      assert.match(recorded.stderr, /src\/leave-guard\.ts: router-blocker 1 exceeds baseline 0/);
      assert.match(recorded.stderr, /needs a reason of 1 to 500 characters/);
      // Recording again is refused before the scan, and the totals are still printed.
      const again = cli('--record-shared-flows');
      assert.match(again.stderr, /already exists/);
      assert.match(again.stdout, /presentation counts remaining: native-dialog 1, router-blocker 1/);
      writeFileSync(join(root, registerName), JSON.stringify(absentRegister()));
      const failing = cli();
      assert.equal(failing.status, 1);
      assert.match(failing.stdout, remaining);
      assert.match(failing.stderr, /src\/a\.tsx: native-dialog 1 exceeds baseline 0/);
      assert.equal(cli('--update-presentation-baseline').status, 0);
      const passing = cli();
      assert.equal(passing.status, 0, passing.stderr);
      assert.match(passing.stdout, remaining);
      // A failing manifest check stops the run before presentation, and the totals are printed all the same.
      writeFileSync(join(root, 'package.json'), JSON.stringify({ ...manifest, engines: { node: '>=20' } }));
      const manifestFails = cli();
      assert.equal(manifestFails.status, 1);
      assert.match(manifestFails.stderr, /engines\.node: expected/);
      assert.match(manifestFails.stdout, remaining);
      // Without the parser the totals are unavailable, and the run says why.
      rmSync(rolldown, { recursive: true });
      assert.match(cli().stdout, /presentation counts unavailable: Cannot resolve rolldown\/parseAst/);
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

// The sharedFlows declaration in architecture.json. The checker reads the declaration beside itself, so each case
// imports its own copy of the checker next to a changed declaration.
type Checker = typeof import('../check.mjs');
type Presentation = Record<string, any>;
const pristine = readFileSync(new URL('../architecture.json', import.meta.url), 'utf8');
const unparseable = '{ "features": ';

// The change gets appStack's presentation policy, the case's own folder and the whole contract, for a case that reaches beyond the policy.
async function declaring(change: (presentation: Presentation, folder: string, contract: Presentation) => void, run: (checker: Checker, folder: string) => void): Promise<void> {
  const folder = mkdtempSync(join(tmpdir(), 'ten98-declaration-'));
  try {
    for (const name of ['check.mjs', 'database-policy.mjs']) copyFileSync(new URL(`../${name}`, import.meta.url), join(folder, name));
    const contract = JSON.parse(pristine);
    change(contract.appStack.presentation, folder, contract);
    writeFileSync(join(folder, 'architecture.json'), JSON.stringify(contract));
    run(await import(pathToFileURL(join(folder, 'check.mjs')).href) as Checker, folder);
  } finally { rmSync(folder, { recursive: true, force: true }); }
}

const declaredPath = 'appStack.presentation.sharedFlows';
const shapeError = `${declaredPath} needs an object with exactly the keys register and firstUiVersion.`;
const registerError = `${declaredPath}.register needs a relative path to a .json file, without ".." or an absolute path.`;
const versionError = `${declaredPath}.firstUiVersion needs a plain x.y.z version, without a prerelease or build suffix.`;

// Each bad declaration, the change that makes it, and the one error it is reported as. The two rows that reach into the
// case's own folder leave an unparseable register there, so a read of it would be reported as unparseable.
const badDeclarations: [string, (presentation: Presentation, folder: string, contract: Presentation) => void, string][] = [];
const refuse = (what: string, expected: string, change: (presentation: Presentation, folder: string, contract: Presentation) => void): void => { badDeclarations.push([what, change, expected]); };
const setRegister = (value: unknown) => (presentation: Presentation): void => { presentation.sharedFlows.register = value; };
const setVersion = (value: unknown) => (presentation: Presentation): void => { presentation.sharedFlows.firstUiVersion = value; };

// Not an object. The falsy values were once read as "no register declared".
for (const value of ['shared-flows.json', null, 5, true, false, 0, '', [], [firstUi, 'shared-flows.json']]) refuse(`sharedFlows ${JSON.stringify(value)}`, shapeError, presentation => { presentation.sharedFlows = value; });
// Not exactly the two keys.
refuse('register missing', shapeError, presentation => { delete presentation.sharedFlows.register; });
refuse('firstUiVersion missing', shapeError, presentation => { delete presentation.sharedFlows.firstUiVersion; });
refuse('an unknown extra key', shapeError, presentation => { presentation.sharedFlows.extra = 'x'; });
refuse('register under another key', registerError, presentation => { presentation.sharedFlows = { regster: 'shared-flows.json', firstUiVersion: firstUi }; });
refuse('firstUiVersion under another key', versionError, presentation => { presentation.sharedFlows = { register: 'shared-flows.json', firstVersion: firstUi }; });
// register is not a string. An array of one path reads as that path to a pattern test, so it has its own case.
for (const value of [5, null, true, ['shared-flows.json'], { path: 'shared-flows.json' }]) refuse(`register ${JSON.stringify(value)}`, registerError, setRegister(value));
// register is absolute, in the POSIX, Windows and UNC forms, and as this machine writes it.
for (const value of ['/shared-flows.json', '\\shared-flows.json', '\\\\server\\share\\shared-flows.json', 'C:\\apps\\shared-flows.json', 'C:/shared-flows.json', 'c:shared-flows.json']) refuse(`register ${value}`, registerError, setRegister(value));
refuse('register as an absolute path on this machine', registerError, (presentation, folder) => {
  writeFileSync(join(folder, 'register.json'), unparseable);
  presentation.sharedFlows.register = join(folder, 'register.json');
});
// register has a ".." segment, however it is separated, and leaves the app.
for (const value of ['src/../shared-flows.json', '..\\shared-flows.json', 'src\\..\\shared-flows.json', 'a/b/../../shared-flows.json']) refuse(`register ${value}`, registerError, setRegister(value));
refuse('register leaving the app by ..', registerError, (presentation, folder) => {
  writeFileSync(join(folder, 'register.json'), unparseable);
  presentation.sharedFlows.register = `../${basename(folder)}/register.json`;
});
// register is not a path to a .json file.
for (const value of ['shared-flows', 'shared-flows.yaml', 'shared-flows.json.bak', '', '.json', 'src/.json', 'shared-flows.json/']) refuse(`register ${JSON.stringify(value)}`, registerError, setRegister(value));
// register is a file another check reads or writes: a baseline, the manifest, the contract or a compiler project, in any
// spelling of the same path (a "./" or doubled separators, either separator, another case).
const collisionError = (value: string) => `${declaredPath}.register ${JSON.stringify(value)} is a file the checks read or write (a baseline, package.json, architecture.json or a compiler project); choose another path.`;
for (const value of [
  'presentation-baseline.json', 'raw-statements.json', 'package.json', 'architecture.json', 'tsconfig.json', 'tsconfig.backend.json', 'tests/tsconfig.api.json', 'tests/tsconfig.tests.json', 'tsconfig.tooling.json',
  './presentation-baseline.json', '.\\raw-statements.json', './/package.json', 'tests//tsconfig.api.json', 'tests\\tsconfig.tests.json', 'Presentation-Baseline.json', 'PACKAGE.json',
]) refuse(`register ${JSON.stringify(value)}`, collisionError(value), setRegister(value));
// ... also one that only another profile's policy names.
refuse('register named as another profile\'s baseline', collisionError('other-baseline.json'), (presentation, _folder, contract) => {
  contract.profiles['other-app'] = { stack: 'app', data: { roots: ['src'], baseline: 'other-baseline.json' } };
  presentation.sharedFlows.register = 'other-baseline.json';
});
// firstUiVersion is not a string, or not a SemVer version. An array of one version reads as that version to a pattern test.
for (const value of ['banana', '0.40', '0.40.0.1', 'v0.40.0', '00.40.0', '', ' 0.40.0', 40, null, ['0.40.0']]) refuse(`firstUiVersion ${JSON.stringify(value)}`, versionError, setVersion(value));
// firstUiVersion is a SemVer version with more than x.y.z: a prerelease or a build part.
for (const value of ['0.40.0-rc.1', '0.40.0-0', '0.40.0+build.5']) refuse(`firstUiVersion ${value}`, versionError, setVersion(value));

test('the sharedFlows declaration must be exactly a relative .json register and a plain x.y.z version', async () => {
  for (const [what, change, expected] of badDeclarations) await declaring(change, checker => assert.deepEqual(checker.inspectWaivers(), [expected], what));
});

test('the real architecture.json declares its sharedFlows in the shape the checker accepts', () => {
  assert.deepEqual(Object.keys(JSON.parse(pristine).appStack.presentation.sharedFlows).sort(), ['firstUiVersion', 'register']);
  assert.deepEqual(inspectWaivers(), []);
});

test('a sharedFlows declaration refuses only a ".." segment, an absolute path, a file another check uses and a version that is not x.y.z', async () => {
  // A file of the same name in another folder, or a similar name, is another file.
  for (const register of ['shared-flows.json', './shared-flows.json', 'config/flows.json', 'a..b/c.json', '..hidden.json', 'dir/..hidden.json', 'spaced name/flows.json',
    'config/package.json', 'src/presentation-baseline.json', 'raw-statements-2.json', 'tsconfig.app.json', 'package-lock.json']) {
    await declaring(setRegister(register), checker => assert.deepEqual(checker.inspectWaivers(), [], register));
  }
  for (const version of ['0.0.0', '10.20.30', '0.40.100']) await declaring(setVersion(version), checker => assert.deepEqual(checker.inspectWaivers(), [], version));
});

const listing = (...folders: string[]): string[] => folders.flatMap(folder => readdirSync(folder, { recursive: true, encoding: 'utf8' }).map(name => join(folder, name))).sort();

test('a bad sharedFlows declaration is reported, not thrown, and no register is read or written', needsParser, async () => {
  for (const [what, change, expected] of badDeclarations) {
    await declaring(change, (checker, folder) => consumer({ register: unparseable }, root => {
      const options = { parseAst };
      // Without a declared register no file is exempt from router-blocker, as when the register is missing.
      assert.deepEqual(checker.checkPresentation(root, profile, options), [expected, `src/leave-guard.ts: router-blocker 1 exceeds baseline 0 ${owned}`], what);
      assert.deepEqual(checker.updatePresentationBaseline(root, profile, options), [expected], what);
      assert.equal(existsSync(join(root, baselineName)), false, what);
      const report = checker.presentationTotals(root, profile, options);
      assert.ok(report && 'totals' in report && report.totals['router-blocker'] === 1, what);
      // The register is gone, so a recording that ignored the declaration would write one.
      rmSync(join(root, registerName));
      const before = listing(root, folder);
      assert.deepEqual(checker.recordSharedFlows(root, profile, options), [expected], what);
      assert.deepEqual(listing(root, folder), before, what);
    }));
  }
});

test('check.mjs reports a bad sharedFlows declaration instead of throwing, and still prints the remaining counts', needsParser, async () => {
  await declaring(presentation => { delete presentation.sharedFlows.register; }, (_checker, folder) => consumer({ sources: { 'src/a.tsx': "window.confirm('a');\n" } }, root => {
    // The manifest only names the profile: its other errors are printed too and stop the run before presentation, and
    // the totals are then counted on their own, which is where an unchecked declaration used to throw.
    writeFileSync(join(root, 'package.json'), JSON.stringify({ name: profile }));
    const rolldown = join(root, 'node_modules', 'rolldown');
    mkdirSync(rolldown);
    writeFileSync(join(rolldown, 'package.json'), '{"name":"rolldown","exports":{"./parseAst":"./parse-ast.cjs"}}');
    writeFileSync(join(rolldown, 'parse-ast.cjs'), `module.exports = require(${JSON.stringify(parserPath)});`);
    const result = spawnSync(process.execPath, [join(folder, 'check.mjs'), root], { encoding: 'utf8', timeout: 20_000, windowsHide: true });
    assert.equal(result.status, 1);
    assert.ok(result.stderr.includes(`${root}: ${shapeError}`), result.stderr);
    assert.doesNotMatch(`${result.stdout}${result.stderr}`, /ERR_INVALID_ARG|must be of type string|unavailable/);
    assert.match(result.stdout, /presentation counts remaining: native-dialog 1, router-blocker 1, t98-selector 0, t98-class 0, t98-dom 0\./);
  }));
});

// A register path that passes the declaration's lexical check can still lead out of the app through a link. A junction
// is made without special rights on Windows, and is a symlink elsewhere; a directory symlink on Windows needs the right
// to make one, so a test that cannot make its link is skipped with the reason.
const linkKinds = process.platform === 'win32' ? ['junction', 'dir'] as const : ['dir'] as const;
const unplaced = (declared: string) => `${declared} must be a file inside the app: a link leads it outside the app, or its folder is missing.`;
const unlinked = `src/leave-guard.ts: router-blocker 1 exceeds baseline 0 ${owned}`;

function linked(t: TestContext, target: string, path: string, kind: 'junction' | 'dir'): boolean {
  try { symlinkSync(target, path, kind); return true; }
  catch (error) { t.skip(`cannot make a ${kind} link here: ${(error as NodeJS.ErrnoException).code}`); return false; }
}

// A consumer whose `link` folder is a link to a folder inside or outside its root, under a declaration naming `link/new.json`.
async function withLink(t: TestContext, kind: 'junction' | 'dir', where: 'inside' | 'outside', run: (checker: Checker, root: string, target: string) => void): Promise<void> {
  await declaring(presentation => { presentation.sharedFlows.register = 'link/new.json'; }, checker => consumer({ register: null }, root => {
    const target = where === 'outside' ? mkdtempSync(join(tmpdir(), 'ten98-outside-')) : join(root, 'inner');
    try {
      mkdirSync(target, { recursive: true });
      if (linked(t, target, join(root, 'link'), kind)) run(checker, root, target);
    } finally { if (where === 'outside') rmSync(target, { recursive: true, force: true }); }
  }));
}

for (const kind of linkKinds) {
  const noun = kind === 'junction' ? 'a junction' : 'a symbolic link';
  test(`a register reached through ${noun} that leads out of the app is neither read nor written`, needsParser, t => withLink(t, kind, 'outside', (checker, root, outside) => {
    const options = { parseAst }, message = unplaced('link/new.json');
    // A register already there is not read through the link, so its adapter is not exempt either.
    writeFileSync(join(outside, 'new.json'), JSON.stringify(absentRegister()));
    assert.deepEqual(checker.checkPresentation(root, profile, options), [message, unlinked]);
    // Recording creates none there, and says why.
    rmSync(join(outside, 'new.json'));
    assert.deepEqual(checker.recordSharedFlows(root, profile, options), [message]);
    assert.deepEqual(readdirSync(outside), []);
  }));

  test(`a register reached through ${noun} that stays inside the app is written and read as usual`, needsParser, t => withLink(t, kind, 'inside', (checker, root, inside) => {
    const options = { parseAst };
    assert.doesNotMatch(checker.recordSharedFlows(root, profile, options).join('\n'), /must be a file inside the app/);
    assert.ok(existsSync(join(inside, 'new.json')));
    assert.doesNotMatch(checker.checkPresentation(root, profile, options).join('\n'), /must be a file inside the app|is missing/);
    assert.deepEqual(checker.recordSharedFlows(root, profile, options), ['link/new.json already exists; edit it instead of recording it again.']);
  }));
}

test('a register whose folder is missing is refused, not written', needsParser, () => declaring(presentation => { presentation.sharedFlows.register = 'missing/new.json'; }, checker => consumer({ register: null }, root => {
  const message = unplaced('missing/new.json');
  assert.deepEqual(checker.recordSharedFlows(root, profile, { parseAst }), [message]);
  assert.deepEqual(checker.checkPresentation(root, profile, { parseAst }), [message, unlinked]);
  assert.equal(existsSync(join(root, 'missing')), false);
})));

// The register itself is the link. A junction can only point at a folder, so the target is a folder named like a file.
for (const target of ['a folder outside the app', 'nothing', 'the app\'s own folder']) {
  test(`a register that is a link to ${target} is refused, not read or written through`, needsParser, t => consumer({ register: null }, root => {
    const outside = mkdtempSync(join(tmpdir(), 'ten98-outside-'));
    try {
      const place = target === 'the app\'s own folder' ? root : join(outside, 'target.json');
      if (target === 'a folder outside the app') mkdirSync(place);
      if (!linked(t, place, join(root, registerName), 'junction')) return;
      assert.deepEqual(checkPresentation(root, profile, { parseAst }), [unplaced(registerName), unlinked]);
      assert.deepEqual(recordSharedFlows(root, profile, { parseAst }), [unplaced(registerName)]);
      assert.deepEqual(readdirSync(outside), target === 'a folder outside the app' ? ['target.json'] : []);
      if (target === 'a folder outside the app') assert.deepEqual(readdirSync(place), []);
    } finally { rmSync(outside, { recursive: true, force: true }); }
  }));
}

for (const kind of linkKinds) {
  test(`an app folder that is itself reached through ${kind === 'junction' ? 'a junction' : 'a symbolic link'} keeps its register`, needsParser, t => consumer({ register: null }, root => {
    const alias = `${root}-alias`;
    if (!linked(t, root, alias, kind)) return;
    try {
      assert.doesNotMatch(recordSharedFlows(alias, profile, { parseAst }).join('\n'), /must be a file inside the app/);
      assert.ok(existsSync(join(root, registerName)));
      assert.doesNotMatch(checkPresentation(alias, profile, { parseAst }).join('\n'), /must be a file inside the app|is missing/);
    } finally { rmSync(alias); }
  }));
}

test('a register whose name starts with two dots is inside the app', needsParser, () => declaring(presentation => { presentation.sharedFlows.register = '..flows.json'; }, checker => consumer({ register: null }, root => {
  assert.doesNotMatch(checker.recordSharedFlows(root, profile, { parseAst }).join('\n'), /must be a file inside the app/);
  assert.ok(existsSync(join(root, '..flows.json')));
})));
