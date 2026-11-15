import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { checkPresentation, recordSharedFlows, updatePresentationBaseline } from '../check.mjs';

const fixtures = new URL('./fixtures/presentation/', import.meta.url);
const profile = 'ten98-campaign';
const baselineName = 'presentation-baseline.json';
const registerName = 'shared-flows.json';
// The design system's list, copied unchanged from ten98-design-system PR #226 at 827f269; it ships in @ten98/ui 0.40.0.
const uiList = readFileSync(new URL('./fixtures/shared-flows/ui-list.json', import.meta.url), 'utf8');
const listed: Record<string, { exports: { name: string; entry: string }[] }> = JSON.parse(uiList).features;
const firstUi: string = JSON.parse(readFileSync(new URL('../architecture.json', import.meta.url), 'utf8')).appStack.presentation.sharedFlows.firstUiVersion;
const adapterSource = "import { useBlocker } from '@tanstack/react-router';\nexport const useAppBlocker = useBlocker;\n";
const ratchetRules = ['native-dialog', 'router-blocker', 't98-selector', 't98-class', 't98-dom'];

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
  baseline?: Baseline;
  // undefined writes every listed feature as absent; null writes no register.
  register?: Register | null;
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
    if (baseline) writeFileSync(join(root, baselineName), JSON.stringify(baseline));
    if (register !== null) writeFileSync(join(root, registerName), JSON.stringify(register ?? absentRegister()));
    const uiFolder = join(root, 'node_modules', '@ten98', 'ui');
    mkdirSync(uiFolder, { recursive: true });
    const exports = ui.list === null ? { '.': './index.js' } : { '.': './index.js', './shared-flows.json': './shared-flows.json' };
    writeFileSync(join(uiFolder, 'package.json'), JSON.stringify({ name: '@ten98/ui', version: ui.version ?? firstUi, exports }));
    if (ui.list !== null) writeFileSync(join(uiFolder, 'shared-flows.json'), ui.list ?? uiList);
    run(root);
  } finally { rmSync(root, { recursive: true, force: true }); }
}

const check = (root: string) => checkPresentation(root, profile, { parseAst });
// A register with every feature absent, then changed; a further argument replaces the adapter, and undefined removes it.
const register = (change: (features: Record<string, unknown>) => void, ...adapter: unknown[]): Register => {
  const { features, leaveGuardAdapter } = absentRegister();
  change(features);
  if (!adapter.length) return { leaveGuardAdapter, features };
  return adapter[0] === undefined ? { features } : { leaveGuardAdapter: adapter[0], features };
};
// The ratchet totals one run reports, and its errors.
function run(root: string): { totals: Record<string, number>; errors: string[] } {
  let totals: Record<string, number> = {};
  const errors = checkPresentation(root, profile, { parseAst, onTotals: reported => { totals = reported; } });
  return { totals, errors };
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
    assert.deepEqual(check(root), [`src/${file}: ${rule} 1 exceeds baseline 0 (presentation is owned by @ten98/ui).`]);
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
    assert.deepEqual(updatePresentationBaseline(root, profile, { parseAst }), []);
    assert.deepEqual(stored(root), { $rules: allRules, 'src/element.tsx': { element: 1 } });
  });
  consumer({ files: ['element-twice.tsx'], baseline: { $rules: allRules, 'src/element-twice.tsx': { element: 1 } } }, root => {
    assert.match(updatePresentationBaseline(root, profile, { parseAst }).join('\n'), /element 2 exceeds baseline 1/);
    assert.deepEqual(stored(root), { $rules: allRules, 'src/element-twice.tsx': { element: 1 } });
  });
});

test('update mode records a missing baseline once from current counts', needsParser, () => consumer({ files: ['element-twice.tsx', 'pass.tsx'] }, root => {
  assert.deepEqual(updatePresentationBaseline(root, profile, { parseAst }), []);
  assert.deepEqual(stored(root), { $rules: allRules, 'src/element-twice.tsx': { element: 2 } });
  assert.deepEqual(check(root), []);
}));

test('update mode records the ratchet rules once on a baseline from before them, then only lowers them', needsParser, () => consumer({
  sources: { 'src/ask.tsx': "export const ask = () => window.confirm('Leave?') && window.alert('Bye');\n" },
  baseline: { 'src/ask.tsx': { element: 0 } },
}, root => {
  // The old baseline allows no native dialogs, so the check refuses until the new rules are recorded.
  assert.match(check(root).join('\n'), /src\/ask\.tsx: native-dialog 2 exceeds baseline 0/);
  assert.deepEqual(updatePresentationBaseline(root, profile, { parseAst }), []);
  assert.deepEqual(stored(root), { $rules: allRules, 'src/ask.tsx': { 'native-dialog': 2 } });
  assert.deepEqual(check(root), []);
  // Recorded once: a rise is now refused, and a fall is recorded.
  writeFileSync(join(root, 'src/ask.tsx'), "export const ask = () => window.confirm('a') && window.alert('b') && window.prompt('c');\n");
  assert.match(updatePresentationBaseline(root, profile, { parseAst }).join('\n'), /native-dialog 3 exceeds baseline 2/);
  writeFileSync(join(root, 'src/ask.tsx'), "export const ask = () => window.confirm('a');\n");
  assert.deepEqual(updatePresentationBaseline(root, profile, { parseAst }), []);
  assert.deepEqual(stored(root), { $rules: allRules, 'src/ask.tsx': { 'native-dialog': 1 } });
}));

test('update mode refuses while the register has errors', needsParser, () => consumer({ files: ['element.tsx'], register: register(() => undefined, '') }, root => {
  assert.match(updatePresentationBaseline(root, profile, { parseAst }).join('\n'), /leaveGuardAdapter must name/);
  assert.equal(existsSync(join(root, baselineName)), false);
}));

test('namespaced JSX tags are raw elements', needsParser, () => consumer({ files: ['namespaced.tsx'] }, root => {
  assert.deepEqual(check(root), ['src/namespaced.tsx: element 1 exceeds baseline 0 (presentation is owned by @ten98/ui).']);
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
}));

// Ratchet rules. Each case is a source and how many the rule counts in it.
const ruleCases: [string, string, string, number][] = [
  ['native-dialog', 'src/a.tsx', "window.confirm('a');", 1],
  ['native-dialog', 'src/a.tsx', "globalThis.alert('a'); self.prompt('a');", 2],
  ['native-dialog', 'src/a.tsx', "window.confirm?.('a'); window?.alert('a');", 2],
  ['native-dialog', 'src/a.tsx', "window['confirm']('a'); window[`prompt`]('a');", 2],
  ['native-dialog', 'src/a.ts', "window.confirm!('a'); (window.alert)('a');", 2],
  ['native-dialog', 'src/a.tsx', "confirm('a'); alert('b'); prompt('c');", 3],
  ['native-dialog', 'src/a.js', 'self.prompt`name`;', 1],
  // A comment or a string mentioning a dialog, a locally declared name, another object, a computed key, a variable.
  ['native-dialog', 'src/a.tsx', "// window.confirm('a')\n/* alert('b') */ const text = \"window.confirm('a')\";", 0],
  ['native-dialog', 'src/a.tsx', "function confirm(text: string) { return text; }\nconfirm('a');", 0],
  ['native-dialog', 'src/a.tsx', "import { alert } from './toast';\nconst { prompt } = api;\nalert('a'); prompt('b');", 0],
  ['native-dialog', 'src/a.tsx', "dialog.confirm('a'); window[name]('a'); const ask = window.confirm; ask('a');", 0],
  ['router-blocker', 'src/a.tsx', "import { useBlocker } from '@tanstack/react-router';", 1],
  ['router-blocker', 'src/a.tsx', "import { useBlocker as block } from 'react-router';", 1],
  ['router-blocker', 'src/a.ts', "import { Link, useBlocker } from 'react-router-dom';", 1],
  // Type-only, another package, and the namespace form the rule does not see.
  ['router-blocker', 'src/a.ts', "import type { useBlocker } from '@tanstack/react-router';\nimport { type useBlocker as B } from 'react-router';", 0],
  ['router-blocker', 'src/a.ts', "import { useBlocker } from './blocker';\nimport * as Router from '@tanstack/react-router';\nRouter.useBlocker({});", 0],
  ['t98-class', 'src/a.tsx', 'export const A = () => <Card className="t98-card" />;', 1],
  ['t98-class', 'src/a.tsx', 'export const A = () => <Card className={`t98-card ${wide}`} />;', 1],
  ['t98-class', 'src/a.tsx', "export const A = () => <Card className={cx('t98-a', on && 't98-b', 'c')} />;", 2],
  ['t98-class', 'src/a.tsx', "export const A = () => <Card className=\"wide\" title=\"t98-card\" data-x={'t98-a'} />;", 0],
  ['t98-dom', 'src/a.ts', "el.querySelector('.t98-card'); document.querySelectorAll(`[data-t98]`);", 2],
  ['t98-dom', 'src/a.ts', "el.closest('.t98-a'); el.matches('.t98-a'); document.getElementsByClassName('t98-a');", 3],
  ['t98-dom', 'src/a.ts', "el.classList.add('t98-a'); el.classList.remove(`t98-${x}`); el?.classList.toggle('t98-a');", 3],
  ['t98-dom', 'src/a.ts', "el.querySelector('button'); el.querySelector(selector); el.classList.add('wide'); set.add('t98-a'); el.closest(`t9${8}-a`);", 0],
];

for (const [rule, path, source, expected] of ruleCases) {
  test(`${rule} counts ${expected} in ${JSON.stringify(source)}`, needsParser, () => {
    assert.equal(totalsFor({ [path]: `${source}\n` })[rule], expected);
  });
}

test('every run reports each ratchet rule total, including zeros, and refuses a new file', needsParser, () => consumer({
  sources: { 'src/a.tsx': "window.confirm('a');\n", 'src/b.ts': "el.classList.add('t98-x');\n", 'src/c.css': '.t98-x {}\n' },
}, root => {
  const { totals, errors } = run(root);
  assert.deepEqual(totals, { 'native-dialog': 1, 'router-blocker': 0, 't98-selector': 1, 't98-class': 0, 't98-dom': 1 });
  assert.deepEqual([...errors].sort(), [
    'src/a.tsx: native-dialog 1 exceeds baseline 0 (presentation is owned by @ten98/ui).',
    'src/b.ts: t98-dom 1 exceeds baseline 0 (presentation is owned by @ten98/ui).',
    'src/c.css: t98-selector 1 exceeds baseline 0 (presentation is owned by @ten98/ui).',
  ]);
}));

test('the leave-guard adapter alone may import useBlocker', needsParser, () => {
  consumer({ sources: { 'src/page.tsx': adapterSource } }, root => {
    assert.deepEqual(check(root), ['src/page.tsx: router-blocker 1 exceeds baseline 0 (presentation is owned by @ten98/ui).']);
  });
  // Without a valid register entry, the adapter file is counted too.
  consumer({ register: register(() => undefined, 'src/missing.ts') }, root => {
    assert.match(check(root).join('\n'), /src\/leave-guard\.ts: router-blocker 1 exceeds baseline 0/);
  });
});

const cssCases: [string, number][] = [
  ['.t98-button { color: red; }', 1],
  ['.a, .t98-b {}', 1],
  ['.t98-a, .t98-b > span {}', 2],
  ['[class*="t98-"] {}', 1],
  ["div[data-t98-part='x'] {}", 1],
  [':is(.t98-a, .b) {}', 1],
  ['@media (min-width: 40rem) { .t98-a { } .b { } }', 1],
  ['@supports (display: grid) { @layer app { .t98-a {} } }', 1],
  ['.a { color: red; .t98-b { color: blue; } }', 1],
  // A brace or a semicolon inside a string does not end the selector.
  ['[title="{"] .t98-a {} [data-x=";"] .t98-b {}', 2],
  ['/* .t98-a {} */ .a {}', 0],
  ['.a::after { content: ".t98-a {"; } .b {}', 0],
  ['.a { content: "t98-"; }', 0],
  ['@layer t98-overrides { .a {} } @import "t98-x.css";', 0],
  // An at-rule's own prelude is not a selector list, even when it names a class.
  ['@supports selector(.t98-a) { .b {} }', 0],
  ['.x-t98-y, #t98-id {}', 0],
];
for (const [css, expected] of cssCases) {
  test(`t98-selector counts ${expected} in ${JSON.stringify(css)}`, needsParser, () => {
    assert.equal(totalsFor({ 'src/styles/app.css': css })['t98-selector'], expected);
  });
}

test('the stylesheet scanner stays linear on a large and hostile input', needsParser, () => {
  const rules = '.a { color: red; }\n.t98-b, .c { margin: 0; }\n'.repeat(40_000);
  const hostile = `${'['.repeat(200_000)}${'"'.repeat(200_000)}${"(".repeat(200_000)} {} .t98-z {}\n/* unterminated ${'*'.repeat(200_000)}`;
  const started = performance.now();
  // 40,000 from the rules, and the one `.t98-z` after the hostile prelude closes.
  assert.equal(totalsFor({ 'src/big.css': rules, 'src/hostile.css': hostile })['t98-selector'], 40_001);
  assert.ok(performance.now() - started < 10_000, 'scanning took too long');
});

// The shared-flow register.
const flows = register;

test('the register refuses a listed feature it leaves out and a feature the list does not have', needsParser, () => consumer({
  register: flows(features => { delete features.team; features['setup-checklist'] = { status: 'absent', reason: 'No checklist.' }; }),
}, root => {
  assert.deepEqual(check(root), [
    `${registerName}: team is missing; declare it "uses", "absent" or "exception".`,
    `${registerName}: setup-checklist is not a shared flow in @ten98/ui ${firstUi}; remove it.`,
  ]);
}));

test('"uses" needs the export imported from its entry and referred to again', needsParser, () => {
  const usesTeam = flows(features => { features.team = { status: 'uses' }; });
  const refused = `${registerName}: team is "uses", but no file under src imports TeamFlow from @ten98/ui and refers to it.`;
  for (const source of [
    "import { TeamFlow } from '@ten98/ui';\nexport const Page = () => null;",
    "import { TeamFlow } from '@ten98/ui/app';\nexport const Page = () => <TeamFlow />;",
    "import type { TeamFlow } from '@ten98/ui';\ntype Props = typeof TeamFlow;",
    "import { type TeamFlow } from '@ten98/ui';\nexport const props: Parameters<typeof TeamFlow> = [];",
    "import { TeamFlow as Flow } from '@ten98/ui';\nexport const Page = () => <TeamFlow />;",
    "import { TeamFlow } from '@ten98/ui';\nexport const config = { TeamFlow: 1, a: other.TeamFlow };",
  ]) {
    consumer({ register: usesTeam, sources: { 'src/page.tsx': source } }, root => assert.deepEqual(check(root), [refused], source));
  }
  for (const source of [
    "import { TeamFlow } from '@ten98/ui';\nexport const Page = () => <TeamFlow />;",
    "import { TeamFlow as Flow } from '@ten98/ui';\nexport const Page = () => <Flow members={[]} />;",
    "import { TeamFlow } from '@ten98/ui';\nexport const routes = { team: TeamFlow };",
    "import { TeamFlow } from '@ten98/ui';\nexport const name = TeamFlow.displayName;",
    "import * as Ui from '@ten98/ui';\nexport const Page = () => <Ui.TeamFlow />;",
    "import { TeamFlow } from '@ten98/ui';\nexport { TeamFlow };",
  ]) {
    consumer({ register: usesTeam, sources: { 'src/page.tsx': source } }, root => assert.deepEqual(check(root), [], source));
  }
});

test('"uses" counts hooks and functions that are imported and called or referenced', needsParser, () => consumer({
  register: flows(features => { features.confirm = { status: 'uses' }; features.export = { status: 'uses' }; }),
  sources: { 'src/hooks.ts': "import { useConfirmDialog, saveFile as save } from '@ten98/ui';\nexport const useAsk = () => useConfirmDialog();\nexport const download = save.bind(null);\n" },
}, root => assert.deepEqual(check(root), [])));

test('"absent" needs a reason and no import of the export', needsParser, () => {
  consumer({ register: flows(features => { features.team = { status: 'absent' }; features.sessions = { status: 'absent', reason: '  ' }; }) }, root => {
    assert.deepEqual(check(root), [`${registerName}: sessions needs a reason of 1 to 500 characters.`, `${registerName}: team needs a reason of 1 to 500 characters.`]);
  });
  consumer({ sources: { 'src/page.tsx': "import { TeamFlow } from '@ten98/ui';\nexport const unused = 1;\n" } }, root => {
    assert.deepEqual(check(root), [`${registerName}: team is "absent", but TeamFlow is imported from @ten98/ui.`]);
  });
});

test('"exception" needs a reason and a review trigger that has not come due', needsParser, () => {
  const exception = (entry: Record<string, unknown>) => flows(features => { features.team = { status: 'exception', ...entry }; });
  const [major, minor] = firstUi.split('.').map(Number);
  const later = `${major}.${minor! + 1}.0`;
  const triggerMissing = `${registerName}: team needs a review trigger, { "ui": "<x.y.z>" } or { "issue": "<https URL>" }.`;
  for (const [entry, expected] of [
    [{ reason: 'Waits for F3.', review: { ui: later } }, []],
    [{ reason: 'Waits for F3.', review: { issue: 'https://github.com/Ten98-IO-Company/ten98-design-system/issues/220' } }, []],
    [{ reason: 'x'.repeat(500), review: { ui: later } }, []],
    [{ review: { ui: later } }, [`${registerName}: team needs a reason of 1 to 500 characters.`]],
    [{ reason: 'x'.repeat(501), review: { ui: later } }, [`${registerName}: team needs a reason of 1 to 500 characters.`]],
    [{ reason: 'Waits for F3.' }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { ui: 'soon' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { issue: 'http://example.com/1' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { ui: later, issue: 'https://example.com/1' } }, [triggerMissing]],
    [{ reason: 'Waits for F3.', review: { ui: firstUi } }, [`${registerName}: team is due for review: @ten98/ui ${firstUi} has reached ${firstUi}; move it to "uses" or record a new reason and trigger.`]],
  ] satisfies [Record<string, unknown>, string[]][]) {
    consumer({ register: exception(entry) }, root => assert.deepEqual(check(root), expected, JSON.stringify(entry)));
  }
  // A trigger below the installed version is due as well.
  consumer({ register: exception({ reason: 'Waits for F3.', review: { ui: later } }), ui: { version: `${major}.${minor! + 1}.3` } }, root => {
    assert.match(check(root).join('\n'), /team is due for review/);
  });
});

test('the register refuses an unknown status', needsParser, () => consumer({ register: flows(features => { features.team = { status: 'partial', reason: 'Half.' }; features.sessions = {}; }) }, root => {
  assert.deepEqual(check(root), [
    `${registerName}: sessions has unknown status (none); use "uses", "absent" or "exception".`,
    `${registerName}: team has unknown status "partial"; use "uses", "absent" or "exception".`,
  ]);
}));

test('the register needs a leave-guard adapter that is a script file under the roots', needsParser, () => {
  for (const adapter of [undefined, '', 'src/missing.ts', 'scripts/leave-guard.ts', '../leave-guard.ts', 'src/styles.css']) {
    consumer({ register: flows(() => undefined, adapter), sources: { 'scripts/leave-guard.ts': adapterSource, 'src/styles.css': '' } }, root => {
      assert.match(check(root).join('\n'), new RegExp(`${registerName}: leaveGuardAdapter must name the app's leave-guard adapter, a script file under src\\.`), String(adapter));
    });
  }
  consumer({ register: flows(() => undefined, './src/leave-guard.ts') }, root => assert.deepEqual(check(root), []));
});

test('the register itself must exist and parse', needsParser, () => {
  consumer({ register: null }, root => {
    // Without a register there is no adapter, so its useBlocker import is counted as well.
    assert.deepEqual(check(root), [`${registerName} is missing; record it once with check.mjs --record-shared-flows, then write each reason.`,
      'src/leave-guard.ts: router-blocker 1 exceeds baseline 0 (presentation is owned by @ten98/ui).']);
  });
  consumer({}, root => {
    writeFileSync(join(root, registerName), '{ "features": ');
    assert.match(check(root).join('\n'), /shared-flows\.json cannot be parsed/);
    writeFileSync(join(root, registerName), '{ "team": { "status": "uses" } }');
    assert.match(check(root).join('\n'), /shared-flows\.json must hold/);
  });
});

test('the installed list fails closed when missing, unparseable, of another schema or with an entry without exports', needsParser, () => {
  const broken = (change: (list: Record<string, any>) => void): string => { const list = JSON.parse(uiList); change(list); return JSON.stringify(list); };
  for (const [ui, expected] of [
    [{ version: '0.39.2', list: null }, `The installed @ten98/ui ships no shared-flows.json; the shared-flow register needs @ten98/ui ${firstUi} or later.`],
    [{ list: '{ "schemaVersion": 1, ' }, `@ten98/ui ${firstUi} shared-flows.json cannot be parsed`],
    [{ list: broken(list => { list.schemaVersion = 2; }) }, `@ten98/ui ${firstUi} shared-flows.json has schemaVersion 2; this checker reads schemaVersion 1.`],
    [{ list: broken(list => { delete list.features; }) }, `@ten98/ui ${firstUi} shared-flows.json has no features map.`],
    [{ list: broken(list => { list.features.team.exports = []; }) }, `@ten98/ui ${firstUi} shared-flows.json: feature team has no exports with a name and an entry.`],
    [{ list: broken(list => { delete list.features.team.exports; }) }, `@ten98/ui ${firstUi} shared-flows.json: feature team has no exports with a name and an entry.`],
    [{ list: broken(list => { list.features.team.exports = [{ name: 'TeamFlow' }]; }) }, `@ten98/ui ${firstUi} shared-flows.json: feature team has no exports with a name and an entry.`],
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
  assert.deepEqual(Object.keys(written), ['leaveGuardAdapter', 'features']);
  assert.equal(written.leaveGuardAdapter, '');
  assert.deepEqual(Object.keys(written.features), Object.keys(listed));
  assert.deepEqual(written.features.team, { status: 'uses' });
  assert.deepEqual(written.features['api-keys'], { status: 'exception', reason: '' });
  assert.deepEqual(written.features.sessions, { status: 'exception', reason: '' });
  // Every exception fails until its reason and trigger are written, and the adapter until it is named.
  assert.match(errors.join('\n'), /leaveGuardAdapter must name/);
  assert.match(errors.join('\n'), /api-keys needs a reason of 1 to 500 characters\./);
  assert.match(errors.join('\n'), /sessions needs a review trigger/);
  assert.doesNotMatch(errors.join('\n'), /: team /);
  assert.deepEqual(recordSharedFlows(root, profile, { parseAst }), [`${registerName} already exists; edit it instead of recording it again.`]);
  assert.deepEqual(JSON.parse(readFileSync(join(root, registerName), 'utf8')), written);
}));

test('record refuses without the installed list and writes nothing', needsParser, () => consumer({ register: null, ui: { list: null } }, root => {
  assert.match(recordSharedFlows(root, profile, { parseAst }).join('\n'), /ships no shared-flows\.json/);
  assert.equal(existsSync(join(root, registerName)), false);
}));

test('check.mjs prints the remaining ratchet counts on every run and records the register', needsParser, () => {
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
      writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'fixture-presentation', type: 'module', packageManager: 'pnpm@11.19.0', engines: { node: '>=24.22.1 <25' },
        scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'pnpm check:architecture && node --test' } }));
      const rolldown = join(root, 'node_modules', 'rolldown');
      mkdirSync(rolldown);
      writeFileSync(join(rolldown, 'package.json'), '{"name":"rolldown","exports":{"./parseAst":"./parse-ast.cjs"}}');
      writeFileSync(join(rolldown, 'parse-ast.cjs'), `module.exports = require(${JSON.stringify(parserPath)});`);
      const cli = (...args: string[]) => spawnSync(process.execPath, [join(checker, 'check.mjs'), ...args, root], { encoding: 'utf8', timeout: 20_000, windowsHide: true });
      const remaining = /presentation counts remaining: native-dialog 1, router-blocker 0, t98-selector 0, t98-class 0, t98-dom 0\./;
      const recorded = cli('--record-shared-flows');
      assert.equal(recorded.status, 1);
      // The recorded register names no adapter yet, so the adapter's useBlocker import is counted until it is named.
      assert.match(recorded.stdout, /presentation counts remaining: native-dialog 1, router-blocker 1, t98-selector 0, t98-class 0, t98-dom 0\./);
      assert.match(recorded.stderr, /leaveGuardAdapter must name/);
      assert.ok(existsSync(join(root, registerName)));
      writeFileSync(join(root, registerName), JSON.stringify(absentRegister()));
      const failing = cli();
      assert.equal(failing.status, 1);
      assert.match(failing.stdout, remaining);
      assert.match(failing.stderr, /src\/a\.tsx: native-dialog 1 exceeds baseline 0/);
      assert.equal(cli('--update-presentation-baseline').status, 0);
      const passing = cli();
      assert.equal(passing.status, 0, passing.stderr);
      assert.match(passing.stdout, remaining);
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
