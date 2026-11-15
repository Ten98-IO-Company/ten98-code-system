import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { checkStartEntry, type PackageManifest } from '../check.mjs';

// The parser resolves as in presentation.test.mts, and CI never skips for want of it.
const runtime = createRequire(new URL('../package.json', import.meta.url));
const parserPath = [() => runtime.resolve('rolldown/parseAst'), () => createRequire(runtime.resolve('vite/package.json')).resolve('rolldown/parseAst')].map(find => {
  try { return find(); } catch { return undefined; }
}).find(Boolean);
const parseAst = parserPath ? runtime(parserPath).parseAst : undefined;
const needsParser = { skip: parseAst || process.env.CI ? false : 'rolldown/parseAst is not installed; run pnpm install' };

const START = `import { createStart } from '@tanstack/react-start';
import { ten98StartOptions } from '@ten98/runtime/start';
import { auditMiddleware } from './server/audit';

export const startInstance = createStart(() => ten98StartOptions({ requestMiddleware: [auditMiddleware] }));
`;
const CLIENT = `import { hydrateTen98Start } from '@ten98/runtime/start';

hydrateTen98Start();
`;
// What Start's router generator writes once src/start.ts exists: a type-only import, which is not a use.
const ROUTE_TREE = `import type { createStart } from '@tanstack/react-start'
import type { startInstance } from './start.ts'
declare module '@tanstack/react-start' { interface Register { config: Awaited<ReturnType<typeof startInstance.getOptions>> } }
`;
const discover: PackageManifest = { name: 'ten98-discover', dependencies: { '@tanstack/react-start': '1.168.61' } };

function app(files: Record<string, string>, manifest: PackageManifest = discover): string[] {
  const root = mkdtempSync(join(tmpdir(), 'ten98-start-check-'));
  try {
    for (const [name, text] of Object.entries(files)) { mkdirSync(dirname(join(root, name)), { recursive: true }); writeFileSync(join(root, name), text); }
    return checkStartEntry(root, manifest, { parseAst });
  } finally { rmSync(root, { recursive: true, force: true }); }
}
const passing = { 'src/start.ts': START, 'src/client.tsx': CLIENT, 'src/routeTree.gen.ts': ROUTE_TREE };

test('the two one-line entries pass, aliased imports included', needsParser, () => {
  assert.deepEqual(app(passing), []);
  assert.deepEqual(app({
    ...passing,
    'src/start.ts': "import { createStart as start } from '@tanstack/react-start';\nimport { ten98StartOptions as options } from '@ten98/runtime/start';\nexport const startInstance = start(() => options());\n",
    'src/client.tsx': "import { hydrateTen98Start as hydrate } from '@ten98/runtime/start';\nhydrate({ reporter: () => {} });\n",
  }), []);
});

// The passing app with `files` replaced, or removed where undefined, gives exactly one error, matching `pattern`.
const refused = (files: Record<string, string | undefined>, pattern: RegExp) => {
  const errors = app(Object.fromEntries(Object.entries({ ...passing, ...files }).filter((entry): entry is [string, string] => entry[1] !== undefined)));
  assert.equal(errors.length, 1, errors.join('\n'));
  assert.match(errors[0]!, pattern);
};
const SHAPE = /^src\/start\.ts must export const startInstance = createStart\(\(\) => ten98StartOptions/;
const IMPORTS = "import { createStart } from '@tanstack/react-start';\nimport { ten98StartOptions } from '@ten98/runtime/start';\n";

test('each refusal names the file and the required shape', needsParser, () => {
  refused({ 'src/start.ts': undefined }, /^src\/start\.ts is missing/);
  refused({ 'src/client.tsx': undefined }, /^src\/client\.tsx is missing/);
  // Start's own options with no shared defaults, the shared options spread and overridden, a wrapper, and an import
  // from somewhere else are all a src/start.ts without ten98StartOptions returned directly.
  for (const body of [
    "import { createStart, createCsrfMiddleware } from '@tanstack/react-start';\nexport const startInstance = createStart(() => ({ requestMiddleware: [createCsrfMiddleware()] }));\n",
    "import { createStart } from '@tanstack/react-start';\nimport { ten98StartOptions } from '@ten98/runtime/start';\nexport const startInstance = createStart(() => ({ ...ten98StartOptions(), serializationAdapters: [] }));\n",
    "import { createStart } from '@tanstack/react-start';\nimport { ten98StartOptions } from '@ten98/runtime/start';\nexport const startInstance = createStart(() => { const options = ten98StartOptions(); options.requestMiddleware = [] as never; return options; });\n",
    "import { createStart } from '@tanstack/react-start';\nimport { ten98StartOptions } from './local-copy';\nexport const startInstance = createStart(() => ten98StartOptions());\n",
    "import { createStart } from '@tanstack/react-start';\nimport { ten98StartOptions } from '@ten98/runtime/start';\nexport const instance = createStart(() => ten98StartOptions());\n",
    "import { createStart } from '@tanstack/react-start';\nimport { ten98StartOptions } from '@ten98/runtime/start';\nexport let startInstance = createStart(() => ten98StartOptions());\n",
  ]) refused({ 'src/start.ts': body }, /^src\/start\.ts must export const startInstance = createStart\(\(\) => ten98StartOptions/);
  refused({ 'src/start.ts': START.replace('[auditMiddleware]', '[auditMiddleware, createStart(() => ({})) as never]') }, /^src\/start\.ts must call createStart only once/);
  for (const body of [
    "import { hydrateRoot } from 'react-dom/client';\nhydrateRoot(document, null);\n",
    "import { hydrateTen98Start } from '@ten98/runtime/start';\nif (Math.random() > 2) hydrateTen98Start();\n",
    "import { hydrateTen98Start } from './elsewhere';\nhydrateTen98Start();\n",
  ]) refused({ 'src/client.tsx': body }, /^src\/client\.tsx must call hydrateTen98Start\(\.\.\.\) from @ten98\/runtime\/start at its top level/);
  // createStart anywhere else in the source roots: a call, an aliased import, a namespace member and a re-export.
  for (const body of [
    "import { createStart } from '@tanstack/react-start';\nexport const second = createStart(() => ({}));\n",
    "import { createStart as make } from '@tanstack/react-start';\nexport { make };\n",
    "import * as Start from '@tanstack/react-start';\nexport const second = Start.createStart(() => ({}));\n",
    "export { createStart } from '@tanstack/react-start';\n",
  ]) refused({ 'src/server/other.ts': body }, /^src\/server\/other\.ts: createStart belongs in src\/start\.ts only/);
});

test('in src/start.ts ten98StartOptions is the import, and nothing else can reach the start instance', needsParser, () => {
  for (const body of [
    // A parameter, with or without a default, that shadows the import; a second import of the same local name.
    `${IMPORTS}export const startInstance = createStart((ten98StartOptions = () => ({})) => ten98StartOptions());\n`,
    `${IMPORTS}export const startInstance = createStart((ten98StartOptions: () => object) => ten98StartOptions() as never);\n`,
    `${IMPORTS}import { ten98StartOptions as copy, ten98StartOptions } from './local-copy';\nexport const startInstance = createStart(() => ten98StartOptions());\n`,
    // A second declarator in the export.
    `${IMPORTS}export const startInstance = createStart(() => ten98StartOptions()), other = 1;\n`,
  ]) refused({ 'src/start.ts': body }, SHAPE);
  // Any other statement, or any other use of startInstance, could replace or change the start instance.
  for (const body of [
    `${START}export const other = createStart(() => ({}));\n`,
    `${START}startInstance.getOptions = async () => ({}) as never;\n`,
    `${START}Object.assign(startInstance, { getOptions: async () => ({}) });\n`,
    `const prepared = 1;\n${START}`,
    `${START}export default startInstance;\n`,
    START.replace('auditMiddleware] }', 'auditMiddleware], ...Object.assign(startInstance, {}) as never }'),
  ]) refused({ 'src/start.ts': body }, /^src\/start\.ts must hold only its imports and the startInstance export, and name startInstance nowhere else/);
});

test('a second createStart argument and an entry that does not parse are refusals', needsParser, () => {
  refused({ 'src/start.ts': `${IMPORTS}export const startInstance = createStart(() => ten98StartOptions(), {} as never);\n` }, SHAPE);
  refused({ 'src/start.ts': 'export const startInstance = ;\n' }, /^src\/start\.ts: cannot parse for the Start entry check/);
  refused({ 'src/client.tsx': 'hydrateTen98Start(<\n' }, /^src\/client\.tsx: cannot parse for the Start entry check/);
});

test('no other file may carry an entry name Start resolves, so the checked entries are the ones Start runs', needsParser, () => {
  // Start takes the first of src/<name>, .ts, .js, .mts, .mjs, .tsx and .jsx; every other spelling is refused too.
  for (const kind of ['start', 'client']) {
    const checked = kind === 'start' ? 'src/start.ts' : 'src/client.tsx';
    for (const extension of ['', '.ts', '.js', '.mts', '.mjs', '.cts', '.cjs', '.tsx', '.jsx']) {
      const name = `src/${kind}${extension}`;
      if (name === checked) continue;
      assert.deepEqual(app({ ...passing, [name]: 'export {};\n' }), [`${name}: Start can take its ${kind} entry from this file instead of ${checked}; keep ${checked} as the only src/${kind} file.`], name);
    }
    // A different case is the same file on a case-insensitive file system.
    assert.equal(app({ ...passing, [`src/${kind.toUpperCase()}.js`]: 'export {};\n' }).length, 1);
  }
  // Folders of those names never resolve as an entry, and other names that start with one are unrelated.
  assert.deepEqual(app({ ...passing, 'src/client/api.ts': 'export {};\n', 'src/start/setup.ts': 'export {};\n', 'src/client-api.ts': 'export {};\n', 'src/start.test.ts': 'export {};\n', 'src/client.d.ts': 'export {};\n' }), []);
  // A second entry that also calls createStart is refused for both.
  assert.deepEqual(app({ ...passing, 'src/start.tsx': "import { createStart } from '@tanstack/react-start';\nexport const startInstance = createStart(() => ({}));\n" }).map(error => error.split(':')[0]), ['src/start.tsx', 'src/start.tsx']);
});

test('the rule applies to apps that ship Start, and not to a waived profile or this package', needsParser, () => {
  const missing = /src\/start\.ts is missing/;
  // Books declares Start through the shared app stack even before its manifest lists it.
  assert.match(app({}, { name: 'ten98-books' }).join('\n'), missing);
  // Campaign's open appStack transition still waives Start, until its manifest lists it.
  assert.deepEqual(app({}, { name: 'ten98-campaign' }), []);
  assert.match(app({}, { name: 'ten98-campaign', dependencies: { '@tanstack/react-start': '1.168.61' } }).join('\n'), missing);
  // The runtime has Start only as a development and optional peer dependency.
  assert.deepEqual(app({}, { name: '@ten98/runtime', devDependencies: { '@tanstack/react-start': '1.168.61' }, peerDependencies: { '@tanstack/react-start': '1.168.61' } }), []);
});

test('the Start entry check fails closed without a parser', () => {
  const root = mkdtempSync(join(tmpdir(), 'ten98-start-check-'));
  try { assert.match(checkStartEntry(root, discover).join('\n'), /Cannot resolve rolldown\/parseAst/); }
  finally { rmSync(root, { recursive: true, force: true }); }
});
