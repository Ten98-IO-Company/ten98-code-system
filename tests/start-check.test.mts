import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
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

test("an errorComponent or defaultErrorComponent that reads its error's text is refused", needsParser, () => {
  const ROUTE = "import { createFileRoute, createRoute, createRouter } from '@tanstack/react-router';\n";
  const refusals: [string, string][] = [
    ['reads error.message', "export const Route = createFileRoute('/x')({ errorComponent: ({ error }) => <p>{error.message}</p> });\n"],
    ['reads error.stack', "export const Route = createFileRoute('/x')({ errorComponent: ({ error: failure }: { error: Error }) => <p>{failure?.stack}</p> });\n"],
    ['reads error.cause', "export const Route = createRoute({ errorComponent: (props: { error: Error }) => <p>{String(props.error!.cause)}</p> } as never);\n"],
    ['reads error.name', "export const Route = createFileRoute('/x')({ errorComponent: function Failure({ error }) { const { name } = error; return <p>{name}</p>; } });\n"],
    ['reads error.toString', "export const Route = createFileRoute('/x')({ errorComponent: ({ error }) => <p>{error.toString()}</p> });\n"],
    ['reads error.message',"export const Route = createFileRoute('/x')({ errorComponent: ({ error: { message } }) => <p>{message}</p> });\n"],
    ['reads error.message',"export const Route = createFileRoute('/x')({ errorComponent: ({ error }) => <p>{(error as Error)['message']}</p> });\n"],
    ['spreads the error', "function RouteError({ error }: { error: Error }) { return <p {...error} />; }\nexport const router = createRouter({ routeTree: {} as never, defaultErrorComponent: RouteError });\n"],
    ['spreads the error',"const Failure = (props: { error: Error }) => <Details value={{ ...props.error }} />;\nexport const Route = createFileRoute('/x')({ errorComponent: Failure });\n"],
    ['puts the error in a template literal', "const errorComponent = ({ error }: { error: Error }) => <p>{`Failed: ${error}`}</p>;\nexport const Route = createFileRoute('/x')({ errorComponent });\n"],
    ['converts the error with String()', "export const Route = createFileRoute('/x')({ errorComponent(props: { error: Error }) { const { error } = props; return <p>{String(error)}</p>; } });\n"],
    ['copies the rest of the error', "export const Route = createFileRoute('/x')({ errorComponent: ({ error }) => { const { ...fields } = error; return <p>{Object.keys(fields)}</p>; } });\n"],
  ];
  for (const [finding, body] of refusals) {
    refused({ 'src/routes/failure.tsx': ROUTE + body }, new RegExp(`^src/routes/failure\\.tsx line \\d+: ${finding.replace(/[.()]/gu, '\\$&')}: an errorComponent also renders on the server with the original error, so it shows publicErrorMessage\\(error\\)`, 'u'));
  }
  // The shown sentence, the planned shared screen, and other components and props that read a message are fine.
  assert.deepEqual(app({
    ...passing,
    'src/routes/fine.tsx': `${ROUTE}import { publicErrorMessage } from '@ten98/runtime/start';
export const Route = createFileRoute('/fine')({
  errorComponent: ({ error, reset }) => <RouteErrorScreen message={publicErrorMessage(error)} onRetry={reset} />,
  notFoundComponent: ({ data }: { data: { message: string } }) => <p>{data.message}</p>,
  component: () => { const error = new Error('local'); return <p>{error.message}</p>; },
});
export const router = createRouter({ routeTree: {} as never, defaultErrorComponent: ({ error, info }) => <p title={info?.componentStack}>{publicErrorMessage(error)}</p> });
`,
  }), []);
});

test('the CLI runs the Start entry check on a Start app', needsParser, () => {
  // The CLI reads the canonical declaration beside check.mjs, so a copy of both declares a profile that needs Start
  // and nothing else. The app sits under work/, where it resolves this package's parser as an installed app would.
  const root = fileURLToPath(new URL('../', import.meta.url));
  mkdirSync(join(root, 'work'), { recursive: true });
  const folder = mkdtempSync(join(root, 'work', 'start-cli-')), checker = join(folder, 'checker'), directory = join(folder, 'app');
  try {
    mkdirSync(checker);
    mkdirSync(join(directory, 'src'), { recursive: true });
    for (const name of ['check.mjs', 'database-policy.mjs']) copyFileSync(join(root, name), join(checker, name));
    const contract = JSON.parse(readFileSync(join(root, 'architecture.json'), 'utf8'));
    contract.profiles['fixture-start'] = { dependencies: { '@tanstack/react-start': '1.168.61' }, devDependencies: {}, sharedDependencies: [], sharedDevDependencies: [], peerDependencies: {}, checkScripts: ['test'], database: { engine: 'postgresql' } };
    writeFileSync(join(checker, 'architecture.json'), JSON.stringify(contract));
    writeFileSync(join(directory, 'package.json'), JSON.stringify({ name: 'fixture-start', type: 'module', packageManager: 'pnpm@11.19.0', engines: { node: '>=24.22.1 <25' },
      dependencies: { '@tanstack/react-start': '1.168.61' }, scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'pnpm check:architecture && node --test' } }));
    const run = () => spawnSync(process.execPath, [join(checker, 'check.mjs'), directory], { encoding: 'utf8', timeout: 60_000, windowsHide: true });
    const missing = run();
    assert.equal(missing.status, 1, missing.stdout + missing.stderr);
    assert.match(missing.stderr, /: src\/start\.ts is missing/);
    assert.match(missing.stderr, /: src\/client\.tsx is missing/);
    writeFileSync(join(directory, 'src', 'start.ts'), START);
    writeFileSync(join(directory, 'src', 'client.tsx'), CLIENT);
    const passed = run();
    assert.equal(passed.status, 0, passed.stdout + passed.stderr);
    assert.match(passed.stdout, /architecture declarations match fixture-start/);
  } finally { rmSync(folder, { recursive: true, force: true }); }
});

test('the Start entry check fails closed without a parser', () => {
  const root = mkdtempSync(join(tmpdir(), 'ten98-start-check-'));
  try { assert.match(checkStartEntry(root, discover).join('\n'), /Cannot resolve rolldown\/parseAst/); }
  finally { rmSync(root, { recursive: true, force: true }); }
});
