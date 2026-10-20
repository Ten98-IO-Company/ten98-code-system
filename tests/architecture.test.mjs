import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { checkManifest, checkRuntimeVersion, inspectSourcePolicy } from '../check.mjs';
import { inspectDatabasePolicy } from '../database-policy.mjs';

const databaseFixture = () => ({
  policy: { default: 'sqlite', integration: 'drizzle', stateless: 'none',
    exceptions: { native: { engine: 'd1', profiles: ['site'], purpose: 'native-platform-binding', requirement: 'Native D1 binding', review: 'issue7' } },
    transitions: { existing: { profile: 'existing', engine: 'postgresql', target: 'sqlite', reason: 'Preserve installed data pending verified parity', review: 'issue7' } } },
  profiles: { app: { database: { engine: 'sqlite' } }, library: { database: { engine: 'none' } },
    site: { database: { engine: 'd1', exception: 'native' } }, existing: { database: { engine: 'postgresql', transition: 'existing' } } },
});

test('canonical database default is SQLite with Drizzle and no database in stateless packages', () => {
  const contract = JSON.parse(readFileSync(new URL('../architecture.json', import.meta.url), 'utf8'));
  assert.equal(contract.databasePolicy.default, 'sqlite');
  assert.equal(contract.databasePolicy.integration, 'drizzle');
  assert.equal(contract.profiles['@ten98/runtime'].database.engine, 'none');
  assert.equal(contract.profiles['@ten98/ui'].database.engine, 'none');
  assert.deepEqual(inspectDatabasePolicy(contract.databasePolicy, contract.profiles), []);
  const { policy, profiles } = databaseFixture();
  assert.deepEqual(inspectDatabasePolicy(policy, profiles), []);
});

test('database choices need explicit declarations and centrally reviewed exceptions', () => {
  for (const mutate of [
    f => { f.policy.default = 'postgresql'; },
    f => { delete f.profiles.app.database; },
    f => { f.profiles.app.database = { engine: 'postgresql' }; },
    f => { f.profiles.app.database = { engine: 'postgresql', exception: 'not-recorded' }; },
    f => { f.profiles.app.database = { engine: 'd1', exception: 'native' }; },
    f => { f.policy.exceptions.native.purpose = 'vector-storage'; },
    f => { f.policy.exceptions.native.purpose = ['approved-requirement']; },
    f => { f.policy.exceptions.native.requirement = ''; },
    f => { f.policy.exceptions.native.review = ''; },
    f => { f.policy.transitions.existing.target = 'postgresql'; },
    f => { f.policy.transitions.existing.reason = ''; },
    f => { f.profiles.library.database = { engine: 'none', exception: 'native' }; },
    f => { f.profiles.app.database = []; },
  ]) {
    const fixture = databaseFixture(); mutate(fixture);
    assert.ok(inspectDatabasePolicy(fixture.policy, fixture.profiles).length > 0);
  }
  assert.ok(inspectDatabasePolicy(null, null).length > 0);
});

test('canonical checker CLI enforces database policy before accepting a reviewed manifest', () => {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-database-policy-'));
  try {
    const checkerFolder = join(directory, 'checker-fixture');
    mkdirSync(checkerFolder, { recursive: true });
    for (const name of ['check.mjs', 'database-policy.mjs']) writeFileSync(join(checkerFolder, name), readFileSync(new URL('../' + name, import.meta.url)));
    const contract = JSON.parse(readFileSync(new URL('../architecture.json', import.meta.url), 'utf8'));
    contract.profiles['fixture-stateful'] = { dependencies: {}, devDependencies: {}, sharedDependencies: [], sharedDevDependencies: [], peerDependencies: {}, checkScripts: ['test'], database: { engine: 'sqlite' } };
    const manifest = { name: 'fixture-stateful', type: 'module', engines: { node: '>=24.0.0 <25' },
      scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'npm run check:architecture && node --test' } };
    writeFileSync(join(directory, 'package.json'), JSON.stringify(manifest));
    const run = () => {
      writeFileSync(join(checkerFolder, 'architecture.json'), JSON.stringify(contract));
      const result = spawnSync(process.execPath, [join(checkerFolder, 'check.mjs'), directory], { encoding: 'utf8', timeout: 5000, windowsHide: true });
      assert.ifError(result.error);
      return result;
    };
    assert.equal(run().status, 0);
    contract.profiles['fixture-stateful'].database = { engine: 'postgresql' };
    const denied = run();
    assert.equal(denied.status, 1);
    assert.match(denied.stderr, /nondefault engine postgresql needs/);
    contract.profiles['fixture-stateful'].database = { engine: 'sqlite' };
    contract.databasePolicy.default = 'postgresql';
    assert.equal(run().status, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('running Node must satisfy the canonical range, not just manifest declarations', () => {
  for (const version of ['24.0.0', '24.19.0', '24.999.999']) assert.deepEqual(checkRuntimeVersion(version), []);
  for (const version of ['22.14.0', '23.99.99', '25.0.0', '26.1.0']) assert.match(checkRuntimeVersion(version).join('\n'), /outside canonical range/);
  for (const version of ['', '24', '24.0.0-rc.1', 'v24.0.0', null]) assert.match(checkRuntimeVersion(version).join('\n'), /Cannot validate/);
});

// Independent fixture: do not derive the expected application from architecture.json.
const campaign = () => ({
  name: 'ten98-campaign', type: 'module', engines: { node: '>=24.0.0 <25' },
  dependencies: { '@ten98/ui': 'file:vendor/ten98-ui-0.3.22.tgz', '@ten98/runtime': 'file:vendor/ten98-runtime-0.1.7.tgz', 'openid-client': '6.8.8', 'qrcode-generator': '2.0.4', react: '19.2.8', 'react-dom': '19.2.8' },
  devDependencies: { '@types/react': '19.2.2', '@types/react-dom': '19.2.2', typescript: '7.0.2', vite: '8.3.4' },
  scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'npm run check:architecture && node --test', build: 'npm run check:architecture && vite build' },
});

test('architecture accepts independent manifests with reviewed tools and mandatory gates', () => {
  assert.deepEqual(checkManifest(campaign()), []);
  const runtime = { name: '@ten98/runtime', type: 'module', engines: { node: '>=24.0.0 <25' }, devDependencies: { typescript: '7.0.2' }, scripts: { 'check:architecture': 'node check.mjs .', test: 'npm run check:architecture && node --test', build: 'npm run check:architecture && tsc --project tsconfig.json', typecheck: 'npm run check:architecture && tsc --project tsconfig.json --noEmit' } };
  assert.deepEqual(checkManifest(runtime), []);
});

test('native static site uses shared build tools without application runtime dependencies', () => {
  const site = () => ({
    name: 'ten98-io', type: 'module', engines: { node: '>=24.0.0 <25' },
    devDependencies: { wrangler: '4.145.0', '@types/node': '24.10.1', typescript: '7.0.2', '@ten98/ui': 'file:vendor/ten98-ui-0.3.22.tgz', '@ten98/runtime': 'file:vendor/ten98-runtime-0.1.7.tgz', react: '19.2.8', 'react-dom': '19.2.8' },
    scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', build: 'npm run check:architecture && tsc --project tsconfig.tooling.json && node scripts/build.mts', check: 'npm run check:architecture && npm run build && node scripts/check.mjs', test: 'npm run check:architecture && node scripts/enquiry-test.mjs' },
  });
  assert.deepEqual(checkManifest(site()), []);
  for (const [change, expected] of [
    [m => { m.scripts.build = 'tsc --project tsconfig.tooling.json && node scripts/build.mts'; }, /scripts.build must run check:architecture first/],
    [m => { delete m.scripts.check; }, /Missing scripts.check/],
    [m => { m.scripts.test = 'node scripts/enquiry-test.mjs'; }, /scripts.test must run check:architecture first/],
    [m => { m.dependencies = { '@ten98/runtime': m.devDependencies['@ten98/runtime'] }; }, /Unapproved runtime dependency @ten98\/runtime/],
    [m => { m.dependencies = { react: '19.2.8' }; }, /Unapproved runtime dependency react/],
    [m => { m.devDependencies['@ten98/ui'] = 'file:vendor/ten98-ui-0.3.19.tgz'; }, /devDependencies.@ten98\/ui/],
    [m => { m.devDependencies.wrangler = '4.144.0'; }, /devDependencies.wrangler/],
    [m => { m.devDependencies.react = '19.3.1'; m.devDependencies['react-dom'] = '19.3.1'; }, /devDependencies.react/],
  ]) {
    const manifest = site(); change(manifest);
    assert.match(checkManifest(manifest).join('\n'), expected);
  }
});

test('native static profile checks every new tooling source and retains only named JavaScript paths', () => {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-static-policy-'));
  try {
    const policy = JSON.parse(readFileSync(new URL('../architecture.json', import.meta.url), 'utf8')).profiles['ten98-io'].sourceLanguage;
    const files = ['scripts/build.mts', 'scripts/css-tokens.mts', 'scripts/css-tokens.test.mts'];
    const legacy = ['src/worker.js', 'public/enquiry.js', 'public/tracking-preferences.js', 'scripts/check.mjs', 'scripts/check-self-test.mjs', 'scripts/enquiry-test.mjs', 'scripts/turnstile-frontend-test.mjs', 'scripts/tracking-preferences-test.mjs'];
    for (const name of [...files, ...legacy]) { mkdirSync(dirname(join(directory, name)), { recursive: true }); writeFileSync(join(directory, name), 'export {};\n'); }
    const compilation = { compilerOptions: { strict: true }, files };
    assert.deepEqual(policy.compilerProjects, ['tsconfig.tooling.json']);
    assert.deepEqual(inspectSourcePolicy(directory, policy, compilation), []);
    assert.match(inspectSourcePolicy(directory, policy, { ...compilation, files: files.filter(file => !file.endsWith('css-tokens.mts')) }).join('\n'), /css-tokens.mts: TypeScript is absent/);
    assert.match(inspectSourcePolicy(directory, policy, { ...compilation, compilerOptions: { strict: false } }).join('\n'), /must enable strict/);
    writeFileSync(join(directory, 'src/new-worker-helper.js'), 'export {};\n');
    assert.match(inspectSourcePolicy(directory, policy, compilation).join('\n'), /new-worker-helper.js: new authored JavaScript/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('architecture rejects unreviewed toolchains and dependency resolution substitutions', () => {
  for (const [change, expected] of [
    [m => { m.devDependencies.next = '16.0.0'; }, /Unapproved development dependency next/],
    [m => { m.devDependencies.express = '5.0.0'; }, /Unapproved development dependency express/],
    [m => { m.devDependencies['@ten98/ui'] = m.dependencies['@ten98/ui']; }, /Unapproved development dependency @ten98\/ui/],
    [m => { m.overrides = { react: '20.0.0' }; }, /overrides/],
    [m => { m.resolutions = { react: '20.0.0' }; }, /resolutions/],
    [m => { m.pnpm = { overrides: { react: '20.0.0' } }; }, /pnpm.overrides/],
    [m => { m.pnpm = { patchedDependencies: { 'react@19.2.8': 'patches/react.patch' } }; }, /pnpm.patchedDependencies/],
    [m => { m.pnpm = { packageExtensions: { react: { dependencies: { express: '5.0.0' } } } }; }, /pnpm.packageExtensions/],
    [m => { m.bundledDependencies = ['express']; }, /bundledDependencies/],
    [m => { m.bundleDependencies = true; }, /bundleDependencies/],
  ]) {
    const manifest = campaign(); change(manifest);
    assert.match(checkManifest(manifest).join('\n'), expected);
  }
  const manifest = campaign();
  Object.assign(manifest, { overrides: {}, resolutions: {}, bundledDependencies: [], bundleDependencies: false });
  assert.deepEqual(checkManifest(manifest), []);
});

test('approved profile-specific development tools keep their reviewed declaration', () => {
  const manifest = {
    name: '@ten98/ui', type: 'module', engines: { node: '>=24.0.0 <25' },
    devDependencies: { ...campaign().devDependencies, '@playwright/test': '^1.64.1', '@ten98/runtime': 'file:vendor/ten98-runtime-0.1.7.tgz', react: '19.2.8', 'react-dom': '19.2.8' },
    peerDependencies: { react: '^18.3.0 || ^19.0.0', 'react-dom': '^18.3.0 || ^19.0.0' },
    scripts: campaign().scripts,
  };
  assert.deepEqual(checkManifest(manifest), []);
  manifest.devDependencies['@playwright/test'] = '*';
  assert.match(checkManifest(manifest).join('\n'), /devDependencies.@playwright\/test/);
  delete manifest.devDependencies['@playwright/test'];
  assert.match(checkManifest(manifest).join('\n'), /devDependencies.@playwright\/test/);
});

test('test and build gates must execute first and propagate architecture failure', () => {
  for (const script of [
    'echo "npm run check:architecture" && node --test',
    'node --test # npm run check:architecture',
    'npm run check:architecture || node --test',
    'npm run check:architecture && node --test || true',
    'npm run check:architecture; node --test',
    'npm run check:architecture & node --test',
    'npm run check:architecture\nnode --test',
    'node --test && npm run check:architecture',
  ]) {
    const manifest = campaign(); manifest.scripts.test = script;
    assert.match(checkManifest(manifest).join('\n'), /scripts.test must run/, script);
  }
  const prehookOnly = campaign();
  prehookOnly.scripts.test = 'node --test'; prehookOnly.scripts.pretest = 'npm run check:architecture';
  assert.match(checkManifest(prehookOnly).join('\n'), /scripts.test must run/);
  for (const prefix of ['npm run', 'pnpm', 'pnpm run']) {
    const manifest = campaign(); manifest.scripts.test = `${prefix} check:architecture && node --test`;
    assert.deepEqual(checkManifest(manifest), []);
  }
});

test('architecture detects actual drift without consulting the contract for expected values', () => {
  for (const [change, expected] of [
    [m => { m.dependencies.react = '20.0.0'; }, /dependencies.react/],
    [m => { m.devDependencies.typescript = '^7.0.2'; }, /devDependencies.typescript/],
    [m => { m.engines.node = '>=22.0.0'; }, /engines.node/],
    [m => { m.name = 'unknown-framework'; }, /Unknown architecture profile/],
    [m => { m.name = 'constructor'; }, /Unknown architecture profile/],
    [m => { m.dependencies.express = '5.0.0'; }, /Unapproved runtime dependency express/],
    [m => { m.optionalDependencies = { express: '5.0.0' }; }, /optional runtime dependency express/],
    [m => { m.peerDependencies = { express: '5.0.0' }; }, /Unapproved peer dependency express/],
    [m => { delete m.dependencies['@ten98/runtime']; }, /dependencies.@ten98\/runtime/],
    [m => { m.dependencies['@ten98/ui'] = 'file:vendor/ten98-ui-0.3.10.tgz'; }, /dependencies.@ten98\/ui/],
    [m => { m.scripts.test = 'node --test'; }, /scripts.test must run/],
    [m => { delete m.scripts['check:architecture']; }, /scripts.check:architecture/],
    [m => { m.scripts['check:architecture'] = 'node check.mjs .'; }, /scripts.check:architecture/],
  ]) {
    const manifest = campaign(); change(manifest);
    assert.match(checkManifest(manifest).join('\n'), expected);
  }
});

test('CLI checks the compiler-backed runtime and returns failure for any drift', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'ten98-architecture-'));
  try {
    const manifest = { name: '@ten98/runtime', type: 'module', engines: { node: '>=24.0.0 <25' }, dependencies: {}, scripts: { 'check:architecture': 'node check.mjs .', test: 'npm run check:architecture && node --test' } }, file = join(temporary, 'package.json');
    writeFileSync(file, JSON.stringify(manifest));
    const script = fileURLToPath(new URL('../check.mjs', import.meta.url));
    const actual = fileURLToPath(new URL('..', import.meta.url));
    let result = spawnSync(process.execPath, [script, actual, actual], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout.split('architecture declarations match').length - 1, 2);
    manifest.dependencies.express = '5.0.0'; writeFileSync(file, JSON.stringify(manifest));
    result = spawnSync(process.execPath, [script, temporary], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(result.status, 1); assert.match(result.stderr, /Unapproved runtime dependency express/);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});

test('real suite manifests match the shared contract after consumer wiring', { skip: process.env.TEN98_CHECK_REAL_BASELINES !== '1' }, () => {
  const repos = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  for (const app of ['ten98-code-system', 'ten98-design-system', 'ten98-campaign', 'ten98-discover', 'ten98-io']) {
    const file = join(repos, app, 'package.json');
    assert.equal(existsSync(file), true, file);
    assert.deepEqual(checkManifest(JSON.parse(readFileSync(file, 'utf8'))), [], file);
  }
});

test('checker can be imported by a stdin module without running its CLI', () => {
  const script = pathToFileURL(fileURLToPath(new URL('../check.mjs', import.meta.url))).href;
  const result = spawnSync(process.execPath, ['--input-type=module', '-'], { input: `import { checkManifest } from ${JSON.stringify(script)}; if (!checkManifest({}).length) throw Error('missing profile must fail');`, encoding: 'utf8', timeout: 10_000 });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout, '');
});
