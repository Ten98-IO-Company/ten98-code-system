import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { checkManifest } from '../check.mjs';

// Independent fixture: do not derive the expected application from architecture.json.
const campaign = () => ({
  name: 'ten98-campaign', type: 'module', engines: { node: '>=24.0.0 <25' },
  dependencies: { '@ten98/ui': 'file:vendor/ten98-ui-0.3.19.tgz', '@ten98/runtime': 'file:vendor/ten98-runtime-0.1.3.tgz', 'openid-client': '6.8.8', 'qrcode-generator': '2.0.4', react: '19.2.8', 'react-dom': '19.2.8' },
  devDependencies: { '@types/react': '19.2.2', '@types/react-dom': '19.2.2', typescript: '7.0.2', vite: '8.3.4' },
  scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'npm run check:architecture && node --test', build: 'npm run check:architecture && vite build' },
});

test('architecture accepts independent manifests with reviewed tools and mandatory gates', () => {
  assert.deepEqual(checkManifest(campaign()), []);
  const runtime = { name: '@ten98/runtime', type: 'module', engines: { node: '>=24.0.0 <25' }, scripts: { 'check:architecture': 'node check.mjs .', test: 'npm run check:architecture && node --test' } };
  assert.deepEqual(checkManifest(runtime), []);
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
    devDependencies: { ...campaign().devDependencies, '@playwright/test': '^1.64.1', '@ten98/runtime': 'file:vendor/ten98-runtime-0.1.3.tgz', react: '19.2.8', 'react-dom': '19.2.8' },
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

test('CLI checks multiple synthetic directories and returns failure for any drift', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'ten98-architecture-'));
  try {
    const manifest = campaign(), file = join(temporary, 'package.json');
    writeFileSync(file, JSON.stringify(manifest));
    const script = fileURLToPath(new URL('../check.mjs', import.meta.url));
    let result = spawnSync(process.execPath, [script, temporary, temporary], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(result.status, 0, result.stderr); assert.equal(result.stdout.split('architecture declarations match').length - 1, 2);
    manifest.dependencies.express = '5.0.0'; writeFileSync(file, JSON.stringify(manifest));
    result = spawnSync(process.execPath, [script, temporary], { encoding: 'utf8', timeout: 10_000 });
    assert.equal(result.status, 1); assert.match(result.stderr, /Unapproved runtime dependency express/);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});

test('real suite manifests match the shared contract after consumer wiring', { skip: process.env.TEN98_CHECK_REAL_BASELINES !== '1' }, () => {
  const repos = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
  for (const app of ['ten98-code-system', 'ten98-design-system', 'ten98-campaign', 'ten98-discover']) {
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
