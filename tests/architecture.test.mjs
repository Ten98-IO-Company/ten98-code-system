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
  dependencies: { '@ten98/ui': 'file:vendor/ten98-ui-0.3.16.tgz', '@ten98/runtime': 'file:vendor/ten98-runtime-0.1.0.tgz', 'openid-client': '6.8.8', 'qrcode-generator': '2.0.4', react: '19.2.8', 'react-dom': '19.2.8' },
  devDependencies: { '@types/react': '19.2.2', '@types/react-dom': '19.2.2', typescript: '7.0.2', vite: '8.3.4', 'app-specific-tool': '1.0.0' },
  scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'npm run check:architecture && node --test', build: 'npm run check:architecture && vite build' },
});

test('architecture accepts independent manifest fixtures and keeps developer tools app-specific', () => {
  assert.deepEqual(checkManifest(campaign()), []);
  const runtime = { name: '@ten98/runtime', type: 'module', engines: { node: '>=24.0.0 <25' }, scripts: { 'check:architecture': 'node check.mjs .', test: 'node --test', pretest: 'npm run check:architecture' } };
  assert.deepEqual(checkManifest(runtime), []);
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
