import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { checkManifest, checkVendoredFloors } from '../check.mjs';

const runtime = 'file:vendor/ten98-runtime-0.1.14.tgz';
const app = ui => ({
  name: 'ten98-campaign', type: 'module', engines: { node: '>=24.0.0 <25' },
  dependencies: { '@ten98/ui': ui, '@ten98/runtime': runtime, 'openid-client': '6.8.8', 'qrcode-generator': '2.0.4', react: '19.2.8', 'react-dom': '19.2.8' },
  devDependencies: { '@types/node': '24.10.1', '@types/react': '19.2.2', '@types/react-dom': '19.2.2', typescript: '7.0.2', vite: '8.3.4' },
  scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'npm run check:architecture && node --test', build: 'npm run check:architecture && vite build' },
});
const uiErrors = ui => checkManifest(app(ui)).filter(error => error.includes('@ten98/ui'));

test('an app may pin any released UI archive at or above the floor', () => {
  for (const version of ['0.5.0', '0.5.4', '0.6.0', '1.0.0']) assert.deepEqual(uiErrors(`file:vendor/ten98-ui-${version}.tgz`), [], version);
});

test('UI pins below the floor or outside a vendored release archive are rejected', () => {
  for (const spec of [
    'file:vendor/ten98-ui-0.4.9.tgz', 'file:vendor/ten98-ui-0.3.22.tgz', '^0.5.0', 'latest', 'link:../ten98-design-system',
    'workspace:*', 'file:../ten98-design-system', 'file:vendor/ten98-ui-0.5.tgz', 'file:vendor/other-ui-0.5.0.tgz', undefined,
  ]) assert.equal(uiErrors(spec).length, 1, String(spec));
});

test('the pinned archive must exist and be the only vendored UI release', () => {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-floors-'));
  try {
    const manifest = app('file:vendor/ten98-ui-0.5.2.tgz');
    assert.match(checkVendoredFloors(directory, manifest).join('\n'), /pinned archive vendor\/ten98-ui-0\.5\.2\.tgz is missing/u);
    mkdirSync(join(directory, 'vendor'));
    writeFileSync(join(directory, 'vendor', 'ten98-ui-0.5.2.tgz'), '');
    assert.deepEqual(checkVendoredFloors(directory, manifest), []);
    writeFileSync(join(directory, 'vendor', 'ten98-ui-0.5.0.tgz'), '');
    assert.match(checkVendoredFloors(directory, manifest).join('\n'), /vendor holds 2 archives/u);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
