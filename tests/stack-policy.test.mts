import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { checkDeployment, checkManifest, driftReport, resolveProfile } from '../check.mjs';
import type { PackageManifest } from '../check.mjs';

type StringMap = Record<string, string>;
type AppManifest = PackageManifest & { dependencies: StringMap; devDependencies: StringMap };

// Independent fixtures: expected values are written here, not read from architecture.json.
const books = (): AppManifest => ({
  name: 'ten98-books', type: 'module', packageManager: 'pnpm@11.19.0', engines: { node: '>=24.22.1 <25' },
  dependencies: { '@tanstack/react-router': '1.170.42', '@tanstack/react-start': '1.168.61', '@ten98/runtime': 'file:vendor/ten98-runtime-0.26.0.tgz', '@ten98/ui': 'file:vendor/ten98-ui-0.36.5.tgz', 'better-auth': '1.7.7', 'drizzle-orm': '0.45.2', nodemailer: '10.1.4', pg: '8.23.0', 'pg-boss': '12.37.1', react: '19.2.8', 'react-dom': '19.2.8', zod: '4.6.6' },
  devDependencies: { '@types/node': '24.10.1', '@types/pg': '8.15.6', '@types/react': '19.2.2', '@types/react-dom': '19.2.2', '@vitejs/plugin-react': '6.1.1', nitro: '3.0.260903-beta', typescript: '7.0.2', vite: '8.3.4' },
  scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'pnpm check:architecture && node --test', build: 'pnpm check:architecture && vite build' },
});
const campaign = (): AppManifest => ({
  name: 'ten98-campaign', type: 'module', engines: { node: '>=24.22.1 <25' },
  dependencies: { '@ten98/ui': 'file:vendor/ten98-ui-0.5.2.tgz', '@ten98/runtime': 'file:vendor/ten98-runtime-0.26.0.tgz', 'drizzle-orm': '0.45.2', 'openid-client': '6.8.8', pg: '8.23.0', 'qrcode-generator': '2.0.4', react: '19.2.8', 'react-dom': '19.2.8' },
  devDependencies: { '@types/node': '24.10.1', '@types/pg': '8.15.6', '@types/react': '19.2.2', '@types/react-dom': '19.2.2', typescript: '7.0.2', vite: '8.3.4' },
  scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'npm run check:architecture && node --test', build: 'npm run check:architecture && vite build' },
});

const temporary = (files: StringMap): string => {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-stack-'));
  for (const [name, content] of Object.entries(files)) { mkdirSync(dirname(join(directory, name)), { recursive: true }); writeFileSync(join(directory, name), content); }
  return directory;
};

test('packageManager must be pnpm 11.19.0 unless an open transition covers the app', () => {
  assert.deepEqual(checkManifest(books()), []);
  for (const value of [undefined, 'npm@10.9.0', 'pnpm@10.0.0', 'pnpm@11.19.0+sha512.abc']) {
    const manifest = books(); manifest.packageManager = value;
    assert.match(checkManifest(manifest).join('\n'), /packageManager: expected pnpm@11\.19\.0/, String(value));
  }
  // Campaign still installs with npm under its recorded transition.
  assert.deepEqual(checkManifest(campaign()), []);
});

test('a second database driver is refused by name, in any dependency section', () => {
  for (const change of [
    (m: AppManifest) => { m.dependencies.postgres = '3.4.7'; },
    (m: AppManifest) => { m.devDependencies['better-sqlite3'] = '12.4.1'; },
    (m: AppManifest) => { m.optionalDependencies = { '@neondatabase/serverless': '1.0.2' }; },
    (m: AppManifest) => { m.dependencies.kysely = '0.28.8'; },
  ]) {
    const manifest = books(); change(manifest);
    assert.match(checkManifest(manifest).join('\n'), /Second database driver/);
  }
});

test('apps share one stack; a transition waives only its named missing libraries', () => {
  // Books declares nothing of its own: its whole dependency set is the shared app stack.
  const manifest = books(); delete manifest.dependencies.zod;
  assert.match(checkManifest(manifest).join('\n'), /dependencies\.zod: expected 4\.6\.6/);
  // Campaign may lack zod during its transition, but a declared zod must still be the shared version.
  const early = campaign(); early.dependencies.zod = '4.0.0';
  assert.match(checkManifest(early).join('\n'), /dependencies\.zod: expected 4\.6\.6/);
  early.dependencies.zod = '4.6.6';
  assert.deepEqual(checkManifest(early), []);
  // The transition does not waive the rest of the stack.
  const drifted = campaign(); drifted.dependencies['drizzle-orm'] = '0.44.0';
  assert.match(checkManifest(drifted).join('\n'), /dependencies\.drizzle-orm/);
});

test('the discover profile is ten98-discover and still accepts its current package name', () => {
  assert.equal(resolveProfile('ten98-monitor')?.name, 'ten98-discover');
  assert.equal(resolveProfile('ten98-discover')?.name, 'ten98-discover');
  assert.equal(resolveProfile('ten98-unknown'), undefined);
  assert.equal(resolveProfile('ten98-discover')?.profile.dependencies['ua-parser-js'], '1.0.41');
  assert.equal(resolveProfile('ten98-discover')?.profile.dependencies['pg-boss'], '12.37.1');
});

test('Dockerfile stages use the slim base image and compose runs PostgreSQL 18', () => {
  const slim = 'node:24.22.1-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205';
  const cases: [StringMap, RegExp | null][] = [
    [{ Dockerfile: `FROM ${slim} AS build\nRUN true\nFROM build AS test\nFROM node:24.22.1-slim\n` }, null],
    [{ Dockerfile: 'FROM node:24.22.1-alpine AS build\n' }, /base image node:24\.22\.1-alpine must be node:24\.22\.1-slim/],
    [{ Dockerfile: 'FROM --platform=linux/amd64 node:24-slim\n' }, /base image node:24-slim/],
    [{ 'compose.yaml': 'services:\n  postgres:\n    image: postgres:18@sha256:1267c7e692de235fda2a50dbcdbcbca4672ea6a0298576a6bd9d07cafc319b32\n' }, null],
    [{ 'compose.yaml': 'services:\n  postgres:\n    image: "postgres:18.1-trixie"\n' }, null],
    [{ 'compose.yaml': 'services:\n  postgres:\n    image: postgres:16-alpine\n' }, /PostgreSQL image postgres:16-alpine must be major 18/],
    [{ 'docker-compose.yml': 'services:\n  db:\n    image: postgres\n' }, /PostgreSQL image postgres must be major 18/],
  ];
  for (const [files, expected] of cases) {
    const directory = temporary(files);
    try {
      const errors = checkDeployment(directory, 'ten98-books').join('\n');
      if (expected) assert.match(errors, expected); else assert.equal(errors, '');
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
  // Campaign's alpine image is covered by its base-image transition; its PostgreSQL image is not.
  const directory = temporary({ Dockerfile: 'FROM node:24.22.1-alpine\n', 'compose.yaml': 'services:\n  db:\n    image: postgres:15\n' });
  try { assert.deepEqual(checkDeployment(directory, 'ten98-campaign'), ['compose.yaml: PostgreSQL image postgres:15 must be major 18 (postgres:18).']); }
  finally { rmSync(directory, { recursive: true, force: true }); }
});

test('check.mjs refuses a raw statement outside the allowlist and accepts it once allowlisted', () => {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-raw-statements-'));
  try {
    const checker = join(directory, 'checker');
    mkdirSync(checker);
    for (const name of ['check.mjs', 'database-policy.mjs']) writeFileSync(join(checker, name), readFileSync(new URL(`../${name}`, import.meta.url)));
    const contract = JSON.parse(readFileSync(new URL('../architecture.json', import.meta.url), 'utf8'));
    // A minimal non-app profile so the fixture needs no installed compiler or bundler.
    contract.profiles['fixture-data'] = { dependencies: {}, devDependencies: {}, sharedDependencies: [], sharedDevDependencies: [], peerDependencies: {}, checkScripts: ['test'],
      data: { roots: ['src'], baseline: 'raw-statements.json' }, database: { engine: 'postgresql' } };
    writeFileSync(join(checker, 'architecture.json'), JSON.stringify(contract));
    const app = join(directory, 'app');
    mkdirSync(join(app, 'src/server'), { recursive: true });
    writeFileSync(join(app, 'package.json'), JSON.stringify({ name: 'fixture-data', type: 'module', packageManager: 'pnpm@11.19.0', engines: { node: '>=24.22.1 <25' },
      scripts: { 'check:architecture': 'node node_modules/@ten98/runtime/check.mjs .', test: 'pnpm check:architecture && node --test' } }));
    const source = join(app, 'src/server/report.ts');
    const run = (...args: string[]) => spawnSync(process.execPath, [join(checker, 'check.mjs'), ...args, app], { encoding: 'utf8', timeout: 10_000, windowsHide: true });

    writeFileSync(source, "import { db } from './db.ts';\nexport const rows = await db.select().from(ledger).where(eq(ledger.companyId, id));\n");
    assert.equal(run().status, 0, run().stderr);
    for (const statement of ["await pool.query('SELECT 1')", 'await client.query<{ id: string }>(`SELECT id FROM t`)', 'await db.execute(sql`SELECT 1`)', "sql.raw('now()')"]) {
      writeFileSync(source, `${statement};\n`);
      const refused = run();
      assert.equal(refused.status, 1, statement);
      assert.match(refused.stderr, /src\/server\/report\.ts: raw statement count 1 exceeds the allowlist \(0 in raw-statements\.json\)/, statement);
    }
    writeFileSync(join(app, 'raw-statements.json'), JSON.stringify({ 'src/server/report.ts': 1 }));
    assert.equal(run().status, 0, run().stderr);
    // A second statement in the same file exceeds the recorded count.
    writeFileSync(source, "await pool.query('SELECT 1');\nawait pool.query('SELECT 2');\n");
    assert.match(run().stderr, /raw statement count 2 exceeds the allowlist \(1 in raw-statements\.json\)/);
    // The updater refuses a rise and only lowers.
    assert.equal(run('--update-raw-statement-baseline').status, 1);
    writeFileSync(source, 'export {};\n');
    assert.equal(run('--update-raw-statement-baseline').status, 0);
    assert.deepEqual(JSON.parse(readFileSync(join(app, 'raw-statements.json'), 'utf8')), {});
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('the drift report lists each consumer as current or behind without failing', () => {
  const current = temporary({ 'package.json': JSON.stringify(books()) });
  const behind = campaign(); behind.dependencies['@ten98/runtime'] = 'file:vendor/ten98-runtime-0.10.0.tgz';
  const old = temporary({ 'package.json': JSON.stringify(behind) });
  try {
    const rows = driftReport([current, old]);
    assert.deepEqual(rows.map(row => [row.name, row.status]), [['ten98-books', 'current'], ['ten98-campaign', 'behind']]);
    assert.match(rows[1].problems.join('\n'), /ten98-runtime-0\.10\.0/);
  } finally { for (const directory of [current, old]) rmSync(directory, { recursive: true, force: true }); }
});
