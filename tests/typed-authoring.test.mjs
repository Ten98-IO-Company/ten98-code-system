import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import * as runtime from '../index.mjs';

test('generated public entrypoint retains every frozen runtime export', () => {
  assert.deepEqual(Object.keys(runtime).sort(), ['createMigrationLedger', 'mayGrantWorkspaceRole', 'mayManageWorkspaceMember', 'normalizeClientAddress', 'oidcEndpoint', 'openRouterFetch', 'parseTrustedProxies', 'readResponseText', 'resolveClientAddress', 'workspaceRoles', 'readResponseBytes', 'readCapability', 'signCapability', 'readJsonBody', 'appOrigin', 'clientLimitKey', 'SES_REGIONS', 'classifyEmailFeedback', 'deriveAwsV4SigningKey', 'sendSesEmail', 'sesOrigin', 'signAwsV4Request', 'verifySnsMessage'].sort());
});

test('actual compiler rejects an implementation type error and preserves last good output', () => {
  const root = fileURLToPath(new URL('..', import.meta.url));
  // work/ is an ignored artifact directory inside the package, so node_modules types still resolve.
  mkdirSync(join(root, 'work'), { recursive: true });
  const temporary = mkdtempSync(join(root, 'work', '.typed-authoring-'));
  const source = readFileSync(new URL('../src/index.mts', import.meta.url), 'utf8');
  const compiler = join(root, 'node_modules/typescript/bin/tsc');
  const hash = path => createHash('sha256').update(readFileSync(path)).digest('hex');
  const compile = () => spawnSync(process.execPath, [compiler, '--project', join(temporary, 'tsconfig.json'), '--pretty', 'false'], { encoding: 'utf8', timeout: 10000, windowsHide: true });
  try {
    mkdirSync(join(temporary, 'src'));
    writeFileSync(join(temporary, 'tsconfig.json'), readFileSync(new URL('../tsconfig.json', import.meta.url)));
    const implementation = join(temporary, 'src/index.mts');
    writeFileSync(implementation, source);
    writeFileSync(join(temporary, 'src/database-policy.mts'), readFileSync(new URL('../src/database-policy.mts', import.meta.url)));
    writeFileSync(join(temporary, 'src/migration-ledger.mts'), readFileSync(new URL('../src/migration-ledger.mts', import.meta.url)));
    for (const module of ['client-address', 'ses-email', 'sns-notification', 'email-feedback', 'capability-token', 'json-body']) writeFileSync(join(temporary, `src/${module}.mts`), readFileSync(new URL(`../src/${module}.mts`, import.meta.url)));
    let result = compile(); assert.equal(result.status, 0, result.stdout + result.stderr);
    const outputs = ['index.mjs', 'index.d.mts'].map(name => join(temporary, name));
    const before = outputs.map(hash);
    writeFileSync(implementation, source + '\nconst invalidImplementationValue: number = "must fail strict checking";\n');
    result = compile(); assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stdout + result.stderr, /TS2322/);
    assert.deepEqual(outputs.map(hash), before);
  } finally { rmSync(temporary, { recursive: true, force: true }); }
});
