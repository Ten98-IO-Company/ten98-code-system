import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { BOOTSTRAP_TOKEN_FILE, bootstrapTokenMatches, isValidBootstrapToken, loadBootstrapToken } from '../index.mjs';

const withDir = (run: (dir: string) => void) => { const dir = mkdtempSync(join(tmpdir(), 'ten98-bootstrap-')); try { run(dir); } finally { rmSync(dir, { recursive: true, force: true }); } };
const invalidToken = (error: unknown) => (error as { code?: string }).code === 'BOOTSTRAP_TOKEN_INVALID';
const valid = 'a'.repeat(32);

test('the token rule is 32 to 512 characters without whitespace', () => {
  for (const value of [valid, 'x'.repeat(512), 'Ab0-_.~!'.repeat(4)]) assert.equal(isValidBootstrapToken(value), true, value);
  for (const value of ['a'.repeat(31), 'a'.repeat(513), `${valid} `, `a\tb${valid}`, `${valid}\n`, undefined, 32, null]) assert.equal(isValidBootstrapToken(value), false, String(value));
});

test('a configured token wins; an invalid one is refused, never replaced', () => withDir(dir => {
  assert.deepEqual(loadBootstrapToken(dir, valid), { token: valid, source: 'environment' });
  assert.throws(() => loadBootstrapToken(dir, 'short'), invalidToken);
  assert.throws(() => loadBootstrapToken(dir, `${valid} spaced`), invalidToken);
}));

test('without a configured token one is generated once into the data directory and then reused', () => withDir(dir => {
  const file = join(dir, BOOTSTRAP_TOKEN_FILE);
  const first = loadBootstrapToken(dir);
  assert.equal(first.source, 'generated');
  assert.equal(first.path, file);
  assert.equal(isValidBootstrapToken(first.token), true);
  assert.equal(readFileSync(file, 'utf8'), first.token);
  if (process.platform !== 'win32') assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(loadBootstrapToken(dir), { token: first.token, source: 'file', path: file });
  // A saved file that breaks the rule is reported, not overwritten.
  writeFileSync(file, 'tampered');
  assert.throws(() => loadBootstrapToken(dir), invalidToken);
  assert.equal(readFileSync(file, 'utf8'), 'tampered');
}));

test('submitted tokens are compared in constant time and only an exact valid match passes', () => {
  assert.equal(bootstrapTokenMatches(valid, valid), true);
  for (const supplied of ['a'.repeat(33), 'b'.repeat(32), '', 'a'.repeat(31), 'a'.repeat(600), undefined, 42]) assert.equal(bootstrapTokenMatches(valid, supplied), false, String(supplied));
  assert.equal(bootstrapTokenMatches('short', 'short'), false);
});
