import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { z } from 'zod';
import { loadConfig, readEnvironment, readSecret } from '../config.mjs';

const directory = mkdtempSync(join(tmpdir(), 'ten98-config-'));
test.after(() => rmSync(directory, { recursive: true, force: true }));
const file = (name: string, contents: string) => { const path = join(directory, name); writeFileSync(path, contents); return path; };
const secret = 'f'.repeat(48);
const invalid = (keys: string[], message: RegExp) => (error: unknown) => {
  const { code, keys: reported, message: text } = error as { code: string; keys: string[]; message: string };
  assert.equal(code, 'CONFIG_INVALID');
  assert.deepEqual(reported, keys);
  assert.match(text, message);
  return true;
};

test('readEnvironment returns NAME, or the trimmed contents of NAME_FILE, and undefined when neither is set', () => {
  assert.equal(readEnvironment('API_KEY', { API_KEY: 'direct' }), 'direct');
  assert.equal(readEnvironment('API_KEY', { API_KEY_FILE: file('api-key', '  from-file\n') }), 'from-file');
  assert.equal(readEnvironment('API_KEY', {}), undefined);
  // As in discover and books, an empty plain value comes back as '' (callers' `??` defaults do not apply), but it
  // never conflicts with a file, and an empty NAME_FILE is unset.
  assert.equal(readEnvironment('API_KEY', { API_KEY: '' }), '');
  assert.equal(readEnvironment('API_KEY', { API_KEY_FILE: '' }), undefined);
  assert.equal(readEnvironment('API_KEY', { API_KEY: '', API_KEY_FILE: file('api-key-2', 'file-wins') }), 'file-wins');
  assert.equal(readEnvironment('API_KEY', { API_KEY: 'direct', API_KEY_FILE: '' }), 'direct');
});

test('readEnvironment trims a file\'s contents but returns a plain value exactly as set', () => {
  assert.equal(readEnvironment('GREETING', { GREETING: '  padded value \n' }), '  padded value \n');
  assert.equal(readEnvironment('GREETING', { GREETING_FILE: file('greeting', '  padded value \n') }), 'padded value');
});

test('readEnvironment reads discover\'s AUTH_SECRET_FILE, DATABASE_URL_FILE and CREDENTIAL_KEYS_FILE', () => {
  for (const name of ['AUTH_SECRET', 'DATABASE_URL', 'CREDENTIAL_KEYS']) {
    assert.equal(readEnvironment(name, { [`${name}_FILE`]: file(name.toLowerCase(), `${name}-value\n`) }), `${name}-value`);
  }
});

test('readEnvironment refuses NAME and NAME_FILE set together', () => {
  assert.throws(() => readEnvironment('API_KEY', { API_KEY: 'direct', API_KEY_FILE: file('both', 'other') }), invalid(['API_KEY'], /^Set only API_KEY or API_KEY_FILE$/));
});

test('readEnvironment reports a missing file by key and error code, without the path', () => {
  const path = join(directory, 'missing-secret-path');
  assert.throws(() => readEnvironment('API_KEY', { API_KEY_FILE: path }), (error: unknown) => {
    invalid(['API_KEY'], /^API_KEY_FILE names a file that cannot be read \(ENOENT\)$/)(error);
    assert.doesNotMatch((error as Error).message, /missing-secret-path/);
    return true;
  });
  assert.throws(() => readEnvironment('API_KEY', { API_KEY_FILE: directory }), invalid(['API_KEY'], /\(EISDIR\)$/));
});

test('readSecret refuses an unset or short secret without echoing it, and honours minimumLength', () => {
  assert.equal(readSecret('AUTH_SECRET', { env: { AUTH_SECRET: secret } }), secret);
  assert.throws(() => readSecret('AUTH_SECRET', { env: {} }), invalid(['AUTH_SECRET'], /^AUTH_SECRET must contain at least 32 characters$/));
  assert.throws(() => readSecret('AUTH_SECRET', { env: { AUTH_SECRET: '' } }), invalid(['AUTH_SECRET'], /^AUTH_SECRET must contain at least 32 characters$/));
  assert.throws(() => readSecret('AUTH_SECRET', { env: { AUTH_SECRET: 'short-secret-value' } }), (error: unknown) => {
    invalid(['AUTH_SECRET'], /at least 32 characters/)(error);
    assert.doesNotMatch((error as Error).message, /short-secret-value/);
    return true;
  });
  assert.equal(readSecret('PIN', { minimumLength: 4, env: { PIN: '1234' } }), '1234');
  assert.throws(() => readSecret('PIN', { minimumLength: 8, env: { PIN: '1234' } }), invalid(['PIN'], /at least 8 characters/));
  assert.throws(() => readSecret('PIN', { minimumLength: 0, env: { PIN: '1234' } }), RangeError);
});

// Campaign gap 16: campaign generates its session secret into DATA_DIR/session-secret. Pointing SESSION_SECRET_FILE at
// that file (or at a Compose secret) replaces the generator and keeps existing sessions valid.
test('readSecret reads campaign\'s saved DATA_DIR/session-secret through SESSION_SECRET_FILE', () => {
  const saved = 'Qm9vdHN0cmFwcGVkLXNlc3Npb24tc2VjcmV0LWZyb20tY2FtcGFpZ24tMDE';
  const path = file('session-secret', `${saved}\n`);
  assert.equal(readSecret('SESSION_SECRET', { env: { SESSION_SECRET_FILE: path } }), saved);
  assert.throws(() => readSecret('SESSION_SECRET', { env: { SESSION_SECRET: secret, SESSION_SECRET_FILE: path } }), invalid(['SESSION_SECRET'], /Set only SESSION_SECRET or SESSION_SECRET_FILE/));
  const truncated = file('session-secret-truncated', 'truncated-session\n');
  assert.throws(() => readSecret('SESSION_SECRET', { env: { SESSION_SECRET_FILE: truncated } }), (error: unknown) => {
    invalid(['SESSION_SECRET'], /^SESSION_SECRET must contain at least 32 characters$/)(error);
    assert.doesNotMatch((error as Error).message, /truncated-session/);
    return true;
  });
});

const schema = z.object({
  DATABASE_URL: z.url({ protocol: /^postgres(ql)?$/ }),
  AUTH_SECRET: z.string().min(32),
  PORT: z.coerce.number().int().default(3000),
  MODE: z.enum(['web', 'worker']).optional(),
});

test('loadConfig reads each schema key through readEnvironment, files included, and applies defaults', () => {
  const config = loadConfig(schema, { DATABASE_URL: 'postgres://app@db/app', AUTH_SECRET_FILE: file('auth-secret', `${secret}\n`), UNRELATED: 'x' });
  assert.deepEqual(config, { DATABASE_URL: 'postgres://app@db/app', AUTH_SECRET: secret, PORT: 3000 });
  const typed: number = config.PORT;
  assert.equal(typed, 3000);
  assert.equal(loadConfig(schema, { DATABASE_URL: 'postgres://app@db/app', AUTH_SECRET: secret, PORT: '8080', MODE: 'worker' }).PORT, 8080);
  // An empty value is left out of the input, so the default applies rather than coercing '' to 0.
  assert.equal(loadConfig(schema, { DATABASE_URL: 'postgres://app@db/app', AUTH_SECRET: secret, PORT: '' }).PORT, 3000);
});

test('loadConfig names every failing key in one error and never includes a value', () => {
  const env = { DATABASE_URL: 'mysql://root:hunter2-password@db/app', AUTH_SECRET: 'too-short-auth-secret', PORT: 'eighty', MODE: 'cron', API_KEY: 'a', API_KEY_FILE: 'b' };
  assert.throws(() => loadConfig(schema.extend({ API_KEY: z.string() }), env), (error: unknown) => {
    invalid(['API_KEY'], /^Invalid configuration: API_KEY: Set only API_KEY or API_KEY_FILE$/)(error);
    return true;
  });
  assert.throws(() => loadConfig(schema, env), (error: unknown) => {
    invalid(['DATABASE_URL', 'AUTH_SECRET', 'PORT', 'MODE'], /^Invalid configuration: DATABASE_URL: .+; AUTH_SECRET: .+; PORT: .+; MODE: .+$/)(error);
    const { message, cause } = error as Error;
    for (const value of ['hunter2-password', 'too-short-auth-secret', 'eighty', 'cron']) assert.ok(!message.includes(value), `message leaks ${value}`);
    assert.equal(cause, undefined);
    return true;
  });
});

test('loadConfig redacts values that an app\'s own refine message or a throwing transform repeats', () => {
  const echo = z.object({ TOKEN: z.string().refine(value => value.startsWith('tk_'), { error: issue => `TOKEN ${String(issue.input)} must start with tk_` }) });
  assert.throws(() => loadConfig(echo, { TOKEN: 'leaky-token-value' }), (error: unknown) => {
    invalid(['TOKEN'], /^Invalid configuration: TOKEN: TOKEN \[redacted\] must start with tk_$/)(error);
    return true;
  });
  const throwing = z.object({ ENDPOINT: z.string().transform(value => { throw new Error(`cannot use ${value}`); }) });
  assert.throws(() => loadConfig(throwing, { ENDPOINT: 'https://user:pass@internal' }), (error: unknown) => {
    invalid(['(schema)'], /^Invalid configuration: \(schema\): cannot use \[redacted\]$/)(error);
    assert.equal((error as Error).cause, undefined);
    return true;
  });
});
