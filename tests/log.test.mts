import assert from 'node:assert/strict';
import test from 'node:test';
import { createLogger, requestId } from '../log.mjs';
import type { LoggerOptions } from '../log.mjs';

function capture(options: Omit<LoggerOptions, 'write'> = { service: 'discover' }) {
  const lines: string[] = [];
  const log = createLogger({ ...options, write: line => { lines.push(line); } });
  const records = (): Record<string, unknown>[] => lines.map(line => JSON.parse(line) as Record<string, unknown>);
  return { log, lines, records };
}

test('each call writes one JSON line with time, level, service, message, request id and fields in that order', () => {
  const { log, lines, records } = capture();
  log.info('report queued', { requestId: 'req-12345678', reportId: 7 });
  assert.equal(lines.length, 1);
  assert.match(lines[0]!, /^\{.*\}\n$/u);
  const [line] = records();
  assert.deepEqual(Object.keys(line!), ['time', 'level', 'service', 'message', 'requestId', 'reportId']);
  assert.equal(new Date(line!.time as string).toISOString(), line!.time);
  assert.deepEqual({ ...line, time: undefined }, { time: undefined, level: 'info', service: 'discover', message: 'report queued', requestId: 'req-12345678', reportId: 7 });
});

test('a field cannot replace the core names, and a line without a request id omits it', () => {
  const { log, records } = capture();
  log.warn('slow', { level: 'debug', service: 'other', message: 'spoofed', time: 'never', ms: 900 });
  assert.deepEqual({ ...records()[0], time: undefined }, { time: undefined, level: 'warn', service: 'discover', message: 'slow', ms: 900 });
});

test('the level option drops less severe calls and defaults to info', () => {
  const quiet = capture({ service: 's', level: 'warn' });
  quiet.log.debug('d'); quiet.log.info('i'); quiet.log.warn('w'); quiet.log.error('e');
  assert.deepEqual(quiet.records().map(line => line.level), ['warn', 'error']);
  const standard = capture();
  standard.log.debug('d'); standard.log.info('i');
  assert.deepEqual(standard.records().map(line => line.message), ['i']);
  const verbose = capture({ service: 's', level: 'debug' });
  verbose.log.debug('d');
  assert.equal(verbose.lines.length, 1);
  assert.throws(() => createLogger({ service: 's', level: 'verbose' as never }), TypeError);
});

test('child loggers add their fields to every line, nest, and yield to call fields', () => {
  const { log, records } = capture();
  const request = log.child({ requestId: 'abcdefgh', route: '/reports' });
  request.child({ workspaceId: 'w1' }).info('read', { route: '/reports/7' });
  request.info('done');
  log.info('bare');
  assert.deepEqual(records().map(line => ({ ...line, time: undefined })), [
    { time: undefined, level: 'info', service: 'discover', message: 'read', requestId: 'abcdefgh', route: '/reports/7', workspaceId: 'w1' },
    { time: undefined, level: 'info', service: 'discover', message: 'done', requestId: 'abcdefgh', route: '/reports' },
    { time: undefined, level: 'info', service: 'discover', message: 'bare' },
  ]);
});

test('an Error is written as its name, message and stack, also when nested', () => {
  const { log, records } = capture();
  const failure = new RangeError('out of range');
  log.error('failed', { error: failure, context: { cause: new Error('inner') } });
  const [line] = records();
  assert.deepEqual(line!.error, { name: 'RangeError', message: 'out of range', stack: failure.stack });
  assert.equal((line!.context as { cause: { message: string } }).cause.message, 'inner');
});

test('a caught Error passed to error() on a child logger, or bound by child(), keeps its name, message and stack', () => {
  const { log, records } = capture();
  const caught = new TypeError('bad input');
  log.child({ requestId: 'abcdefgh' }).error('Request failed.', { error: caught });
  log.child({ error: caught }).error('Request failed.');
  const expected = { name: 'TypeError', message: 'bad input', stack: caught.stack };
  assert.match(caught.stack!, /^TypeError: bad input\n\s+at /u);
  assert.deepEqual(records().map(line => ({ ...line, time: undefined })), [
    { time: undefined, level: 'error', service: 'discover', message: 'Request failed.', requestId: 'abcdefgh', error: expected },
    { time: undefined, level: 'error', service: 'discover', message: 'Request failed.', error: expected },
  ]);
});

test('secret-looking field names are redacted case-insensitively at every depth', () => {
  const { log, lines, records } = capture();
  log.info('login', {
    password: 'hunter2', clientSecret: 's1', accessToken: 't1', Authorization: 'Bearer x', 'set-cookie': 'sid=1', apiKey: 'k1',
    headers: { 'X-API-KEY': 'k2', accept: 'text/html' }, attempts: [{ token: 't2' }], user: 'ada',
  });
  assert.doesNotMatch(lines[0]!, /hunter2|s1|t1|Bearer|sid=1|k1|k2|t2/u);
  const [line] = records();
  for (const name of ['password', 'clientSecret', 'accessToken', 'Authorization', 'set-cookie', 'apiKey']) assert.equal(line![name], '[redacted]', name);
  assert.deepEqual(line!.headers, { 'X-API-KEY': '[redacted]', accept: 'text/html' });
  assert.deepEqual(line!.attempts, [{ token: '[redacted]' }]);
  assert.equal(line!.user, 'ada');
});

test('bigint fields are written as strings and a circular field does not throw', () => {
  const { log, records } = capture();
  log.info('charged', { amountMinor: 12345678901234567n });
  const circular: Record<string, unknown> = {};
  circular.self = circular;
  log.info('loop', { requestId: 'abcdefgh', circular });
  const [charged, loop] = records();
  assert.equal(charged!.amountMinor, '12345678901234567');
  assert.deepEqual({ ...loop, time: undefined }, { time: undefined, level: 'info', service: 'discover', message: 'loop', requestId: 'abcdefgh', circular: { self: '[circular]' } });
});

test('requestId keeps a valid incoming x-request-id and replaces anything else with a new UUID', () => {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
  const withId = (value?: string) => new Request('https://example.test/', value === undefined ? {} : { headers: { 'x-request-id': value } });
  for (const valid of ['abcdefgh', 'req_1.2-3', 'A'.repeat(128), '0b6d3c9e-2f5e-4b7a-9a43-1f1d6c2b8e10']) assert.equal(requestId(withId(valid)), valid);
  for (const invalid of [undefined, '', 'short', 'A'.repeat(129), 'has space1', 'line\tbreak1', 'semi;colon1', 'ünïcode123', '../../etc/x']) {
    assert.match(requestId(withId(invalid)), uuid, String(invalid));
  }
  assert.notEqual(requestId(withId()), requestId(withId()));
});

test('every common secret name is redacted, in any case and separator style (check of 9e03146)', () => {
  const { log, records } = capture();
  const names = ['pass', 'passwd', 'pwd', 'passphrase', 'auth', 'credential', 'credentials', 'session', 'sessionId', 'sid', 'jwt', 'bearer',
    'signature', 'otp', 'dsn', 'databaseUrl', 'DATABASE_URL', 'connectionString', 'connection-string', 'privateKey', 'x-api-key', 'refresh_token',
    'cvv', 'cardNumber', 'mnemonic', 'seed', 'psk', 'csrf', 'hmac', 'salt', 'clientSecret', 'accessToken', 'set-cookie', 'Authorization',
    // Deliberate: `tokens` is usually a list of tokens, and a name ending in `key` cannot tell an id key from a secret key.
    'tokens', 'primaryKey'];
  log.info('config', Object.fromEntries(names.map(name => [name, 'visible-secret'])));
  const line = records()[0]!;
  for (const name of names) assert.equal(line[name], '[redacted]', name);
  assert.doesNotMatch(JSON.stringify(line), /visible-secret/);
  // The SMTP shape the email entry builds.
  log.info('smtp', { auth: { user: 'login', pass: 'visible-secret' }, smtp: { user: 'login', pass: 'visible-secret' } });
  assert.doesNotMatch(JSON.stringify(records()[1]), /visible-secret/);
});

test('ordinary names that only contain a secret word are written as given (check of PR 138)', () => {
  const { log, records } = capture();
  const names = ['author', 'authorId', 'passed', 'bypass', 'compass', 'keyboard', 'monkey', 'sessionCount', 'tokenCount', 'otpEnabled',
    'signatureValid', 'isPrivate', 'keyset', 'keyword', 'turkey', 'hotpath', 'passengerCount', 'authenticated'];
  log.info('ordinary', Object.fromEntries(names.map(name => [name, `value-of-${name}`])));
  const line = records()[0]!;
  for (const name of names) assert.equal(line[name], `value-of-${name}`, name);
});

test('credentials embedded in a URL are removed from any string value, whatever the field is called', () => {
  const { log, records } = capture();
  log.error('connect failed postgres://app:p4ss@db.internal:5432/app', {
    target: 'postgres://app:p4ss@db.internal:5432/app', mirror: 'redis://:t0ken@cache:6379', hook: 'https://user@example.com/x',
    note: 'retrying smtp://mailer:hunter2@smtp.example.com now', error: new Error('ECONNREFUSED postgres://app:p4ss@db.internal/app'),
    // A password holding a raw @, space or / (check of PR 138): everything up to the LAST @ goes.
    atSign: 'postgres://app:S3CR@T@h/db', space: 'postgres://app:S3 CRET@h/db', slash: 'postgres://app:S3/CRET@h/db',
    plain: 'https://example.com/a@b',
  });
  const line = records()[0]!, text = JSON.stringify(line);
  for (const secret of ['p4ss', 't0ken', 'hunter2', 'user@', 'S3CR@T']) assert.doesNotMatch(text, new RegExp(secret), secret);
  assert.match(text, /postgres:\/\/\[redacted\]@db\.internal:5432\/app/);
  // A raw @ inside the authority is covered: everything to its last @ goes.
  assert.equal(line.atSign, 'postgres://[redacted]@h/db');
  // Documented limit: a raw space or / ends the authority (such a URL is already invalid), so the password is written.
  assert.equal(line.space, 'postgres://app:S3 CRET@h/db');
  assert.equal(line.slash, 'postgres://app:S3/CRET@h/db');
  // An @ in a path is not a credential.
  assert.equal(line.plain, 'https://example.com/a@b');
});

test('a long hostile string is scanned in linear time and cut to length (check of PR 138)', () => {
  const { log, records } = capture();
  const hostile = ['a'.repeat(1_000_000), 'a+.-'.repeat(250_000), 'a://'.repeat(250_000), `x${'://'.repeat(333_333)}`, `${'a@'.repeat(500_000)}`];
  const started = performance.now();
  for (const value of hostile) log.info('payload', { value });
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 1000, `five 1 MB strings took ${elapsed.toFixed(0)} ms`);
  for (const line of records()) {
    assert.ok((line.value as string).length < 8300, 'cut to length');
    assert.match(line.value as string, /…\[truncated \d+ characters\]$/u);
  }
  // A credential beyond the cut is still redacted rather than half-written.
  log.info('edge', { value: `${'x'.repeat(8180)} postgres://app:LONGSECRET@host/db` });
  assert.doesNotMatch(JSON.stringify(records().at(-1)), /LONGSECRET|LONGSEC|app:L/u);
});

test('a log call never throws: throwing getters, unserialisable values and a failing sink', () => {
  const { log, records } = capture();
  const hostile = { get boom() { throw new Error('getter'); } };
  assert.doesNotThrow(() => log.info('getter', hostile));
  assert.doesNotThrow(() => log.info('symbol id', { requestId: Symbol('x') as never }));
  assert.doesNotThrow(() => log.info('bigint id', { requestId: 10n as never }));
  assert.doesNotThrow(() => log.child(hostile).info('child of hostile'));
  const lines = records();
  assert.equal(lines[0]!.logError, 'fields could not be read');
  assert.equal(lines[0]!.message, 'getter');
  assert.equal(lines.length, 4);
  const failing = createLogger({ service: 's', write: () => { throw new Error('sink down'); } });
  assert.doesNotThrow(() => failing.error('lost'));
});

test('names fail closed: every secret name from the three checks is redacted (second check of PR 138)', () => {
  const { log, records } = capture();
  const names = ['PGPASSWORD', 'dbpassword', 'DBPASS', 'userpassword', 'sessionid', 'PHPSESSID', 'JSESSIONID', 'accesstoken', 'refreshtoken',
    'authtoken', 'clientsecret', 'privatekey', 'secretkey', 'connectionstring', 'databaseurl', 'setcookie', 'cardnumber', 'password1',
    'password2', 'key1', 'token2', 'secret2', 'apiKey2', 'TOKEN_V2', 'password_confirmation', 'passwordConfirmation', 'passwordPlain',
    'tokenValue', 'secretValue', 'clientSecretValue', 'cookieValue', 'bearerValue', 'jwtRaw', 'credentialsJson', 'secret_old', 'hmacSecretOld',
    'otpCode', 'signatureHex', 'stripeSk', 'creditCard', 'recoveryCodes', 'resetLink', 'magicLink', 'pässword', 'пароль', 'sk', 'sid'];
  log.info('config', Object.fromEntries(names.map(name => [name, 'visible-secret'])));
  const line = records()[0]!;
  for (const name of names) assert.equal(line[name], '[redacted]', name);
  assert.doesNotMatch(JSON.stringify(line), /visible-secret/);
});

test('the harmless list is exact, extendable by the app, and cannot allow a secret', () => {
  const { log, records } = capture();
  log.info('ordinary', { keywords: ['a', 'b'], footprint: 3, authority: 'x' });
  assert.deepEqual({ ...records()[0], time: undefined }, { time: undefined, level: 'info', service: 'discover', message: 'ordinary', keywords: ['a', 'b'], footprint: 3, authority: 'x' });
  // A near miss of a harmless name stays redacted: the list matches whole names only.
  log.info('near', { keywordToken: 'x', rankKeyword: 'y' });
  assert.deepEqual([records()[1]!.keywordToken, records()[1]!.rankKeyword], ['[redacted]', '[redacted]']);
  const lines: string[] = [], ranked = createLogger({ service: 's', allow: ['rankKeyword', 'rank-keyword'], write: line => { lines.push(line); } });
  ranked.info('rank', { rankKeyword: 'shoes', rank_keyword: 'boots', password: 'visible-secret' });
  assert.deepEqual([JSON.parse(lines[0]!).rankKeyword, JSON.parse(lines[0]!).rank_keyword, JSON.parse(lines[0]!).password], ['shoes', 'boots', '[redacted]']);
  for (const secret of ['password', 'apiKey', 'sessionId', 'DATABASE_URL', 'sid', 'key', 'myPasswordField', 'cookieJar', '']) {
    assert.throws(() => createLogger({ service: 's', allow: [secret] }), TypeError, secret);
  }
});

test('ordinary strings are written unchanged: stack frames, scoped package URLs and a URL before an email address', () => {
  const { log, records } = capture();
  const ordinary = {
    frame: 'at load (file:///srv/app/node_modules/@ten98/runtime/log.mjs:12:3)',
    npm: 'https://registry.npmjs.org/@ten98/ui', unpkg: 'https://unpkg.com/@ten98/ui@0.39.0/dist/x.js',
    sentence: 'see https://example.com/docs and write to me@example.org', query: 'https://example.com/?next=a@b', fragment: 'https://example.com/#me@x',
  };
  log.info('ordinary', ordinary);
  const line = records()[0]!;
  for (const [name, value] of Object.entries(ordinary)) assert.equal(line[name], value, name);
  // Userinfo alone, such as a token used as the user, is still a credential.
  log.info('userinfo', { github: 'https://ghp_abc123@github.com/org/repo', ssh: 'ssh://git@github.com/org/repo.git', boxed: new String('postgres://app:p4ss@h/db') });
  assert.deepEqual([records()[1]!.github, records()[1]!.ssh, records()[1]!.boxed], ['https://[redacted]@github.com/org/repo', 'ssh://[redacted]@github.com/org/repo.git', 'postgres://[redacted]@h/db']);
  // Far from the scheme (no 256-character bound any more).
  log.info('far', { url: `postgres://app:${'p'.repeat(600)}@h/db` });
  assert.equal(records()[2]!.url, 'postgres://[redacted]@h/db');
});

test('hostile keys and shapes stay within time, size and depth bounds', () => {
  const { log, lines, records } = capture();
  const started = performance.now();
  log.info('long key', { [`A${'B'.repeat(1_000_000)}`]: 'x' });
  log.info('huge key', { [`${'PASSWORD'.repeat(1_250_000)}`]: 'visible-secret' });
  log.info('many keys', Object.fromEntries(Array.from({ length: 2000 }, (_, i) => [`K${i}${'X'.repeat(2000)}`, i])));
  log.info('wide', Object.fromEntries(Array.from({ length: 10_000 }, (_, i) => [`f${i}`, 'v'.repeat(8192)])));
  let deep: Record<string, unknown> = { leaf: 1 };
  for (let i = 0; i < 100; i++) deep = { next: deep };
  log.info('deep', { deep });
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 2000, `took ${elapsed.toFixed(0)} ms`);
  for (const line of lines) assert.ok(line.length < 140_000, `line of ${line.length} characters`);
  assert.doesNotMatch(lines.join(''), /visible-secret/);
  const [longKey, , manyKeys, wide] = records();
  assert.ok(Object.keys(longKey!).some(key => key.length === 257 && key.endsWith('…')));
  assert.equal(manyKeys!['…'], '1800 more fields');
  assert.match(String(wide!['…']), /more fields$/u);
  assert.match(lines[4]!, /\[depth limit\]/u);
});
