import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { inspect } from 'node:util';
import { setFlagsFromString } from 'node:v8';
import { runInNewContext } from 'node:vm';
import { DrizzleQueryError, sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import { createLogger, DEFAULT_REDACT_PATHS, requestId, safeDatabaseError, SafeDatabaseError } from '../log.mjs';
import type { LoggerOptions } from '../log.mjs';

type Line = Record<string, unknown>;
function capture(options: Omit<LoggerOptions, 'write'> = { service: 'discover' }) {
  const lines: string[] = [];
  const log = createLogger({ ...options, write: line => { lines.push(line); } });
  const records = (): Line[] => lines.map(line => JSON.parse(line) as Line);
  return { log, lines, records };
}
const withoutTime = (line: Line | undefined): Line => ({ ...line, time: undefined });

test('each call writes one JSON line with time, level, service, the fields and msg', () => {
  const { log, lines, records } = capture();
  log.info('report queued', { requestId: 'req-12345678', reportId: 7 });
  assert.equal(lines.length, 1);
  assert.match(lines[0]!, /^\{.*\}\n$/u);
  const [line] = records();
  assert.deepEqual(Object.keys(line!).sort(), ['level', 'msg', 'reportId', 'requestId', 'service', 'time']);
  assert.equal(new Date(line!.time as string).toISOString(), line!.time);
  assert.deepEqual(withoutTime(line), { time: undefined, level: 'info', service: 'discover', msg: 'report queued', requestId: 'req-12345678', reportId: 7 });
  // A line break in the message or a field stays inside the one line.
  log.warn('first\n{"level":"error"}', { note: 'a\nb' });
  assert.equal(lines[1]!.split('\n').length, 2);
  assert.deepEqual([records()[1]!.msg, records()[1]!.note], ['first\n{"level":"error"}', 'a\nb']);
  assert.throws(() => createLogger({ service: 's', write: 'stdout' as never }), TypeError);
});

test('a field cannot replace time, level, service or msg, at the call or in a child', () => {
  const { log, lines, records } = capture();
  log.child({ service: 'other', msg: 'bound' }).warn('slow', { level: 'debug', service: 'other', msg: 'spoofed', time: 'never', ms: 900 });
  assert.equal(lines[0]!.match(/"level"/gu)?.length, 1);
  assert.equal(lines[0]!.match(/"msg"/gu)?.length, 1);
  assert.deepEqual(withoutTime(records()[0]), { time: undefined, level: 'warn', service: 'discover', msg: 'slow', ms: 900 });
});

test('the level option drops less severe calls, defaults to info and refuses unknown levels', () => {
  const quiet = capture({ service: 's', level: 'warn' });
  quiet.log.debug('d'); quiet.log.info('i'); quiet.log.warn('w'); quiet.log.error('e');
  assert.deepEqual(quiet.records().map(line => line.level), ['warn', 'error']);
  const standard = capture();
  standard.log.debug('d'); standard.log.info('i');
  assert.deepEqual(standard.records().map(line => line.msg), ['i']);
  const verbose = capture({ service: 's', level: 'debug' });
  verbose.log.debug('d');
  assert.deepEqual(verbose.records().map(line => line.level), ['debug']);
  assert.throws(() => createLogger({ service: 's', level: 'verbose' as never }), TypeError);
  assert.throws(() => createLogger({ service: '' }), TypeError);
});

test('child loggers add their fields to every line, nest, and yield to call fields', () => {
  const { log, records } = capture();
  const request = log.child({ requestId: 'abcdefgh', route: '/reports' });
  request.child({ workspaceId: 'w1' }).info('read', { route: '/reports/7' });
  request.info('done');
  log.info('bare');
  assert.deepEqual(records().map(withoutTime), [
    { time: undefined, level: 'info', service: 'discover', msg: 'read', requestId: 'abcdefgh', route: '/reports/7', workspaceId: 'w1' },
    { time: undefined, level: 'info', service: 'discover', msg: 'done', requestId: 'abcdefgh', route: '/reports' },
    { time: undefined, level: 'info', service: 'discover', msg: 'bare' },
  ]);
});

test('every default secret name is hidden at the top level and one and two levels down', () => {
  const names = DEFAULT_REDACT_PATHS.filter(path => !path.startsWith('*') && !path.includes('.')).map(path => path.startsWith('[') ? JSON.parse(path.slice(1, -1)) as string : path);
  assert.equal(names.length, 37);
  assert.ok(names.includes('x-api-key') && names.includes('DATABASE_URL') && names.includes('recoveryCodes'));
  const { log, lines } = capture();
  for (const name of names) log.info('m', { [name]: 'SECRET-0', one: { [name]: 'SECRET-1' }, two: { level: { [name]: 'SECRET-2' } }, list: [{ [name]: 'SECRET-L' }] });
  assert.equal(lines.length, names.length);
  for (const line of lines) {
    // An array element counts as one level: list.0.name is hidden by *.*.name.
    assert.doesNotMatch(line, /SECRET-[012L]/u, line);
    assert.equal(line.match(/\[redacted\]/gu)?.length, 4, line);
  }
});

test('request and response header paths are hidden, and names deeper than two levels are written as given', () => {
  const { log, records } = capture();
  log.info('request', { req: { method: 'GET', headers: { authorization: 'Bearer A', cookie: 'sid=B', accept: 'text/html' } }, res: { headers: { 'set-cookie': 'sid=C' } } });
  log.info('deep', { a: { b: { c: { password: 'DEEP' } } } });
  const [request, deep] = records();
  assert.deepEqual(request!.req, { method: 'GET', headers: { authorization: '[redacted]', cookie: '[redacted]', accept: 'text/html' } });
  assert.deepEqual(request!.res, { headers: { 'set-cookie': '[redacted]' } });
  // Fails open: the default list stops two levels down, as the guide says.
  assert.deepEqual(deep!.a, { b: { c: { password: 'DEEP' } } });
});

test('redact adds paths and cannot remove the defaults; an invalid path is refused when the logger is made', () => {
  const { log, records } = capture({ service: 's', redact: ['user.email', '*.ssn'] });
  log.info('m', { user: { email: 'e@example.com', name: 'Ann' }, person: { ssn: '123' }, password: 'p' });
  assert.deepEqual(withoutTime(records()[0]), { time: undefined, level: 'info', service: 's', msg: 'm', user: { email: '[redacted]', name: 'Ann' }, person: { ssn: '[redacted]' }, password: '[redacted]' });
  const empty = capture({ service: 's', redact: [] });
  empty.log.info('m', { token: 't' });
  assert.equal(empty.records()[0]!.token, '[redacted]');
  assert.ok(Object.isFrozen(DEFAULT_REDACT_PATHS));
  assert.throws(() => createLogger({ service: 's', redact: ['a..b'] }), TypeError);
  assert.throws(() => createLogger({ service: 's', redact: [7 as never] }), TypeError);
});

test('errors are written as class name, message, stack, code and cause, never their other properties', () => {
  const { log, records } = capture();
  const failure = Object.assign(new RangeError('out of range', { cause: new Error('inner') }), { code: 'E_RANGE', config: { apiUrl: 'https://u:p@example.com' } });
  log.error('failed', { err: failure, context: { list: [new AggregateError([new Error('a')], 'many')] } });
  log.error('direct', failure);
  const [nested, direct] = records();
  const written = nested!.err as Line;
  assert.deepEqual(Object.keys(written).sort(), ['cause', 'code', 'message', 'stack', 'type']);
  assert.deepEqual([written.type, written.message, written.code, (written.cause as Line).message], ['RangeError', 'out of range', 'E_RANGE', 'inner']);
  assert.match(written.stack as string, /^RangeError: out of range\n\s+at /u);
  const aggregate = ((nested!.context as Line).list as Line[])[0]!;
  assert.equal((aggregate.errors as Line[])[0]!.message, 'a');
  assert.deepEqual(direct!.err, written);
  assert.doesNotMatch(JSON.stringify(records()), /u:p@/u);
});

test('a log call never throws: throwing getters, proxies, cycles, odd values and a failing destination', () => {
  const { log, records } = capture();
  const circular: Record<string, unknown> = { name: 'loop' };
  circular.self = circular;
  const revoked = Proxy.revocable({}, {});
  revoked.revoke();
  const hostile = {
    get broken(): never { throw new Error('getter'); },
    circular,
    revoked: revoked.proxy,
    keys: new Proxy({}, { ownKeys() { throw new Error('ownKeys'); } }),
    when: new Date(0), never: new Date(Number.NaN), big: 2n ** 70n, nan: Number.NaN, fn: () => 1, sym: Symbol('s'), nothing: undefined,
    ['__proto__']: { polluted: true },
  };
  assert.doesNotThrow(() => log.info('hostile', hostile));
  const cause: Record<string, unknown> = {};
  const loop = new Error('loop', { cause });
  cause.back = loop;
  assert.doesNotThrow(() => log.error('loop', { err: loop }));
  assert.doesNotThrow(() => log.info(Symbol('m') as never, 'not fields' as never));
  assert.doesNotThrow(() => log.child(revoked.proxy).info('child of revoked'));
  const [line, looped, odd, child] = records();
  assert.deepEqual({ ...line, time: undefined }, {
    time: undefined, level: 'info', service: 'discover', msg: 'hostile', broken: '[unreadable]', circular: { name: 'loop', self: '[circular]' },
    revoked: '[unreadable]', keys: '[unreadable]', when: '1970-01-01T00:00:00.000Z', never: null, big: '1180591620717411303424', nan: 'NaN',
    ['__proto__']: { polluted: true },
  });
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  assert.deepEqual(((looped!.err as Line).cause as Line).back, '[circular]');
  assert.deepEqual([odd!.msg, odd!.fields], ['Symbol(m)', 'not fields']);
  assert.equal(child!.msg, 'child of revoked');
  const failing = createLogger({ service: 's', write: () => { throw new Error('disk full'); } });
  assert.doesNotThrow(() => failing.error('lost'));
});

// gc() before each call, so heapUsed after it bounds what the call allocated (a collection during the call only lowers it).
setFlagsFromString('--expose-gc');
const gc = runInNewContext('gc') as () => void;

test('hostile shapes are bounded before pino sees them: each within its time and memory budget', () => {
  const { log, lines } = capture();
  const text8k = 'x'.repeat(8192);
  const shapes: [string, () => unknown, number][] = [
    ['a 1 MB key', () => ({ ['k'.repeat(1 << 20)]: 1 }), 250],
    ['a 10 MB key', () => ({ ['k'.repeat(10 << 20)]: 1 }), 250],
    // V8 enumerates every key of an object before the first one is read, about as long as building the object took.
    ['1,000,000 fields', () => { const many: Record<string, number> = {}; for (let index = 0; index < 1e6; index++) many[`f${index}`] = index; return many; }, 5000],
    ['10,000 fields of 8 kB', () => Object.fromEntries(Array.from({ length: 10_000 }, (_, index) => [`f${index}`, text8k + index])), 250],
    ['100,000 levels of nesting', () => { const root: Record<string, unknown> = {}; let at = root; for (let index = 0; index < 1e5; index++) { const next = {}; at.next = next; at = next; } return { root }; }, 250],
    ['shared empty containers', () => { const empty = {}, list: unknown[] = []; let level: Record<string, unknown> = { a: empty, b: list }; for (let index = 0; index < 60; index++) level = { a: level, b: level, c: list }; return { level, many: new Array(1e6).fill(empty) }; }, 250],
    ['a 10 MB typed array', () => ({ data: new Uint8Array(10 << 20), buffer: new ArrayBuffer(1024) }), 250],
  ];
  for (const [name, build, budgetMs] of shapes) {
    const value = build();
    lines.length = 0;
    gc();
    const heap = process.memoryUsage().heapUsed, started = performance.now();
    log.info(name, value as Record<string, unknown>);
    const elapsed = performance.now() - started, allocated = process.memoryUsage().heapUsed - heap;
    assert.equal(lines.length, 1, name);
    assert.ok(elapsed < budgetMs, `${name}: ${elapsed.toFixed(0)} ms, budget ${budgetMs} ms`);
    assert.ok(allocated < 32 * 1024 * 1024, `${name}: ${(allocated / 1048576).toFixed(1)} MB allocated, budget 32 MB`);
    assert.ok(lines[0]!.length < 256 * 1024, `${name}: line of ${lines[0]!.length} characters, budget 256 kB`);
    JSON.parse(lines[0]!);
  }
});

test('the bounds: entries, depth, string length, key length, total size and binary data', () => {
  const { log, records } = capture();
  log.info('m', { list: Array.from({ length: 150 }, (_, index) => index), long: 'y'.repeat(10_000), ['k'.repeat(300)]: 1,
    deep: { a: { b: { c: { d: { e: { f: 1 } } } } } }, bytes: Buffer.from('secret bytes'), view: new DataView(new ArrayBuffer(8)) });
  const [line] = records();
  const list = line!.list as unknown[];
  assert.deepEqual([list.length, list[99], list[100]], [101, 99, '[truncated]']);
  assert.equal(line!.long, `${'y'.repeat(8192)}…[truncated]`);
  assert.equal(line![`${'k'.repeat(256)}…`], 1);
  // Five levels of objects under a field are written; the sixth is a marker.
  assert.deepEqual(line!.deep, { a: { b: { c: { d: { e: '[depth limit]' } } } } });
  assert.deepEqual([line!.bytes, line!.view], ['[Buffer 12 bytes]', '[DataView 8 bytes]']);
  const wide = Object.fromEntries(Array.from({ length: 150 }, (_, index) => [`f${index}`, index]));
  log.info('wide', wide);
  const written = records()[1]!;
  assert.equal(written.f99, 99);
  assert.equal(written.f100, undefined);
  assert.equal(written['[truncated]'], '50 more fields');
  log.info('budget', Object.fromEntries(Array.from({ length: 20 }, (_, index) => [`f${index}`, 'z'.repeat(8192)])));
  const spent = records()[2]!;
  assert.equal(spent.f7, 'z'.repeat(8192));
  assert.equal(spent.f8, '[truncated]');
});

test('requestId keeps a valid incoming x-request-id and otherwise makes a UUID, from a Request or a Node request', () => {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
  const web = (value?: string) => new Request('https://example.com/', value === undefined ? {} : { headers: { 'x-request-id': value } });
  assert.equal(requestId(web('req.ABC_12-34')), 'req.ABC_12-34');
  assert.equal(requestId({ headers: { 'x-request-id': 'node-request-1' } }), 'node-request-1');
  for (const value of [undefined, 'short', 'x'.repeat(129), 'has space1', '{"json":1}', 'semi;colon1']) assert.match(requestId(web(value)), uuid, String(value));
  for (const value of [['abcdefgh', 'ijklmnop'], 'line\nbreak123', 12345678]) assert.match(requestId({ headers: { 'x-request-id': value as string } }), uuid, String(value));
  assert.match(requestId({ headers: { get() { throw new Error('no'); } } }), uuid);
  assert.notEqual(requestId(web()), requestId(web()));
  const { log, records } = capture();
  log.child({ requestId: requestId(web('req-12345678')) }).info('handled');
  assert.equal(records()[0]!.requestId, 'req-12345678');
});

const MARKER = 'MARKER-5d1c0f';
// A drizzle-orm error over a pg server error, both carrying the marker the way the libraries do.
function markedError(): DrizzleQueryError {
  const server = Object.assign(new pg.DatabaseError(`invalid input syntax for type integer: "${MARKER}"`, 120, 'error'), {
    severity: 'ERROR', code: '22P02', detail: `Key (email)=(${MARKER}) already exists.`, hint: MARKER, where: `SQL function ${MARKER}`, internalQuery: MARKER,
    position: '8', schema: 'public', table: 'accounts', column: 'email', constraint: 'accounts_email_key', routine: 'pg_strtoint32_safe',
  });
  return new DrizzleQueryError(`select $1::int /* ${MARKER} */`, [MARKER], server);
}

test('safeDatabaseError keeps class names, SQLSTATE code and names only, through the cause chain', () => {
  const original = markedError();
  assert.match(`${original.message}${inspect(original)}`, new RegExp(MARKER, 'u'), 'the fixture carries the marker');
  const safe = safeDatabaseError(original);
  assert.ok(safe instanceof SafeDatabaseError && safe instanceof Error);
  assert.deepEqual([safe.errorClass, safe.message, safe.code], ['DrizzleQueryError', 'Failed query', undefined]);
  assert.ok(safe.cause instanceof SafeDatabaseError);
  assert.deepEqual({ ...safe.cause }, { name: 'SafeDatabaseError', errorClass: 'DatabaseError', code: '22P02', constraint: 'accounts_email_key', table: 'accounts', column: 'email', schema: 'public' });
  assert.equal(safe.cause.message, 'Database error 22P02');
  for (const output of [JSON.stringify(safe), inspect(safe, { depth: 10, showHidden: true }), String(safe.stack), String(safe.cause.stack)]) assert.doesNotMatch(output, new RegExp(MARKER, 'u'));
  assert.equal(safeDatabaseError(safe), safe);
  // A statement wrapper found by shape alone, and a cause chain that loops, stay safe and finite.
  const looped: Error & { cause?: unknown } = Object.assign(new Error(`Failed query: insert ${MARKER}`), { query: `insert ${MARKER}`, params: [MARKER] });
  looped.cause = looped;
  const reduced = safeDatabaseError(looped);
  assert.deepEqual([reduced.errorClass, reduced.message, reduced.cause], ['Error', 'Failed query', undefined]);
  assert.equal(safeDatabaseError(new Proxy({}, { get() { throw new Error('trap'); } })).message, 'Database error');
});

test('a database error carries no statement, parameter or server text into log output, however it is logged', () => {
  const { log, lines, records } = capture({ service: 's', level: 'debug' });
  const error = markedError();
  log.error('as a field', { err: error });
  log.error('as the fields', error);
  log.error('as a cause', { err: new Error('saving the account failed', { cause: error }) });
  log.error('nested', { attempts: [{ error }], aggregate: new AggregateError([error], 'retries failed') });
  log.child({ error }).warn('bound in a child');
  log.error('already safe', { err: safeDatabaseError(error) });
  assert.equal(lines.length, 6);
  assert.doesNotMatch(lines.join(''), new RegExp(MARKER, 'u'));
  const written = records()[0]!.err as Line;
  assert.deepEqual(written, { type: 'DrizzleQueryError', message: 'Failed query',
    cause: { type: 'DatabaseError', message: 'Database error 22P02', code: '22P02', constraint: 'accounts_email_key', table: 'accounts', column: 'email', schema: 'public' } });
  assert.deepEqual(records()[5]!.err, written);
});

test('root and ./browser load without node_modules; ./log needs its pino peer', () => {
  const directory = mkdtempSync(join(tmpdir(), 'ten98-log-peer-'));
  try {
    const root = new URL('../', import.meta.url);
    for (const file of readdirSync(root).filter(name => name.endsWith('.mjs'))) copyFileSync(new URL(file, root), join(directory, file));
    writeFileSync(join(directory, 'package.json'), JSON.stringify({ name: 'isolated', type: 'module' }));
    const load = (file: string) => spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(new URL(file, `file:///${directory.replaceAll('\\', '/')}/`).href)}); console.log('loaded');`],
      { cwd: directory, encoding: 'utf8', timeout: 20_000, windowsHide: true });
    for (const file of ['index.mjs', 'browser.mjs']) {
      const loaded = load(file);
      assert.equal(loaded.status, 0, `${file}: ${loaded.stderr}`);
      assert.equal(loaded.stdout.trim(), 'loaded');
    }
    const refused = load('log.mjs');
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, /Cannot find package 'pino'/u);
  } finally { rmSync(directory, { recursive: true, force: true }); }
  const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.deepEqual(manifest.exports['./log'], { types: './log.d.mts', import: './log.mjs' });
  assert.equal(manifest.peerDependencies.pino, '10.4.0');
  assert.deepEqual(manifest.peerDependenciesMeta.pino, { optional: true });
  assert.doesNotMatch(readFileSync(new URL('../log.d.mts', import.meta.url), 'utf8'), /['"]pino['"]/u, 'the declarations do not need pino types');
  assert.doesNotMatch(readFileSync(new URL('../database-error.mjs', import.meta.url), 'utf8'), /\bimport\b[^;]*['"](?:pino|pg|drizzle-orm)['"]/u, 'safeDatabaseError imports no library');
});

// Real PostgreSQL, opt-in: set TEN98_TEST_DATABASE_URL to a disposable server. It uses a temporary table only.
const url = process.env.TEN98_TEST_DATABASE_URL;
const skip = url ? false : 'set TEN98_TEST_DATABASE_URL to a disposable PostgreSQL to log real database errors';

test('failing statements on PostgreSQL leave no marker from their text or parameters in log output', { skip }, async () => {
  const pool = new pg.Pool({ connectionString: url, max: 1 });
  try {
    const db = drizzle(pool);
    const failures: unknown[] = [];
    const attempt = async (run: () => Promise<unknown>) => { try { await run(); assert.fail('the statement should fail'); } catch (error) { failures.push(error); } };
    // 22P02 quotes the value it could not cast in the server message.
    await attempt(() => db.execute(sql`select ${MARKER}::int as value /* ${sql.raw(MARKER)} */`));
    // 23505 puts the duplicate value in detail.
    await db.execute(sql`create temporary table log_marker (email text constraint log_marker_email_key unique)`);
    await db.execute(sql`insert into log_marker (email) values (${MARKER})`);
    await attempt(() => db.execute(sql`insert into log_marker (email) values (${MARKER}) /* ${sql.raw(MARKER)} */`));
    for (const failure of failures) assert.match(`${(failure as Error).message}${inspect(failure, { depth: 5 })}`, new RegExp(MARKER, 'u'), 'the raw error carries the marker');
    const { log, lines, records } = capture({ service: 's' });
    for (const failure of failures) log.error('statement failed', { err: failure });
    assert.doesNotMatch(lines.join(''), new RegExp(MARKER, 'u'));
    assert.doesNotMatch(failures.map(failure => inspect(safeDatabaseError(failure), { depth: 10, showHidden: true })).join(''), new RegExp(MARKER, 'u'));
    const [cast, duplicate] = records().map(line => line.err as Line);
    assert.deepEqual(cast, { type: 'DrizzleQueryError', message: 'Failed query', cause: { type: 'DatabaseError', message: 'Database error 22P02', code: '22P02' } });
    assert.deepEqual(duplicate, { type: 'DrizzleQueryError', message: 'Failed query',
      cause: { type: 'DatabaseError', message: 'Database error 23505', code: '23505', constraint: 'log_marker_email_key', table: 'log_marker', schema: (duplicate!.cause as Line).schema } });
    assert.match(String((duplicate!.cause as Line).schema), /^pg_temp_\d+$/u);
  } finally { await pool.end(); }
});
