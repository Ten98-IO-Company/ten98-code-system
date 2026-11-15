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
  assert.deepEqual({ ...loop, time: undefined }, { time: undefined, level: 'info', service: 'discover', message: 'loop', requestId: 'abcdefgh', logError: 'fields could not be serialised' });
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
