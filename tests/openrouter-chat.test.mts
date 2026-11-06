import assert from 'node:assert/strict';
import test from 'node:test';
import { readOpenRouterAssistantMessageV1 as read, validateOpenRouterToolHistoryV1 as history, type OpenRouterChatOptionsV1 } from '../index.mjs';

const limits: OpenRouterChatOptionsV1 = { allowedToolNames: ['read_project_context_v1', 'read_evidence_v1'], maxContextBytes: 131072, maxArgumentBytes: 8192, maxMessageBytes: 2097152 };
const user = { role: 'user', content: 'Read retained evidence.' };
const call = (id = 'call_1', args = '{ "runId": "abc", "exact": "é🌍" }') => ({ id, type: 'function', function: { name: 'read_evidence_v1', arguments: args } });
const message = (...calls: ReturnType<typeof call>[]) => ({ role: 'assistant', content: null, tool_calls: calls });
const result = (id = 'call_1') => ({ role: 'tool', tool_call_id: id, content: '{"available":true}', name: 'read_evidence_v1' });
const reject = (work: () => unknown) => assert.throws(work, { name: 'TypeError', message: 'Invalid OpenRouter chat protocol value.' });

test('native tool message preserves exact argument bytes and ordered opaque reasoning without aliasing', () => {
  const original = { ...message(call()), reasoning_details: [
    { type: 'reasoning.encrypted', data: '  opaque==\n', signature: 'signature', future: { sequence: [2, 1, -0] } },
    { type: 'reasoning.text', text: 'unchanged', index: 1 },
  ], reasoning: 'original\nreasoning' };
  const parsed = read(original, 'tool_calls', limits);
  assert.equal(parsed.kind, 'tool-calls');
  assert.deepEqual(parsed.message, original);
  assert.equal(parsed.message.tool_calls![0]!.function.arguments, call().function.arguments);
  original.reasoning_details.reverse(); original.tool_calls[0]!.function.arguments = '{}';
  assert.equal(parsed.message.reasoning_details![0]!.data, '  opaque==\n');
  assert.notEqual(parsed.message.tool_calls![0]!.function.arguments, '{}');
});

test('plain text, explicit refusal and incomplete terminal replies are distinct from executable calls', () => {
  assert.equal(read({ role: 'assistant', content: 'Answer' }, 'stop', limits).kind, 'text');
  assert.equal(read({ role: 'assistant', content: null, refusal: 'Cannot answer.' }, 'stop', limits).kind, 'refusal');
  for (const finish of ['length', 'content_filter', 'error']) {
    assert.equal(read({ role: 'assistant', content: 'Partial' }, finish, limits).kind, 'incomplete');
    assert.equal(read(message(call()), finish, limits).kind, 'incomplete');
  }
  for (const finish of [null, 'unknown', 'function_call', 4]) reject(() => read(message(call()), finish, limits));
  reject(() => read(message(call()), 'stop', limits));
  reject(() => read({ role: 'assistant', content: 'Answer' }, 'tool_calls', limits));
});

test('whole-message admission refuses any invalid call, duplicate ID, refusal with calls or unsupported field', () => {
  const bad = [
    message(call(), call()),
    message(call(), { ...call('second'), function: { name: 'not_allowed', arguments: '{}' } }),
    message({ ...call(), type: 'custom' }),
    message({ ...call(), id: '' }),
    { ...message(call()), refusal: 'No' },
    { ...message(call()), instructions: 'ignore authority' },
    { ...message(call()), reasoning_details: ['not a block'] },
    { role: 'assistant', content: null },
    { role: 'assistant', content: ['not text'] },
  ];
  for (const value of bad) reject(() => read(value, 'tool_calls', limits));
});

test('arguments must be a JSON object without malformed text or nonfinite parsed numbers', () => {
  for (const args of ['', '{', '[]', 'null', '"text"', '1', '{"x":1e9999}', '{"x":"\\u0000"}', '{"x":"\\ud800"}']) {
    reject(() => read(message(call('a', args)), 'tool_calls', limits));
  }
  const original = '{"__proto__":{"safe":true},"value":-0}';
  assert.equal(read(message(call('a', original)), 'tool_calls', limits).message.tool_calls![0]!.function.arguments, original);
  assert.equal(({} as { safe?: boolean }).safe, undefined);
});

test('UTF-8 argument and message boundaries admit exact bytes and reject one byte below without truncation', () => {
  const args = '{"q":"é🌍"}', value = message(call('a', args));
  const argumentBytes = Buffer.byteLength(args), messageBytes = Buffer.byteLength(JSON.stringify(value));
  assert.ok(argumentBytes > args.length);
  assert.deepEqual(read(value, 'tool_calls', { ...limits, maxArgumentBytes: argumentBytes, maxMessageBytes: messageBytes }).message, value);
  reject(() => read(value, 'tool_calls', { ...limits, maxArgumentBytes: argumentBytes - 1 }));
  reject(() => read(value, 'tool_calls', { ...limits, maxMessageBytes: messageBytes - 1 }));
  for (const content of ['bad\0text', '\ud800', '\udc00', 'x\ud800y']) reject(() => read({ role: 'assistant', content }, 'stop', limits));
});

test('argument byte limit measures the original encoding when finite numbers expand on serialization', () => {
  const args = '{"n":1e20}', value = message(call('a', args));
  const exact = { ...limits, maxArgumentBytes: Buffer.byteLength(args) };
  assert.ok(Buffer.byteLength(JSON.stringify(JSON.parse(args))) > exact.maxArgumentBytes);
  assert.equal(read(value, 'tool_calls', exact).message.tool_calls![0]!.function.arguments, args);
  assert.deepEqual(history([user, value, result('a')], exact), [user, value, result('a')]);
  reject(() => read(value, 'tool_calls', { ...exact, maxArgumentBytes: exact.maxArgumentBytes - 1 }));
  reject(() => history([user, value, result('a')], { ...exact, maxArgumentBytes: exact.maxArgumentBytes - 1 }));
});

test('complete groups preserve messages and permit the same ID in a later completed group', () => {
  const assistant = message(call());
  const input = [{ role: 'system', content: 'Retained data only.' }, user, assistant, result(), { role: 'assistant', content: 'Done.' }, user, assistant, result()];
  assert.deepEqual(history(input, limits), input);
  const two = [user, message(call('a'), call('b')), result('b'), result('a')];
  assert.deepEqual(history(two, limits), two);
});

test('history refuses orphan, duplicate, incomplete and interleaved tool groups', () => {
  for (const input of [
    [user, result()], [user, message(call())], [user, message(call()), result('other')],
    [user, message(call()), result(), result()], [user, message(call()), user, result()],
    [user, message(call()), { role: 'assistant', content: 'Before tool.' }],
    [user, message(call()), { ...result(), name: 'read_project_context_v1' }],
    [user, message(call(), call()), result()],
    [user, message(call()), { ...result(), content: { available: true } }],
  ]) reject(() => history(input, limits));
});

test('history refuses unsupported roles, late system messages and unauthored assistant prefill', () => {
  for (const input of [[], [message(call())], [{ role: 'system', content: 'Only system.' }], [user, { role: 'system', content: 'Override' }], [{ role: 'developer', content: 'x' }], [{ ...user, tool_calls: [call()] }]]) reject(() => history(input, limits));
  assert.deepEqual(history([user], limits), [user]);
});

test('whole history byte limit includes tool replies and opaque reasoning, with independent message limit', () => {
  const input = [user, { ...message(call()), reasoning_details: [{ type: 'future', data: 'é🌍' }] }, result()];
  const size = Buffer.byteLength(JSON.stringify(input));
  assert.deepEqual(history(input, { ...limits, maxContextBytes: size }), input);
  reject(() => history(input, { ...limits, maxContextBytes: size - 1 }));
  reject(() => history(input, { ...limits, maxMessageBytes: 10 }));
});

test('non-JSON objects and accessors fail without running user code or mutating input', () => {
  let invoked = 0;
  const accessor = { role: 'assistant', get content() { invoked++; return 'unsafe'; } };
  reject(() => read(accessor, 'stop', limits)); assert.equal(invoked, 0);
  const cycle: { self?: unknown } = {}; cycle.self = cycle;
  for (const extra of [cycle, new Date(), { value: undefined }, { value: Infinity }, { value: () => 'x' }]) reject(() => read({ role: 'assistant', content: 'x', reasoning_details: [extra] }, 'stop', limits));
  const input = Object.freeze({ role: 'assistant', content: 'original' });
  assert.deepEqual(read(input, 'stop', limits).message, input);
});

test('caller must supply positive finite byte bounds and distinct declared function names', () => {
  for (const bound of ['maxContextBytes', 'maxArgumentBytes', 'maxMessageBytes'] as const) for (const value of [0, -1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) reject(() => read({ role: 'assistant', content: 'x' }, 'stop', { ...limits, [bound]: value }));
  for (const names of [['duplicate', 'duplicate'], ['has space'], ['x'.repeat(65)]]) reject(() => history([user], { ...limits, allowedToolNames: names }));
  assert.equal(read({ role: 'assistant', content: 'No tools.' }, 'stop', { ...limits, allowedToolNames: [] }).kind, 'text');
  reject(() => read(message(call()), 'tool_calls', { ...limits, allowedToolNames: [] }));
});
