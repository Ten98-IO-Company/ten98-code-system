import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizePublicHostname } from '../index.mjs';

const label = (length: number) => 'a'.repeat(length);
// Invisible characters are built from code points so a reviewer can see each one.
const [TAB, NUL, LONE_SURROGATE] = [9, 0, 0xd800].map(code => String.fromCharCode(code));

test('normalizePublicHostname returns the lowercase ASCII form of a public hostname', () => {
  for (const [input, expected] of [
    ['example.com', 'example.com'], ['WWW.Example.COM', 'www.example.com'], ['shop.example.co.uk.', 'shop.example.co.uk'],
    ['bücher.de', 'xn--bcher-kva.de'], ['xn--bcher-kva.de', 'xn--bcher-kva.de'], ['ＥＸＡＭＰＬＥ.com', 'example.com'],
    ['a-b.example.io', 'a-b.example.io'], ['123.example.com', '123.example.com'], ['example.xn--p1ai', 'example.xn--p1ai'],
    [`${label(63)}.com`, `${label(63)}.com`], [`${label(63)}.${label(63)}.${label(63)}.${label(61)}`, `${label(63)}.${label(63)}.${label(63)}.${label(61)}`],
  ]) assert.equal(normalizePublicHostname(input), expected, input);
});

test('normalizePublicHostname refuses special-use names and everything below them', () => {
  for (const name of ['localhost', 'local', 'internal', 'invalid', 'test', 'example', 'onion', 'home.arpa', 'alt']) {
    for (const input of [name, `api.${name}`, `a.b.${name}.`, name.toUpperCase()]) assert.equal(normalizePublicHostname(input), null, input);
  }
  // A name that only ends with the same letters is not below the special name.
  for (const input of ['mytest.com', 'api.contest', 'shop.mylocal', 'a.salt']) assert.equal(normalizePublicHostname(input), input);
  assert.equal(normalizePublicHostname('latest'), null);
});

test('normalizePublicHostname refuses addresses, numeric top-level labels and malformed labels', () => {
  for (const input of [
    '192.0.2.1', '192.0.2.1.', '3221225985', '0xc0.0.2.1', '0300.0.2.1', '[::1]', '::1', 'example.123', 'example.0x1f', '1.2.3.4.5',
    'com', 'a..com', '.example.com', 'example.com..', '-a.com', 'a-.com', 'a_b.com', `${label(64)}.com`,
    `${label(63)}.${label(63)}.${label(63)}.${label(62)}`, `${label(1025)}.com`,
  ]) assert.equal(normalizePublicHostname(input), null, input);
});

test('normalizePublicHostname refuses URLs, ports, credentials, wildcards and hidden characters', () => {
  for (const input of [
    'https://example.com', 'example.com/path', 'example.com:443', 'user@example.com', '*.example.com', 'example.com?q', 'example.com#x',
    'exa%6dple.com', 'exa mple.com', ' example.com', `example.com${TAB}`, `exa${NUL}mple.com`, `exa${LONE_SURROGATE}mple.com`, 'a\\b.com',
    '', null, undefined, 42, ['example.com'],
  ]) assert.equal(normalizePublicHostname(input), null, JSON.stringify(input));
});
