import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
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
    [`${label(63)}.com`, `${label(63)}.com`], [`${label(63)}.${label(63)}.${label(63)}.${label(57)}.com`, `${label(63)}.${label(63)}.${label(63)}.${label(57)}.com`],
  ]) assert.equal(normalizePublicHostname(input), expected, input);
});

test('normalizePublicHostname refuses special-use names and everything below them', () => {
  for (const name of ['localhost', 'local', 'internal', 'invalid', 'test', 'example', 'onion', 'home.arpa', 'alt']) {
    for (const input of [name, `api.${name}`, `a.b.${name}.`, name.toUpperCase()]) assert.equal(normalizePublicHostname(input), null, input);
  }
  // A name that only ends with the same letters is not below the special name.
  assert.equal(normalizePublicHostname('mytest.com'), 'mytest.com');
  for (const input of ['api.contest', 'shop.mylocal', 'a.salt']) assert.equal(normalizePublicHostname(input, { allowUnlistedSuffixForTesting: true }), input);
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

test('normalizePublicHostname requires a registrable name under an ICANN-section public suffix', () => {
  for (const [input, expected] of [
    // ICANN suffixes, including multi-label, wildcard and exception rules.
    ['example.com', 'example.com'], ['example.co.uk', 'example.co.uk'], ['shop.example.co.uk', 'shop.example.co.uk'], ['example.site', 'example.site'],
    ['app.dev', 'app.dev'], ['city.kawasaki.jp', 'city.kawasaki.jp'], ['a.b.kawasaki.jp', 'a.b.kawasaki.jp'], ['kawasaki.jp', 'kawasaki.jp'], ['www.ck', 'www.ck'], ['a.foo.ck', 'a.foo.ck'],
    // Private-section suffixes are not consulted: these are ordinary names under io, com and com.
    ['github.io', 'github.io'], ['user.github.io', 'user.github.io'], ['blogspot.com', 'blogspot.com'], ['s3.amazonaws.com', 's3.amazonaws.com'],
    // IDN and punycode, trailing dots and case.
    ['пример.рф', 'xn--e1afmkfd.xn--p1ai'], ['xn--e1afmkfd.xn--p1ai', 'xn--e1afmkfd.xn--p1ai'], ['例子.中国', 'xn--fsqu00a.xn--fiqs8s'],
    ['ПРИМЕР.РФ.', 'xn--e1afmkfd.xn--p1ai'], ['EXAMPLE.Com.', 'example.com'], ['Shop.Example.CO.UK', 'shop.example.co.uk'],
  ]) assert.equal(normalizePublicHostname(input), expected, input);
  for (const input of [
    // A public suffix itself, or a name covered by a wildcard suffix.
    'com', 'com.', 'co.uk', 'CO.UK.', 'uk', 'x.kawasaki.jp', 'ck', 'foo.ck', 'рф', 'xn--p1ai', '中国',
    // Internal names on suffixes outside the list.
    'nas.home', 'router.home.', 'host.localdomain', 'srv.intra', 'web.docker', 'vault.service.consul', 'printer.lan', 'dc1.corp', 'box.private',
    'NAS.HOME', 'example.unlistedtld',
    // arpa and everything under it.
    'arpa', 'in-addr.arpa', '1.0.0.127.in-addr.arpa', '1.0.0.127.in-addr.arpa.', 'b.a.ip6.arpa', 'e164.arpa', 'x.e164.arpa', 'x.home.arpa', 'example.arpa',
    // Single labels.
    'example', 'nas', 'nas.', 'xn--bcher-kva',
  ]) assert.equal(normalizePublicHostname(input), null, input);
});

test('only the explicit test option admits a name on an unlisted suffix', () => {
  const testing = { allowUnlistedSuffixForTesting: true };
  for (const input of ['app.corp', 'nas.home', 'web.docker']) {
    assert.equal(normalizePublicHostname(input), null, input);
    assert.equal(normalizePublicHostname(input, {}), null, input);
    assert.equal(normalizePublicHostname(input, testing), input, input);
  }
  // The option never admits a public suffix itself, a special-use name, arpa, a single label or an address.
  for (const input of ['co.uk', 'com', 'api.test', 'app.localhost', 'x.in-addr.arpa', 'nas', '192.0.2.1']) {
    assert.equal(normalizePublicHostname(input, testing), null, input);
  }
});

test('the shipped Public Suffix List is the unmodified upstream file at the recorded commit', () => {
  const record: { repository: string; commit: string; path: string; sha256: string; license: string } = JSON.parse(readFileSync(new URL('../data/public_suffix_list.json', import.meta.url), 'utf8'));
  const bytes = readFileSync(new URL('../data/public_suffix_list.dat', import.meta.url));
  assert.deepEqual(Object.keys(record), ['repository', 'commit', 'path', 'sha256', 'license']);
  assert.equal(record.repository, 'https://github.com/publicsuffix/list');
  assert.match(record.commit, /^[0-9a-f]{40}$/);
  assert.equal(record.license, 'MPL-2.0');
  assert.equal(createHash('sha256').update(bytes).digest('hex'), record.sha256);
  assert.match(bytes.toString('utf8'), /^\/\/ This Source Code Form is subject to the terms of the Mozilla Public\n\/\/ License, v\. 2\.0\./);
  const notices = readFileSync(new URL('../THIRD_PARTY_NOTICES.md', import.meta.url), 'utf8');
  assert.ok(notices.includes(`publicsuffix/list@${record.commit}`) && notices.includes('https://mozilla.org/MPL/2.0/'));
  const manifest: { files: string[] } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.deepEqual(['data/public_suffix_list.dat', 'data/public_suffix_list.json', 'THIRD_PARTY_NOTICES.md'].filter(file => !manifest.files.includes(file)), []);
});
