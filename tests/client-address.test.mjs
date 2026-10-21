import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeClientAddress, parseTrustedProxies, resolveClientAddress } from '../index.mjs';

// Vectors ported from ten98-discover tests/analytics-network.test.ts, where this logic originated.
const proxies = parseTrustedProxies('10.0.0.0/24,2001:db8:1::/48');
const none = parseTrustedProxies('');

test('an untrusted peer is the client and forwarding headers are ignored', () => {
  assert.equal(resolveClientAddress('192.0.2.1', '203.0.113.2', none), '192.0.2.1');
  assert.equal(resolveClientAddress('192.0.2.9', '198.51.100.4', proxies), '192.0.2.9');
  assert.equal(resolveClientAddress('2001:0db8:0:0::1', 'malformed', none), '2001:db8::1');
  assert.equal(resolveClientAddress(undefined, '192.0.2.1', none), null);
});

test('a trusted peer resolves the right-most untrusted forwarded hop', () => {
  assert.equal(resolveClientAddress('10.0.0.3', '198.51.100.4, 203.0.113.8, 10.0.0.2', proxies), '203.0.113.8');
  assert.equal(resolveClientAddress('10.0.0.3', '198.51.100.4, 10.0.0.2', proxies), '198.51.100.4');
  assert.equal(resolveClientAddress('10.0.0.3', null, proxies), null);
  assert.equal(resolveClientAddress('10.0.0.3', '10.0.0.2, 10.0.0.1', proxies), null);
});

test('two clients behind one proxy get different addresses, so they never share a limit', () => {
  const first = resolveClientAddress('10.0.0.3', '198.51.100.4', proxies), second = resolveClientAddress('10.0.0.3', '198.51.100.5', proxies);
  assert.notEqual(first, second);
  assert.notEqual(first, '10.0.0.3');
});

test('mapped IPv4 and IPv6 use canonical forms and matching proxy ranges', () => {
  for (const ip of ['::ffff:192.0.2.3', '::ffff:c000:203']) assert.equal(normalizeClientAddress(ip), '192.0.2.3');
  assert.equal(resolveClientAddress('::ffff:a00:3', '::ffff:c000:203, ::ffff:a00:2', proxies), '192.0.2.3');
  assert.equal(resolveClientAddress('2001:db8:1::8', '2001:db8:2::1, 2001:db8:1::4', proxies), '2001:db8:2::1');
  assert.equal(resolveClientAddress('10.0.0.3', '192.0.2.1', parseTrustedProxies('::ffff:0a00:0000/120')), '192.0.2.1');
  const exact = parseTrustedProxies('::ffff:10.0.0.3');
  assert.equal(resolveClientAddress('10.0.0.3', '192.0.2.1', exact), '192.0.2.1');
  assert.equal(resolveClientAddress('10.0.0.4', '192.0.2.1', exact), '10.0.0.4');
});

test('malformed, non-literal and oversized forwarding chains stay unknown', () => {
  for (const value of [
    'unknown', '192.0.2.1:80', '[2001:db8::1]:80', '"192.0.2.1"', 'fe80::1%eth0',
    '010.0.0.1', 'example.test', '192.0.2.1,,10.0.0.2', 'garbage,192.0.2.1', ' 192.0.2.1',
    '192.0.2.1,' + ' '.repeat(4096) + '10.0.0.2', Array(21).fill('192.0.2.1').join(','),
  ]) assert.equal(resolveClientAddress('10.0.0.3', value, proxies), null);
  assert.equal(resolveClientAddress('10.0.0.3', Array(20).fill('192.0.2.1').join(','), proxies), '192.0.2.1');
  for (const peer of ['', ' 192.0.2.1', '192.0.2.1:80', '[::1]', 'fe80::1%2', 'unknown']) assert.equal(resolveClientAddress(peer, '192.0.2.1', none), null);
});

test('invalid proxy configuration fails closed without echoing the value', () => {
  for (const raw of ['secret-sentinel', '10.0.0.1,,10.0.0.2', '10.0.0.0/33', '2001:db8::/129', '10.0.0.1/-1', '10.0.0.0/01', '::ffff:10.0.0.1/24', 'fe80::1%eth0', '10.0.0.0/24/1', 'x'.repeat(4097), 7]) {
    assert.throws(() => parseTrustedProxies(raw), error => error.code === 'CLIENT_ADDRESS_CONFIG' && !String(error.message).includes('secret-sentinel'));
  }
  assert.throws(() => parseTrustedProxies(Array(33).fill('10.0.0.1').join(',')), { code: 'CLIENT_ADDRESS_CONFIG' });
  assert.doesNotThrow(() => parseTrustedProxies(undefined));
});
