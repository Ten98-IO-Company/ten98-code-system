import assert from 'node:assert/strict';
import test from 'node:test';
import { clientLimitKey } from '../index.mjs';

const secret = 's'.repeat(32);

test('client limit keys are stable per client and scope, and never contain the address', () => {
  const key = clientLimitKey('signin', '203.0.113.7', secret);
  assert.match(key, /^signin:[A-Za-z0-9_-]{43}$/u);
  assert.equal(key.includes('203.0.113.7'), false);
  assert.equal(clientLimitKey('signin', '203.0.113.7', secret), key);
  // The same client is a different key in another scope, under another secret, and differs from other clients.
  assert.notEqual(clientLimitKey('setup', '203.0.113.7', secret), key.replace(/^signin/u, 'setup'));
  assert.notEqual(clientLimitKey('signin', '203.0.113.7', 't'.repeat(32)), key);
  assert.notEqual(clientLimitKey('signin', '203.0.113.8', secret), key);
  // Equivalent spellings of one address share a key.
  assert.equal(clientLimitKey('signin', '::ffff:203.0.113.7', secret), key);
  assert.equal(clientLimitKey('signin', '2001:db8::1', secret), clientLimitKey('signin', '2001:0db8:0:0:0:0:0:1', secret));
});

test('IPv6 clients are keyed by network prefix, /56 by default; IPv4 stays per address', () => {
  const key = (address: string, options?: { ipv6Prefix?: number }) => clientLimitKey('signin', address, secret, options);
  // Two addresses in the same /56 share one key; a different /56 is a different client.
  assert.equal(key('2001:db8:1:ab00::1'), key('2001:db8:1:abff:ffff:ffff:ffff:ffff'));
  assert.notEqual(key('2001:db8:1:ab00::1'), key('2001:db8:1:ac00::1'));
  // An IPv4-mapped address still matches the plain IPv4 address, and IPv4 neighbours stay distinct.
  assert.equal(key('::ffff:203.0.113.7'), key('203.0.113.7'));
  assert.notEqual(key('203.0.113.7'), key('203.0.113.8'));
  // The prefix is configurable from 48 to 64.
  assert.notEqual(key('2001:db8:1:ab01::1', { ipv6Prefix: 64 }), key('2001:db8:1:ab02::1', { ipv6Prefix: 64 }));
  assert.equal(key('2001:db8:1:ab01::1', { ipv6Prefix: 48 }), key('2001:db8:1:ffff::1', { ipv6Prefix: 48 }));
  assert.notEqual(key('2001:db8:1:ab00::1', { ipv6Prefix: 56 }), key('2001:db8:1:ab00::1', { ipv6Prefix: 64 }));
  // Embedded IPv4 notation is expanded before grouping.
  assert.equal(key('64:ff9b::192.0.2.1'), key('64:ff9b::c000:201'));
  for (const ipv6Prefix of [47, 65, 56.5]) assert.throws(() => key('2001:db8::1', { ipv6Prefix }), TypeError);
});

test('an unresolved client gets a dedicated key kept apart from every resolved client', () => {
  assert.equal(clientLimitKey('setup', null, secret), 'setup:unresolved');
  assert.notEqual(clientLimitKey('setup', null, secret), clientLimitKey('setup', '203.0.113.7', secret));
});

test('invalid scope, secret or address is a caller error, not a shared key', () => {
  for (const scope of ['', 'Sign-In', 'a b', 'x'.repeat(65), 'a:b']) assert.throws(() => clientLimitKey(scope, '203.0.113.7', secret), TypeError, scope);
  assert.throws(() => clientLimitKey('signin', '203.0.113.7', 'short'), TypeError);
  for (const address of ['unknown', '', 'local', '203.0.113.7:443', '[::1]']) assert.throws(() => clientLimitKey('signin', address, secret), TypeError, address);
});
