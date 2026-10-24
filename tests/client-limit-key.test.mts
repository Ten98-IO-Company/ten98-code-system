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

test('an unresolved client gets a dedicated key kept apart from every resolved client', () => {
  assert.equal(clientLimitKey('setup', null, secret), 'setup:unresolved');
  assert.notEqual(clientLimitKey('setup', null, secret), clientLimitKey('setup', '203.0.113.7', secret));
});

test('invalid scope, secret or address is a caller error, not a shared key', () => {
  for (const scope of ['', 'Sign-In', 'a b', 'x'.repeat(65), 'a:b']) assert.throws(() => clientLimitKey(scope, '203.0.113.7', secret), TypeError, scope);
  assert.throws(() => clientLimitKey('signin', '203.0.113.7', 'short'), TypeError);
  for (const address of ['unknown', '', 'local', '203.0.113.7:443', '[::1]']) assert.throws(() => clientLimitKey('signin', address, secret), TypeError, address);
});
