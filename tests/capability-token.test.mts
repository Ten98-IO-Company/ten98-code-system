import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';
import { readCapability, signCapability } from '../index.mjs';

const secret = 'k'.repeat(32);

test('a signed payload reads back only for its own purpose and secret', () => {
  const token = signCapability('direct-unsubscribe', ['project-1', 'a@example.com'], secret);
  assert.deepEqual(readCapability('direct-unsubscribe', token, secret), ['project-1', 'a@example.com']);
  assert.equal(readCapability('ten98.retention.preview.v1', token, secret), null);
  assert.equal(readCapability('direct-unsubscribe', token, 'x'.repeat(32)), null);
  const hex = signCapability('ten98.replay-upload.v1', { version: 1, until: 5 }, secret, { encoding: 'hex' });
  assert.match(hex, /^[A-Za-z0-9_-]+\.[a-f0-9]{64}$/u);
  assert.deepEqual(readCapability('ten98.replay-upload.v1', hex, secret, { encoding: 'hex' }), { version: 1, until: 5 });
  assert.equal(readCapability('ten98.replay-upload.v1', hex, secret), null);
});

test('tokens issued by the apps before this release still verify', () => {
  // Campaign unsubscribe links (base64url signature) and Discover replay tokens (hex signature), built exactly as the apps do.
  const campaignBody = Buffer.from(JSON.stringify(['p', 'a@example.com'])).toString('base64url');
  const campaign = `${campaignBody}.${createHmac('sha256', secret).update(`direct-unsubscribe:${campaignBody}`).digest('base64url')}`;
  assert.deepEqual(readCapability('direct-unsubscribe', campaign, secret, { maxLength: 1000 }), ['p', 'a@example.com']);
  const discoverBody = Buffer.from(JSON.stringify({ version: 1, id: 'r' })).toString('base64url');
  const discover = `${discoverBody}.${createHmac('sha256', secret).update(`ten98.replay-upload.v1:${discoverBody}`).digest('hex')}`;
  assert.deepEqual(readCapability('ten98.replay-upload.v1', discover, secret, { encoding: 'hex' }), { version: 1, id: 'r' });
  assert.equal(signCapability('direct-unsubscribe', ['p', 'a@example.com'], secret), campaign);
});

test('tampered, malformed, over-length or non-canonical tokens read as null', () => {
  const token = signCapability('direct-unsubscribe', { a: 1 }, secret);
  const [body, signature] = token.split('.') as [string, string];
  const flip = (text: string, at: number) => text.slice(0, at) + (text[at] === 'A' ? 'B' : 'A') + text.slice(at + 1);
  for (const value of [
    `${flip(body, 0)}.${signature}`, `${body}.${flip(signature, 0)}`, `${body}.${signature}.x`, `${body}`, `.${signature}`,
    `${body}=.${signature}`, `${body}.${signature}=`, '', 42, null, undefined, `${body}.${signature.slice(0, 42)}`,
  ]) assert.equal(readCapability('direct-unsubscribe', value, secret), null, String(value));
  assert.equal(readCapability('direct-unsubscribe', token, secret, { maxLength: token.length - 1 }), null);
  // The last base64url character has spare bits: a second spelling of the same digest is refused.
  const last = signature.at(-1)!, alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_', index = alphabet.indexOf(last);
  const twin = signature.slice(0, -1) + alphabet[(index & ~3) | ((index + 1) & 3)];
  assert.notEqual(twin, signature);
  assert.deepEqual(Buffer.from(twin, 'base64url'), Buffer.from(signature, 'base64url'));
  assert.equal(readCapability('direct-unsubscribe', `${body}.${twin}`, secret), null);
  // A signed body that is not JSON reads as null too.
  const junk = Buffer.from('not json').toString('base64url');
  assert.equal(readCapability('direct-unsubscribe', `${junk}.${createHmac('sha256', secret).update(`direct-unsubscribe:${junk}`).digest('base64url')}`, secret), null);
});

test('configuration errors throw instead of silently failing', () => {
  for (const purpose of ['', 'a:b', 'a b', 'x'.repeat(129)]) assert.throws(() => signCapability(purpose, 1, secret), TypeError, purpose);
  assert.throws(() => signCapability('p', 1, 'short'), TypeError);
  assert.throws(() => signCapability('p', undefined, secret), TypeError);
  assert.throws(() => readCapability('p', 'x.y', secret, { encoding: 'base32' as 'hex' }), TypeError);
  assert.throws(() => readCapability('p', 'x.y', secret, { maxLength: 0 }), TypeError);
});
