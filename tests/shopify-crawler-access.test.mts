import assert from 'node:assert/strict';
import test from 'node:test';
import {webcrypto} from 'node:crypto';
import { parseShopifyCrawlerAccess, shopifyCrawlerHeadersFor, verifyShopifyCrawlerAccess } from '../shopify-crawler-access.mjs';

const origin = 'https://shop.example.com';
const expiry = 2_000_000_000;
const params = `("@authority" "signature-agent");keyid="fixture";expires=${expiry}`;
async function generatePair() {
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  assert.ok('privateKey' in keys && 'publicKey' in keys);
  return keys;
}
const pair = await generatePair();
async function credential(parameters = params, host = 'shop.example.com', label = 'sig1') {
  const base = `"@authority": ${host}\n"signature-agent": "https://shopify.com"\n"@signature-params": ${parameters}`;
  const bytes = await crypto.subtle.sign('Ed25519', pair.privateKey, Buffer.from(base));
  return { origin, signatureInput: `${label}=${parameters}`, signature: `${label}=:${Buffer.from(bytes).toString('base64')}:` };
}
const valid = await credential();
const at = (parameters: string) => ({ ...valid, signatureInput: `sig1=${parameters}` });

test('parses exact bytes, original values and safe metadata without requiring unexpired access', () => {
  assert.deepEqual(parseShopifyCrawlerAccess(valid), {
    ...valid, label: 'sig1', keyId: 'fixture', parameters: params, expiresAt: new Date(expiry * 1000).toISOString(),
  });
  assert.equal(parseShopifyCrawlerAccess(at(params.replace(String(expiry), '1')))?.expiresAt, '1970-01-01T00:00:01.000Z');
  assert.equal(parseShopifyCrawlerAccess({ ...valid, ignored: 'metadata' })?.origin, origin);
});

test('verifies generated Ed25519 signatures and preserves quoted separators, escapes and parameter order', async () => {
  const ordered = `("@authority" "signature-agent");nonce="x;expires=2;\\\"\\\\";expires=${expiry};tag="";created=1900000000;alg="ed25519";keyid="a;\\\"b"`;
  const other = await credential(ordered, 'shop.example.com', '*key.a_1-2');
  assert.equal(parseShopifyCrawlerAccess(other)?.keyId, 'a;"b');
  assert.equal(parseShopifyCrawlerAccess(other)?.parameters, ordered);
  assert.equal(parseShopifyCrawlerAccess(other)?.createdAt, new Date(1_900_000_000_000).toISOString());
  assert.equal(await verifyShopifyCrawlerAccess(valid, pair.publicKey), 'valid');
  assert.equal(await verifyShopifyCrawlerAccess(other, pair.publicKey), 'valid');
  assert.equal(await verifyShopifyCrawlerAccess({ ...other, signatureInput: other.signatureInput.replace(';tag=""', '') }, pair.publicKey), 'invalid');
});

test('distinguishes a www twin from a foreign hostname in both directions', async () => {
  assert.equal(await verifyShopifyCrawlerAccess(await credential(params, 'www.shop.example.com'), pair.publicKey), 'wrong_domain');
  assert.equal(await verifyShopifyCrawlerAccess({ ...valid, origin: 'https://www.shop.example.com' }, pair.publicKey), 'wrong_domain');
  assert.equal(await verifyShopifyCrawlerAccess(await credential(params, 'foreign.example.com'), pair.publicKey), 'invalid');
});

test('accepts a native Node public key through the exported verifier without a caller cast', async () => {
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const key = await webcrypto.subtle.importKey('jwk', jwk, 'Ed25519', false, ['verify']);
  assert.equal(await verifyShopifyCrawlerAccess(valid, key), 'valid');
});

test('fails closed for malformed keys, key types, signature changes and throwing input', async () => {
  const another = await generatePair();
  const aes = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, true, ['encrypt']);
  for (const key of [pair.privateKey, another.publicKey, aes, null, {}, { type: 'public', algorithm: { name: 'Ed25519' }, usages: ['verify'] }]) {
    assert.equal(await verifyShopifyCrawlerAccess(valid, key as CryptoKey), 'invalid');
  }
  const throwing = { get origin() { throw new Error('SECRET_MUST_NOT_ESCAPE'); } };
  assert.equal(parseShopifyCrawlerAccess(throwing), null);
  assert.deepEqual(shopifyCrawlerHeadersFor(origin, throwing, 0), {});
  assert.equal(await verifyShopifyCrawlerAccess(throwing, pair.publicKey), 'invalid');
});

test('rejects unknown, duplicate, missing, hidden and partial numeric expiry parameters', () => {
  const list = '("@authority" "signature-agent")';
  for (const parameters of [
    `${list};keyid="fixture"`, `${list};keyid="x;expires=${expiry}"`,
    `${params};expires=${expiry}`, `${params};keyid="other"`, `${params};unknown="x"`,
    `${list};keyid="";expires=${expiry}`, `${list};expires=${expiry}`, `${params};alg="rsa"`,
    `${params};nonce=plain`, `${params};nonce="x`, `${params};tag="x\\q"`, `${params};tag="x"junk`,
    `${params};created=${expiry}`, `${params};created=${expiry + 1}`, `${params};created=NaN`,
    `${params};created=8640000000001`, `${params};created=1;created=2`,
    ...['0', '-1', 'NaN', 'Infinity', '2e9', '2000000000x', '2000000000.0', '2000000000 ', '9007199254740992', '8640000000001', ''].map(value => `${list};keyid="fixture";expires=${value}`),
    `${params};`, `${params},sig2=${params}`, `${params};expires`, `${params};nonce="x";`,
  ]) assert.equal(parseShopifyCrawlerAccess(at(parameters)), null, parameters);
});

test('rejects component changes, labels, noncanonical base64, wrong byte lengths and trailing data', () => {
  for (const change of [
    { signatureInput: valid.signatureInput.replace('sig1=', 'other=') },
    { signature: valid.signature.replace('sig1=', 'other=') },
    { signatureInput: valid.signatureInput.replace('sig1=', 'Bad=') },
    { signatureInput: valid.signatureInput.replace('"@authority" "signature-agent"', '"signature-agent" "@authority"') },
    { signatureInput: valid.signatureInput.replace('"signature-agent"', '"other"') },
    { signatureInput: valid.signatureInput.replace('"signature-agent"', '"signature-agent" "extra"') },
    { signature: valid.signature.replace('==:', '=:') }, { signature: `${valid.signature}junk` },
    { signature: 'sig1=:!!!!:' }, { signature: `sig1=:${Buffer.alloc(63).toString('base64')}:` },
    { signature: `sig1=:${Buffer.alloc(65).toString('base64')}:` },
    { signature: `sig1=:${Buffer.alloc(64).toString('base64').replace('AA==', 'AB==')}:` },
    { signature: valid.signature.replace('=:', '= :') },
  ]) assert.equal(parseShopifyCrawlerAccess({ ...valid, ...change }), null, JSON.stringify(change));
});

test('rejects noncanonical or nonpublic origins, controls, non-ASCII and oversized values', () => {
  for (const value of [
    'http://shop.example.com', `${origin}:444`, `${origin}:443`, `${origin}/`, `${origin}/path`, `${origin}?x`, `${origin}#x`,
    'https://user:pass@shop.example.com', 'https://@shop.example.com', 'https://SHOP.example.com',
    'https://shop.example.com.', 'https://127.0.0.1', 'https://local', 'https://shop.local', 'https://bücher.de',
  ]) assert.equal(parseShopifyCrawlerAccess({ ...valid, origin: value }), null, value);
  for (const field of ['origin', 'signatureInput', 'signature']) {
    for (const value of ['\r\nInjected: SECRET', '\0', '\t', '\x7f', 'é', 'x'.repeat(4097), '', null, 4]) {
      assert.equal(parseShopifyCrawlerAccess({ ...valid, [field]: value }), null);
    }
  }
  for (const value of [null, [], 'SECRET', 1, undefined]) assert.equal(parseShopifyCrawlerAccess(value), null);
  const prefix = `${params};nonce="`;
  assert.ok(parseShopifyCrawlerAccess(at(`${prefix}${'x'.repeat(4096 - 'sig1='.length - prefix.length - 1)}"`)));
  assert.equal(parseShopifyCrawlerAccess(at(`${prefix}${'x'.repeat(4097 - 'sig1='.length - prefix.length - 1)}"`)), null);
});

test('adds only fixed headers on the exact HTTPS origin until the expiry boundary', () => {
  const expected = { 'Signature-Input': valid.signatureInput, Signature: valid.signature, 'Signature-Agent': '"https://shopify.com"' };
  assert.deepEqual(shopifyCrawlerHeadersFor(`${origin}/products?q=1`, valid, expiry * 1000 - 1), expected);
  assert.deepEqual(shopifyCrawlerHeadersFor(`${origin}:443/products`, valid, 0), expected);
  assert.deepEqual(shopifyCrawlerHeadersFor(origin, { ...valid, Authorization: 'SECRET' }, 0), expected);
  for (const now of [expiry * 1000, expiry * 1000 + 1, NaN, Infinity, -Infinity]) {
    assert.deepEqual(shopifyCrawlerHeadersFor(origin, valid, now), {});
  }
  assert.deepEqual(shopifyCrawlerHeadersFor(origin, at(params.replace(String(expiry), '1'))), {});
  for (const url of [
    'http://shop.example.com', `${origin}:444/path`, 'https://www.shop.example.com', 'https://other.example.com',
    'https://shop.example.com.evil.com', 'https://user:pass@shop.example.com', 'https://@shop.example.com',
    ` ${origin}`, `${origin}\n`, `https:\\shop.example.com`, '/relative', 'not a url',
  ]) assert.deepEqual(shopifyCrawlerHeadersFor(url, valid, 0), {}, url);
});

test('reparses forged parsed credentials before selecting headers', () => {
  const parsed = parseShopifyCrawlerAccess(valid)!;
  assert.deepEqual(shopifyCrawlerHeadersFor(origin, { ...parsed, signatureInput: 'SECRET\r\nInjected: yes' }, 0), {});
  assert.deepEqual(shopifyCrawlerHeadersFor(origin, { ...parsed, signatureInput: parsed.signatureInput.replace(String(expiry), '1'), expiresAt: '9999-01-01T00:00:00.000Z' }, 1000), {});
  assert.deepEqual(shopifyCrawlerHeadersFor(origin, { origin, expiresAt: parsed.expiresAt, headers: { Authorization: 'SECRET' } }, 0), {});
});
