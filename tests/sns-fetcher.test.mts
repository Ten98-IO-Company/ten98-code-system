import assert from 'node:assert/strict';
import test from 'node:test';
import { confirmSnsSubscription, createSnsCertificateFetcher, snsRefusalStatus } from '../index.mjs';
import type { SnsRejection } from '../index.mjs';

// Stubbed transports only; nothing reaches AWS.
const CERT = 'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0123abcd.pem';
const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';
type Call = { url: string; init: RequestInit };
function transport(reply: (call: Call) => Response | Promise<Response>) {
  const calls: Call[] = [];
  return { calls, fetch: async (url: string, init: RequestInit) => { const call = { url, init }; calls.push(call); return reply(call); } };
}

test('the certificate fetcher caches each certificate and sends a bounded, credential-free GET', async () => {
  const stub = transport(() => new Response(PEM));
  const fetchCertificate = createSnsCertificateFetcher({ fetch: stub.fetch });
  assert.equal(await fetchCertificate(CERT), PEM);
  assert.equal(await fetchCertificate(CERT), PEM);
  assert.equal(stub.calls.length, 1);
  const { url, init } = stub.calls[0]!;
  assert.equal(url, CERT);
  assert.deepEqual([init.method, init.redirect, init.credentials], ['GET', 'error', 'omit']);
  assert.ok(init.signal instanceof AbortSignal);
  // The cache is cleared when it reaches maxEntries, so a third certificate evicts the first two.
  const small = transport(() => new Response(PEM));
  const limited = createSnsCertificateFetcher({ fetch: small.fetch, maxEntries: 2 });
  for (const name of ['a', 'b', 'c', 'a']) await limited(`https://sns.us-east-1.amazonaws.com/${name}.pem`);
  assert.equal(small.calls.length, 4);
});

test('the certificate fetcher backs off after a failure and asks the budget before each network fetch', async () => {
  let clock = 1_000;
  let fail = true;
  const stub = transport(() => fail ? new Response('down', { status: 503 }) : new Response(PEM));
  const admitted: boolean[] = [];
  let allow = true;
  const fetchCertificate = createSnsCertificateFetcher({ fetch: stub.fetch, now: () => clock, failureBackoffMs: 60_000, admit: () => { admitted.push(allow); return allow; } });
  await assert.rejects(fetchCertificate(CERT));
  fail = false;
  await assert.rejects(fetchCertificate(CERT), /recently/);
  assert.equal(stub.calls.length, 1);
  clock += 60_001;
  assert.equal(await fetchCertificate(CERT), PEM);
  assert.equal(stub.calls.length, 2);
  // Cached certificates do not use the budget; a refused budget sends nothing.
  await fetchCertificate(CERT);
  assert.equal(admitted.length, 2);
  allow = false;
  await assert.rejects(fetchCertificate('https://sns.us-east-1.amazonaws.com/other.pem'), /budget/);
  assert.equal(stub.calls.length, 2);
});

test('the certificate fetcher refuses non-SNS URLs and oversized or failed replies', async () => {
  const stub = transport(() => new Response(PEM));
  const fetchCertificate = createSnsCertificateFetcher({ fetch: stub.fetch });
  for (const url of [
    'http://sns.us-east-1.amazonaws.com/a.pem', 'https://sns.us-east-1.amazonaws.com.evil.example/a.pem', 'https://evil.example/a.pem',
    'https://sns.us-east-1.amazonaws.com/a.pem?x=1', 'https://sns.us-east-1.amazonaws.com/a/b.pem', 'https://sns.us-east-1.amazonaws.com/a.txt',
    'https://user@sns.us-east-1.amazonaws.com/a.pem', 'https://sns.us-east-1.amazonaws.com:8443/a.pem', 'not a url',
  ]) await assert.rejects(fetchCertificate(url), /Not an SNS certificate URL/, url);
  assert.equal(stub.calls.length, 0);
  const big = createSnsCertificateFetcher({ fetch: transport(() => new Response('x'.repeat(100))).fetch, maxBytes: 50 });
  await assert.rejects(big(CERT));
  const broken = createSnsCertificateFetcher({ fetch: transport(() => { throw new TypeError('fetch failed'); }).fetch });
  await assert.rejects(broken(CERT));
  for (const options of [{ timeoutMs: 0 }, { maxBytes: 0 }, { maxEntries: 1.5 }, { failureBackoffMs: -1 }]) assert.throws(() => createSnsCertificateFetcher(options), (error: unknown) => (error as { code?: string }).code === 'SNS_CONFIG');
});

test('snsRefusalStatus asks SNS to retry only when the certificate was unavailable', () => {
  const reasons: SnsRejection[] = ['too-large', 'malformed', 'unsupported-type', 'unsupported-signature-version', 'certificate-url', 'topic', 'region-mismatch', 'stale', 'certificate-unavailable', 'certificate-invalid', 'signature', 'subscribe-url'];
  for (const reason of reasons) assert.equal(snsRefusalStatus(reason), reason === 'certificate-unavailable' ? 503 : 403, reason);
});

test('confirmSnsSubscription fetches only SNS ConfirmSubscription URLs and fails on a non-2xx reply', async () => {
  const url = 'https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn%3Aaws%3Asns%3Aus-east-1%3A123456789012%3Afeedback&Token=abc';
  const stub = transport(() => new Response('<ConfirmSubscriptionResponse/>'));
  await confirmSnsSubscription(url, { fetch: stub.fetch });
  assert.equal(stub.calls[0]!.url, url);
  assert.deepEqual([stub.calls[0]!.init.redirect, stub.calls[0]!.init.credentials], ['error', 'omit']);
  for (const bad of ['https://evil.example/?Action=ConfirmSubscription', 'https://sns.us-east-1.amazonaws.com/x?Action=ConfirmSubscription', 'https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe', 'nope']) {
    await assert.rejects(confirmSnsSubscription(bad, { fetch: stub.fetch }), /Not an SNS subscription confirmation URL/, bad);
  }
  assert.equal(stub.calls.length, 1);
  await assert.rejects(confirmSnsSubscription(url, { fetch: transport(() => new Response('', { status: 500 })).fetch }));
});
