import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import test from 'node:test';
import { SES_REGIONS, deriveAwsV4SigningKey, sendSesEmail, sesOrigin, signAwsV4Request } from '../ses-email.mjs';

const sha = text => createHash('sha256').update(text).digest('hex');
const DATE = new Date('2026-10-23T08:09:10.123Z');
const CREDENTIALS = Object.freeze({ accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' });
const MESSAGE = Object.freeze({ from: 'Ten98 <noreply@mail.ten98.io>', to: 'reader@example.com', subject: 'Welcome', text: 'Hello', html: '<p>Hello</p>' });

function stubFetch(respond = () => new Response(JSON.stringify({ MessageId: '0100-abc-000000' }), { status: 200 })) {
  const calls = [];
  const fetch = async (url, init) => { calls.push({ url, init }); return respond(init); };
  return { calls, fetch };
}
const send = (overrides = {}) => sendSesEmail({ region: 'eu-west-1', credentials: CREDENTIALS, message: MESSAGE, now: () => DATE, ...overrides });
const fails = (promise, expected) => assert.rejects(promise, error => {
  for (const [key, value] of Object.entries(expected)) assert.deepEqual(error[key], value, key);
  return true;
});

// Known answer from AWS "Examples of how to derive a signing key for Signature Version 4",
// https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html (now redirected to the IAM user guide's
// create-signed-request page; the values are on the archived page): key wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
// date 20120215, region us-east-1, service iam.
test('signing key derivation matches the AWS documentation example', () => {
  assert.equal(Buffer.from(deriveAwsV4SigningKey('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', '20120215', 'us-east-1', 'iam')).toString('hex'),
    'f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d');
});

// Vectors from the AWS SigV4 test suite as published in awslabs/aws-c-auth tests/aws-signing-test-suite/v4
// (context: AKIDEXAMPLE, us-east-1, service "service", 2015-08-30T12:36:00Z).
const SUITE = { credentials: { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' }, region: 'us-east-1', service: 'service', host: 'example.amazonaws.com', method: 'POST', path: '/', date: new Date('2015-08-30T12:36:00Z') };
const authorization = (signedHeaders, signature) => `AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=${signedHeaders}, Signature=${signature}`;

test('signing reproduces the AWS SigV4 suite post-vanilla, post-x-www-form-urlencoded and post-sts-header-before vectors', () => {
  assert.deepEqual(signAwsV4Request(SUITE), {
    'x-amz-date': '20150830T123600Z',
    authorization: authorization('host;x-amz-date', '5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b'),
  });

  const body = 'Param1=value1';
  const form = signAwsV4Request({ ...SUITE, body, headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': '13', 'x-amz-content-sha256': sha(body) } });
  assert.equal(form.authorization, authorization('content-length;content-type;host;x-amz-content-sha256;x-amz-date', 'd3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b'));

  const sessionToken = 'AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==';
  const sts = signAwsV4Request({ ...SUITE, credentials: { ...SUITE.credentials, sessionToken } });
  assert.equal(sts['x-amz-security-token'], sessionToken);
  assert.equal(sts.authorization, authorization('host;x-amz-date;x-amz-security-token', '85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead'));
});

test('sendSesEmail posts the exact signed SES v2 request to the fixed regional origin', async () => {
  const { calls, fetch } = stubFetch();
  assert.deepEqual(await send({ fetch, configurationSetName: 'transactional', idempotencyKey: 'invite-42',
    message: { ...MESSAGE, replyTo: 'support@ten98.io', headers: { 'List-Unsubscribe': '<https://ten98.io/u/abc>', 'List-Unsubscribe-Post': 'List-Unsubscribe=One-Click' } } }),
  { accepted: true, messageId: '0100-abc-000000' });

  assert.equal(calls.length, 1);
  const [{ url, init }] = calls;
  assert.equal(url, 'https://email.eu-west-1.amazonaws.com/v2/email/outbound-emails');
  assert.equal(init.method, 'POST');
  assert.equal(init.redirect, 'error');
  assert.equal(init.credentials, 'omit');
  assert.ok(init.signal instanceof AbortSignal);
  const expectedBody = JSON.stringify({
    FromEmailAddress: 'Ten98 <noreply@mail.ten98.io>',
    Destination: { ToAddresses: ['reader@example.com'] },
    ReplyToAddresses: ['support@ten98.io'],
    Content: { Simple: {
      Subject: { Data: 'Welcome', Charset: 'UTF-8' },
      Body: { Text: { Data: 'Hello', Charset: 'UTF-8' }, Html: { Data: '<p>Hello</p>', Charset: 'UTF-8' } },
      Headers: [{ Name: 'List-Unsubscribe', Value: '<https://ten98.io/u/abc>' }, { Name: 'List-Unsubscribe-Post', Value: 'List-Unsubscribe=One-Click' }],
    } },
    ConfigurationSetName: 'transactional',
    EmailTags: [{ Name: 'idempotency-key', Value: 'invite-42' }],
  });
  assert.equal(init.body, expectedBody);

  // Independent reference signature for this exact request, written out from the SigV4 steps.
  const canonicalRequest = ['POST', '/v2/email/outbound-emails', '', 'content-type:application/json', 'host:email.eu-west-1.amazonaws.com',
    'x-amz-date:20261023T080910Z', '', 'content-type;host;x-amz-date', sha(expectedBody)].join('\n');
  const stringToSign = ['AWS4-HMAC-SHA256', '20261023T080910Z', '20261023/eu-west-1/ses/aws4_request', sha(canonicalRequest)].join('\n');
  let key = Buffer.from('AWS4' + CREDENTIALS.secretAccessKey);
  for (const part of ['20261023', 'eu-west-1', 'ses', 'aws4_request']) key = createHmac('sha256', key).update(part).digest();
  const signature = createHmac('sha256', key).update(stringToSign).digest('hex');
  assert.deepEqual(init.headers, {
    'content-type': 'application/json',
    'x-amz-date': '20261023T080910Z',
    authorization: `AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261023/eu-west-1/ses/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=${signature}`,
  });
});

test('a session token is sent and signed as x-amz-security-token', async () => {
  const { calls, fetch } = stubFetch();
  await send({ fetch, credentials: { ...CREDENTIALS, sessionToken: 'FwoGZXIvYXdzEXAMPLE/token==' } });
  const { headers } = calls[0].init;
  assert.equal(headers['x-amz-security-token'], 'FwoGZXIvYXdzEXAMPLE/token==');
  assert.match(headers.authorization, /SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, /);
});

test('regions come only from the allowlist of constant origins', async () => {
  assert.equal(Object.isFrozen(SES_REGIONS), true);
  assert.ok(SES_REGIONS.includes('us-east-1') && SES_REGIONS.includes('eu-central-2'));
  for (const region of SES_REGIONS) assert.equal(sesOrigin(region), `https://email.${region}.amazonaws.com`);
  const { calls, fetch } = stubFetch();
  for (const region of ['us-gov-west-1', 'cn-north-1', 'EU-WEST-1', 'evil.example/', 'eu-west-1.attacker.net', '__proto__', 'toString', '', undefined]) {
    await fails(send({ fetch, region }), { code: 'INVALID_REGION' });
  }
  assert.equal(calls.length, 0);
});

test('header injection and malformed input are refused before any request', async () => {
  const { calls, fetch } = stubFetch();
  const cases = [
    { subject: 'Hi\r\nBcc: victim@example.com' },
    { subject: 'Hi\nthere' },
    { to: 'reader@example.com\r\nBcc: victim@example.com' },
    { to: ['reader@example.com', 'second@example.com'] },
    { to: 'not-an-address' },
    { from: 'Evil, other@attacker.net <noreply@mail.ten98.io>' },
    { from: 'Name\r\n <noreply@mail.ten98.io>' },
    { replyTo: 'a@b.com, c@d.com' },
    { headers: { 'List-Unsubscribe': '<https://x>\r\nBcc: victim@example.com' } },
    { headers: { 'X-Bad:Name': 'v' } },
    { headers: { 'X Space': 'v' } },
    { headers: { Bcc: 'victim@example.com' } },
    { headers: { 'X-SES-CONFIGURATION-SET': 'other' } },
    { headers: { 'X-Tag': 'v', 'x-tag': 'w' } },
    { headers: Object.fromEntries(Array.from({ length: 16 }, (_, index) => [`X-H${index}`, 'v'])) },
    { text: undefined, html: undefined },
  ];
  for (const change of cases) await fails(send({ fetch, message: { ...MESSAGE, ...change } }), { code: 'INVALID_INPUT' });
  await fails(send({ fetch, idempotencyKey: 'has space' }), { code: 'INVALID_INPUT' });
  await fails(send({ fetch, configurationSetName: 'bad/name' }), { code: 'INVALID_INPUT' });
  await fails(send({ fetch, credentials: { ...CREDENTIALS, secretAccessKey: 'secret\nvalue' } }), { code: 'INVALID_INPUT' });
  await fails(send({ fetch, credentials: { ...CREDENTIALS, accessKeyId: 'akid\r\nx' } }), { code: 'INVALID_INPUT' });
  assert.equal(calls.length, 0);
  // Positive controls: the same validators admit ordinary values.
  await send({ fetch, message: { ...MESSAGE, from: 'noreply@mail.ten98.io', html: undefined, headers: { 'X-Entity-Ref-ID': 'abc-123' } } });
  assert.equal(calls.length, 1);
});

const rejection = (status, type, { inHeader = true } = {}) => () => new Response(
  JSON.stringify(inHeader ? { message: 'Email address is not verified: reader@example.com' } : { __type: `com.amazonaws.sesv2#${type}`, message: 'detail' }),
  { status, headers: inHeader ? { 'x-amzn-ErrorType': `${type}:http://internal.amazon.com/coral/com.amazonaws.sesv2/` } : {} });

test('definite SES rejections carry the SES error type and a safe message', async () => {
  const types = [[400, 'MessageRejected'], [400, 'MailFromDomainNotVerifiedException'], [400, 'AccountSuspendedException'],
    [400, 'SendingPausedException'], [400, 'BadRequestException'], [404, 'NotFoundException'], [403, 'AccessDeniedException']];
  for (const [status, type] of types) {
    for (const inHeader of [true, false]) {
      const { fetch } = stubFetch(rejection(status, type, { inHeader }));
      await assert.rejects(send({ fetch }), error => {
        assert.deepEqual([error.code, error.uncertain, error.retryable, error.status], [type, false, false, status]);
        assert.doesNotMatch(error.message, /reader@example\.com|detail|wJalr|AKIA/);
        return true;
      });
    }
  }
  const { fetch } = stubFetch(() => new Response('<html>oops</html>', { status: 400 }));
  await fails(send({ fetch }), { code: 'HTTP_400', uncertain: false, retryable: false });
  const injected = stubFetch(() => new Response('{}', { status: 400, headers: { 'x-amzn-ErrorType': 'Bad Type<script>' } }));
  await fails(send({ fetch: injected.fetch }), { code: 'HTTP_400' });
});

test('throttling is retryable and not uncertain', async () => {
  for (const respond of [rejection(429, 'TooManyRequestsException'), rejection(400, 'ThrottlingException'), () => new Response('', { status: 429 })]) {
    const { fetch } = stubFetch(respond);
    await assert.rejects(send({ fetch }), error => error.retryable === true && error.uncertain === false && /Throttl|TooMany/.test(error.code));
  }
});

test('server failures and unreadable acceptances are uncertain', async () => {
  for (const [status, type] of [[500, 'InternalFailure'], [503, 'ServiceUnavailable']]) {
    const { fetch } = stubFetch(rejection(status, type));
    await fails(send({ fetch }), { code: type, uncertain: true, retryable: false, status });
  }
  for (const body of ['not json', '{}', JSON.stringify({ MessageId: 42 }), JSON.stringify({ MessageId: 'line\nbreak' })]) {
    const { fetch } = stubFetch(() => new Response(body, { status: 200 }));
    await fails(send({ fetch }), { code: 'INVALID_RESPONSE', uncertain: true, retryable: false });
  }
});

test('network failures, aborts and timeouts after sending are uncertain', async () => {
  const network = stubFetch(() => { throw new TypeError('fetch failed'); });
  await fails(send({ fetch: network.fetch }), { code: 'NETWORK_ERROR', uncertain: true, retryable: false });

  const hang = init => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true }));
  const controller = new AbortController();
  const aborted = stubFetch(hang);
  const pending = send({ fetch: aborted.fetch, signal: controller.signal });
  controller.abort();
  await fails(pending, { code: 'ABORTED', uncertain: true, retryable: false });

  const timed = stubFetch(hang);
  await fails(send({ fetch: timed.fetch, signal: AbortSignal.timeout(5) }), { code: 'TIMEOUT', uncertain: true });

  const before = stubFetch();
  await fails(send({ fetch: before.fetch, signal: AbortSignal.abort() }), { code: 'ABORTED', uncertain: false });
  assert.equal(before.calls.length, 0);
});
