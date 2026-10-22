import assert from 'node:assert/strict';
import { createSign, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { verifySnsMessage } from '../sns-notification.mjs';

// A throwaway key and self-signed certificate stand in for the AWS signing certificate; nothing touches the network.
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const der = (tag, ...parts) => {
  const body = Buffer.concat(parts);
  const length = body.length < 128 ? Buffer.from([body.length]) : (bytes => Buffer.from([0x80 | bytes.length, ...bytes]))([...Buffer.from(body.length.toString(16).padStart(body.length > 255 ? 4 : 2, '0'), 'hex')]);
  return Buffer.concat([Buffer.from([tag]), length, body]);
};
const oid = hex => der(0x06, Buffer.from(hex, 'hex'));
const utcTime = ms => der(0x17, Buffer.from(new Date(ms).toISOString().replace(/^\d\d|[-:T]|\.\d+/g, ''), 'ascii'));
function selfSignedPem(notBefore, notAfter) {
  const sha256WithRsa = der(0x30, oid('2a864886f70d01010b'), Buffer.from([0x05, 0x00]));
  const name = der(0x30, der(0x31, der(0x30, oid('550403'), der(0x0c, Buffer.from('sns.amazonaws.com')))));
  const tbs = der(0x30, der(0xa0, der(0x02, Buffer.from([2]))), der(0x02, Buffer.from([1])), sha256WithRsa, name,
    der(0x30, utcTime(notBefore), utcTime(notAfter)), name, publicKey.export({ type: 'spki', format: 'der' }));
  const signature = createSign('sha256').update(tbs).sign(privateKey);
  const cert = der(0x30, tbs, sha256WithRsa, der(0x03, Buffer.from([0]), signature));
  return `-----BEGIN CERTIFICATE-----\n${cert.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
}
const day = 86_400_000;
const pem = selfSignedPem(Date.now() - day, Date.now() + day);
assert.ok(new X509Certificate(pem).publicKey.equals(publicKey));

const envelope = name => JSON.parse(readFileSync(new URL(`./fixtures/ses-feedback/sns-envelope-${name}.json`, import.meta.url), 'utf8'));
const FIELDS = {
  Notification: ['Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type'],
  SubscriptionConfirmation: ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type'],
};
function signed(message, key = privateKey) {
  const body = { ...message, Timestamp: message.Timestamp === 'now' ? new Date().toISOString() : message.Timestamp };
  const text = FIELDS[body.Type].filter(name => body[name] !== undefined).map(name => `${name}\n${body[name]}\n`).join('');
  return JSON.stringify({ ...body, Signature: createSign('RSA-SHA256').update(text).sign(key, 'base64') });
}
const notification = (changes = {}) => ({ ...envelope('notification'), Timestamp: 'now', ...changes });
const confirmation = (changes = {}) => ({ ...envelope('subscription-confirmation'), Timestamp: 'now', ...changes });
const TOPIC = 'arn:aws:sns:us-east-1:123456789012:ses-feedback';
function options(extra = {}) {
  const fetched = [];
  return { fetched, allowedRegions: ['us-east-1'], topicArns: [TOPIC], fetchCertificate: async url => (fetched.push(url), pem), ...extra };
}

test('a valid SignatureVersion 2 Notification verifies and parses its SES message', async () => {
  const opts = options();
  const result = await verifySnsMessage(signed(notification({ Subject: 'Amazon SES Email Event Notification' })), opts);
  assert.equal(result.ok, true);
  assert.equal(result.duplicate, false);
  assert.equal(result.type, 'Notification');
  assert.equal(result.messageId, '22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324');
  assert.equal(result.subject, 'Amazon SES Email Event Notification');
  assert.equal(result.message.bounce.bounceType, 'Permanent');
  assert.deepEqual(opts.fetched, ['https://sns.us-east-1.amazonaws.com/SimpleNotificationService-9c6465fa7f48f5cacd23014631ec1136.pem']);
  const plain = await verifySnsMessage(signed(notification({ Message: 'not json' })), options());
  assert.deepEqual([plain.ok, plain.rawMessage, 'message' in plain, 'subject' in plain], [true, 'not json', false, false]);
});

test('a SubscriptionConfirmation returns the SubscribeURL on the constant SNS origin only after verification', async () => {
  const result = await verifySnsMessage(signed(confirmation()), options());
  assert.equal(result.ok, true);
  assert.equal(result.type, 'SubscriptionConfirmation');
  assert.equal(result.subscribeUrl, envelope('subscription-confirmation').SubscribeURL);
  for (const SubscribeURL of [
    'https://sns.us-east-1.amazonaws.com.evil.example/?Action=ConfirmSubscription&TopicArn=' + TOPIC,
    'https://sns.us-west-2.amazonaws.com/?Action=ConfirmSubscription&TopicArn=' + TOPIC,
    'https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&TopicArn=' + TOPIC,
    'https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:us-east-1:123456789012:other',
    'https://user@sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=' + TOPIC,
  ]) assert.deepEqual(await verifySnsMessage(signed(confirmation({ SubscribeURL })), options()), { ok: false, reason: 'subscribe-url' }, SubscribeURL);
  const tampered = JSON.parse(signed(confirmation()));
  tampered.SubscribeURL = 'https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=' + TOPIC + '&Token=other';
  assert.deepEqual(await verifySnsMessage(JSON.stringify(tampered), options()), { ok: false, reason: 'signature' });
});

test('a bad signature, a different key and SignatureVersion 1 are rejected', async () => {
  const body = JSON.parse(signed(notification()));
  assert.deepEqual(await verifySnsMessage(JSON.stringify({ ...body, Message: '{"tampered":true}' }), options()), { ok: false, reason: 'signature' });
  assert.deepEqual(await verifySnsMessage(JSON.stringify({ ...body, Signature: 'AAAA' }), options()), { ok: false, reason: 'signature' });
  assert.deepEqual(await verifySnsMessage(JSON.stringify({ ...body, Signature: 'not base64!' }), options()), { ok: false, reason: 'signature' });
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  assert.deepEqual(await verifySnsMessage(signed(notification(), other), options()), { ok: false, reason: 'signature' });
  const opts = options();
  assert.deepEqual(await verifySnsMessage(signed(notification({ SignatureVersion: '1' })), opts), { ok: false, reason: 'unsupported-signature-version' });
  assert.deepEqual(opts.fetched, []);
});

test('only an https certificate URL on an allowlisted regional SNS origin is fetched', async () => {
  for (const SigningCertURL of [
    'https://sns.us-east-1.amazonaws.com.evil.example/SimpleNotificationService-1.pem',
    'http://sns.us-east-1.amazonaws.com/SimpleNotificationService-1.pem',
    'https://sns.us-east-1.amazonaws.com:8443/SimpleNotificationService-1.pem',
    'https://user:pass@sns.us-east-1.amazonaws.com/SimpleNotificationService-1.pem',
    'https://sns.us-east-1.amazonaws.com./SimpleNotificationService-1.pem',
    'https://sns.us-west-2.amazonaws.com/SimpleNotificationService-1.pem',
    'https://evil.example/sns.us-east-1.amazonaws.com/SimpleNotificationService-1.pem',
    'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-1.pem?x=1',
    'https://sns.us-east-1.amazonaws.com/SimpleNotificationService-1.pem#x',
    'https://sns.us-east-1.amazonaws.com/a/../SimpleNotificationService-1.crt',
    'https://sns.us-east-1.amazonaws.com/a%2Fb.pem',
    'not a url',
  ]) {
    const opts = options();
    assert.deepEqual(await verifySnsMessage(signed(notification({ SigningCertURL })), opts), { ok: false, reason: 'certificate-url' }, SigningCertURL);
    assert.deepEqual(opts.fetched, []);
  }
});

test('the topic must be expected and in the certificate region', async () => {
  assert.deepEqual(await verifySnsMessage(signed(notification({ TopicArn: 'arn:aws:sns:us-east-1:123456789012:other' })), options()), { ok: false, reason: 'topic' });
  const west = 'arn:aws:sns:us-west-2:123456789012:ses-feedback';
  assert.deepEqual(await verifySnsMessage(signed(notification({ TopicArn: west })), options({ allowedRegions: ['us-east-1', 'us-west-2'], topicArns: [TOPIC, west] })), { ok: false, reason: 'region-mismatch' });
});

test('stale or unparseable timestamps are rejected before the certificate is fetched', async () => {
  for (const Timestamp of [new Date(Date.now() - 3_600_001).toISOString(), new Date(Date.now() + 3_660_000).toISOString(), 'yesterday']) {
    const opts = options();
    assert.deepEqual(await verifySnsMessage(signed(notification({ Timestamp })), opts), { ok: false, reason: 'stale' }, Timestamp);
    assert.deepEqual(opts.fetched, []);
  }
  const old = new Date(Date.now() - 2 * 3_600_000).toISOString();
  assert.equal((await verifySnsMessage(signed(notification({ Timestamp: old })), options({ maxAgeMs: 3 * 3_600_000 }))).ok, true);
});

test('a verified duplicate MessageId short-circuits', async () => {
  const seen = [];
  const result = await verifySnsMessage(signed(notification()), options({ isDuplicate: async id => (seen.push(id), true) }));
  assert.deepEqual(result, { ok: true, duplicate: true, type: 'Notification', messageId: '22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324' });
  const forged = JSON.stringify({ ...JSON.parse(signed(notification())), Message: 'x' });
  assert.deepEqual(await verifySnsMessage(forged, options({ isDuplicate: async id => (seen.push(id), true) })), { ok: false, reason: 'signature' });
  assert.equal(seen.length, 1);
});

test('malformed bodies, unsupported types and certificate failures are rejected without echoing input', async () => {
  for (const body of ['{', '[]', 'null', '"x"', JSON.stringify({ ...notification(), Timestamp: 1 }), JSON.stringify({ ...notification(), Subject: 5 })]) {
    assert.deepEqual(await verifySnsMessage(body, options()), { ok: false, reason: 'malformed' }, body);
  }
  assert.deepEqual(await verifySnsMessage(signed(notification({ Type: 'Notification' })).replace('"Notification"', '"Other"'), options()), { ok: false, reason: 'unsupported-type' });
  assert.deepEqual(await verifySnsMessage('x'.repeat(1_048_577), options()), { ok: false, reason: 'too-large' });
  const body = signed(notification());
  assert.deepEqual(await verifySnsMessage(body, options({ fetchCertificate: async () => { throw new Error('network'); } })), { ok: false, reason: 'certificate-unavailable' });
  assert.deepEqual(await verifySnsMessage(body, options({ fetchCertificate: async () => 'not a pem' })), { ok: false, reason: 'certificate-invalid' });
  const expired = selfSignedPem(Date.now() - 2 * day, Date.now() - day);
  assert.deepEqual(await verifySnsMessage(body, options({ fetchCertificate: async () => expired })), { ok: false, reason: 'certificate-invalid' });
  const result = await verifySnsMessage(signed(notification({ Message: '<script>secret</script>' })).replace('"Notification"', '"Bogus"'), options());
  assert.doesNotMatch(JSON.stringify(result), /secret/);
});

test('configuration outside the constant region map or without topics throws', async () => {
  const body = signed(notification());
  for (const extra of [{ allowedRegions: [] }, { allowedRegions: ['evil.example'] }, { allowedRegions: ['toString'] }, { topicArns: [] }, { maxAgeMs: 0 }]) {
    await assert.rejects(verifySnsMessage(body, options(extra)), { code: 'SNS_CONFIG' });
  }
});
