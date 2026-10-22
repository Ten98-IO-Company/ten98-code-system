// Amazon SNS HTTP(S) message verification for SES feedback and other topic subscriptions.
// The caller fetches and caches signing certificates and records processed message ids, so this module does no I/O itself.
// Procedure: https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html
// and https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message-verify-message-signature.html
import { createVerify, X509Certificate } from 'node:crypto';
// Constant origins, so a certificate or confirmation request can only ever reach an AWS SNS endpoint.
// The aws and aws-us-gov partitions share the sns.<region>.amazonaws.com form; China (amazonaws.com.cn) is not supported.
const SNS_ORIGINS = Object.freeze({
    'af-south-1': 'https://sns.af-south-1.amazonaws.com',
    'ap-east-1': 'https://sns.ap-east-1.amazonaws.com',
    'ap-east-2': 'https://sns.ap-east-2.amazonaws.com',
    'ap-northeast-1': 'https://sns.ap-northeast-1.amazonaws.com',
    'ap-northeast-2': 'https://sns.ap-northeast-2.amazonaws.com',
    'ap-northeast-3': 'https://sns.ap-northeast-3.amazonaws.com',
    'ap-south-1': 'https://sns.ap-south-1.amazonaws.com',
    'ap-south-2': 'https://sns.ap-south-2.amazonaws.com',
    'ap-southeast-1': 'https://sns.ap-southeast-1.amazonaws.com',
    'ap-southeast-2': 'https://sns.ap-southeast-2.amazonaws.com',
    'ap-southeast-3': 'https://sns.ap-southeast-3.amazonaws.com',
    'ap-southeast-4': 'https://sns.ap-southeast-4.amazonaws.com',
    'ap-southeast-5': 'https://sns.ap-southeast-5.amazonaws.com',
    'ap-southeast-6': 'https://sns.ap-southeast-6.amazonaws.com',
    'ap-southeast-7': 'https://sns.ap-southeast-7.amazonaws.com',
    'ca-central-1': 'https://sns.ca-central-1.amazonaws.com',
    'ca-west-1': 'https://sns.ca-west-1.amazonaws.com',
    'eu-central-1': 'https://sns.eu-central-1.amazonaws.com',
    'eu-central-2': 'https://sns.eu-central-2.amazonaws.com',
    'eu-north-1': 'https://sns.eu-north-1.amazonaws.com',
    'eu-south-1': 'https://sns.eu-south-1.amazonaws.com',
    'eu-south-2': 'https://sns.eu-south-2.amazonaws.com',
    'eu-west-1': 'https://sns.eu-west-1.amazonaws.com',
    'eu-west-2': 'https://sns.eu-west-2.amazonaws.com',
    'eu-west-3': 'https://sns.eu-west-3.amazonaws.com',
    'il-central-1': 'https://sns.il-central-1.amazonaws.com',
    'me-central-1': 'https://sns.me-central-1.amazonaws.com',
    'me-south-1': 'https://sns.me-south-1.amazonaws.com',
    'mx-central-1': 'https://sns.mx-central-1.amazonaws.com',
    'sa-east-1': 'https://sns.sa-east-1.amazonaws.com',
    'us-east-1': 'https://sns.us-east-1.amazonaws.com',
    'us-east-2': 'https://sns.us-east-2.amazonaws.com',
    'us-gov-east-1': 'https://sns.us-gov-east-1.amazonaws.com',
    'us-gov-west-1': 'https://sns.us-gov-west-1.amazonaws.com',
    'us-west-1': 'https://sns.us-west-1.amazonaws.com',
    'us-west-2': 'https://sns.us-west-2.amazonaws.com',
});
const MAX_BODY = 1_048_576;
// Key order of the string to sign, which is fixed per message type.
const SIGNED_FIELDS = {
    Notification: ['Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type'],
    SubscriptionConfirmation: ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type'],
    UnsubscribeConfirmation: ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type'],
};
function configError() {
    throw Object.assign(new Error('Invalid SNS verification configuration.'), { code: 'SNS_CONFIG' });
}
/** The allowlisted region whose constant origin the URL uses, or null. Userinfo, ports, fragments and trailing-dot hosts never match. */
function snsRegion(value, regions) {
    let url;
    try {
        url = new URL(value);
    }
    catch {
        return null;
    }
    if (url.username || url.password || url.hash)
        return null;
    const region = regions.find(name => url.origin === SNS_ORIGINS[name]);
    return region ? { region, url } : null;
}
function reject(reason) {
    return { ok: false, reason };
}
/**
 * Verifies a raw SNS HTTP(S) POST body: SignatureVersion 2 (SHA256withRSA) only, a certificate from an allowlisted
 * regional SNS origin, an expected TopicArn in that region and a fresh Timestamp. Rejections carry a short code and never echo input.
 * Throws SNS_CONFIG for an unknown region, an empty topic list or a non-positive maxAgeMs.
 */
export async function verifySnsMessage(rawBody, options) {
    const { allowedRegions, topicArns, fetchCertificate, isDuplicate, maxAgeMs = 3_600_000 } = options;
    if (allowedRegions.length === 0 || allowedRegions.some(region => !Object.hasOwn(SNS_ORIGINS, region)))
        configError();
    if (topicArns.length === 0 || !(maxAgeMs > 0))
        configError();
    if (typeof rawBody !== 'string')
        return reject('malformed');
    if (rawBody.length > MAX_BODY)
        return reject('too-large');
    let body;
    try {
        body = JSON.parse(rawBody);
    }
    catch {
        return reject('malformed');
    }
    if (!body || typeof body !== 'object' || Array.isArray(body))
        return reject('malformed');
    const fields = body;
    const type = fields.Type;
    if (type !== 'Notification' && type !== 'SubscriptionConfirmation' && type !== 'UnsubscribeConfirmation')
        return reject('unsupported-type');
    const signed = SIGNED_FIELDS[type];
    if (fields.Subject === null)
        delete fields.Subject;
    for (const name of [...signed, 'Signature', 'SignatureVersion', 'SigningCertURL']) {
        if (typeof fields[name] !== 'string' && !(name === 'Subject' && fields[name] === undefined))
            return reject('malformed');
    }
    const text = fields;
    // Values are joined with newlines to form the string to sign, so a newline in any field but Message could move
    // text between fields (for example fold Subject into MessageId) without changing the signature.
    if (signed.some(name => name !== 'Message' && text[name]?.includes('\n')))
        return reject('malformed');
    if (text.SignatureVersion !== '2')
        return reject('unsupported-signature-version');
    const certificate = snsRegion(text.SigningCertURL, allowedRegions);
    // AWS serves signing certificates at a single-segment path such as /SimpleNotificationService-<hex>.pem.
    if (!certificate || certificate.url.search || !/^\/[A-Za-z0-9_-]{1,128}\.pem$/.test(certificate.url.pathname))
        return reject('certificate-url');
    const { region } = certificate;
    if (!topicArns.includes(text.TopicArn))
        return reject('topic');
    // arn:<partition>:sns:<region>:<account>:<topic>
    if (text.TopicArn.split(':')[3] !== region)
        return reject('region-mismatch');
    const timestamp = Date.parse(text.Timestamp);
    const now = Date.now();
    if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > maxAgeMs)
        return reject('stale');
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text.Signature))
        return reject('signature');
    let pem;
    try {
        pem = await fetchCertificate(SNS_ORIGINS[region] + certificate.url.pathname);
    }
    catch {
        return reject('certificate-unavailable');
    }
    let x509;
    try {
        x509 = new X509Certificate(pem);
    }
    catch {
        return reject('certificate-invalid');
    }
    if (now < Date.parse(x509.validFrom) || now > Date.parse(x509.validTo))
        return reject('certificate-invalid');
    // Each present field contributes "Key\nValue\n" in the fixed order above; Subject only when present.
    const stringToSign = signed.filter(name => text[name] !== undefined).map(name => `${name}\n${text[name]}\n`).join('');
    let valid = false;
    try {
        valid = createVerify('RSA-SHA256').update(stringToSign, 'utf8').verify(x509.publicKey, text.Signature, 'base64');
    }
    catch {
        valid = false;
    }
    if (!valid)
        return reject('signature');
    const messageId = text.MessageId;
    if (await isDuplicate?.(messageId))
        return { ok: true, duplicate: true, type, messageId };
    if (type === 'SubscriptionConfirmation') {
        const confirm = snsRegion(text.SubscribeURL, [region]);
        if (!confirm || confirm.url.pathname !== '/' || confirm.url.searchParams.get('Action') !== 'ConfirmSubscription'
            || confirm.url.searchParams.get('TopicArn') !== text.TopicArn)
            return reject('subscribe-url');
        return { ok: true, duplicate: false, type, messageId, topicArn: text.TopicArn, rawMessage: text.Message, subscribeUrl: `${SNS_ORIGINS[region]}/${confirm.url.search}` };
    }
    if (type === 'UnsubscribeConfirmation')
        return { ok: true, duplicate: false, type, messageId, topicArn: text.TopicArn, rawMessage: text.Message };
    let message;
    try {
        message = JSON.parse(text.Message);
    }
    catch {
        message = undefined;
    }
    return {
        ok: true, duplicate: false, type, messageId, topicArn: text.TopicArn, rawMessage: text.Message,
        ...(message === undefined ? {} : { message }), ...(text.Subject === undefined ? {} : { subject: text.Subject }),
    };
}
