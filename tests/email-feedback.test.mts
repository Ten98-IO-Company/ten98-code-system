import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { classifyEmailFeedback, type EmailFeedbackOptions } from '../email-feedback.mjs';

// Shapes follow https://docs.aws.amazon.com/ses/latest/dg/notification-contents.html; every listed type and subtype has a fixture.
const fixture = (name: string) => JSON.parse(readFileSync(new URL(`./fixtures/ses-feedback/${name}.json`, import.meta.url), 'utf8'));
const options = { transient: { threshold: 3, windowMs: 7 * 24 * 3_600_000 } };
const actions = (event: unknown, opts: EmailFeedbackOptions = options) => classifyEmailFeedback(event, opts).map(({ recipient, action, reason }) => [recipient, action, reason]);

const expected = {
  'bounce-undetermined': ['undetermined@example.net', 'flag-undetermined', 'undetermined-bounce'],
  'bounce-permanent-general': ['unknown-user@example.net', 'suppress', 'permanent-bounce'],
  'bounce-permanent-noemail': ['noemail@example.net', 'suppress', 'permanent-bounce'],
  'bounce-permanent-suppressed': ['suppressed@example.net', 'suppress', 'permanent-bounce'],
  'bounce-permanent-on-account-suppression-list': ['account-list@example.net', 'record', 'provider-suppressed'],
  'bounce-permanent-on-tenant-suppression-list': ['tenant-list@example.net', 'record', 'provider-suppressed'],
  'bounce-permanent-email-validation-suppressed': ['invalid-shape@example.net', 'record', 'provider-suppressed'],
  'bounce-permanent-unsubscribed-recipient': ['unsubscribed@example.net', 'record', 'unsubscribed-recipient'],
  'bounce-permanent-policy-5.7.1': ['policy@example.net', 'deliverability-alert', 'policy-block'],
  'bounce-permanent-dmarc-5.7.26': ['dmarc@example.net', 'deliverability-alert', 'policy-block'],
  'bounce-transient-general': ['auto-reply@example.net', 'count-transient', 'transient-bounce'],
  'bounce-transient-mailbox-full': ['full@example.net', 'count-transient', 'transient-bounce'],
  'bounce-transient-message-too-large': ['large@example.net', 'count-transient', 'transient-bounce'],
  'bounce-transient-content-rejected': ['content@example.net', 'count-transient', 'transient-bounce'],
  'bounce-transient-attachment-rejected': ['attachment@example.net', 'count-transient', 'transient-bounce'],
  'bounce-transient-rate-limited-4.7.28': ['rate@example.net', 'deliverability-alert', 'policy-block'],
  'complaint-abuse': ['abuse@example.net', 'suppress', 'complaint'],
  'complaint-auth-failure': ['auth-failure@example.net', 'suppress', 'complaint'],
  'complaint-fraud': ['fraud@example.net', 'suppress', 'complaint'],
  'complaint-not-spam': ['not-spam@example.net', 'record', 'not-spam'],
  'complaint-other': ['other@example.net', 'suppress', 'complaint'],
  'complaint-virus': ['virus@example.net', 'suppress', 'complaint'],
  'complaint-no-feedback-type': ['no-type@example.net', 'suppress', 'complaint'],
  'event-complaint-on-account-suppression-list': ['complaint-list@example.net', 'record', 'provider-suppressed'],
  'delivery': ['delivered@example.net', 'delivered', 'delivered'],
};

test('every SES fixture maps to its documented action', () => {
  for (const [name, outcome] of Object.entries(expected)) assert.deepEqual(actions(fixture(name)), [outcome], name);
});

test('a Permanent bounce with a 5.7.x policy code never suppresses, per recipient', () => {
  assert.deepEqual(actions(fixture('bounce-multiple-recipients')), [
    ['first@example.net', 'suppress', 'permanent-bounce'],
    ['second@example.net', 'deliverability-alert', 'policy-block'],
  ]);
  const event = fixture('bounce-permanent-general');
  for (const [status, diagnosticCode, action] of [
    ['5.7.606', undefined, 'deliverability-alert'],
    [undefined, 'smtp; 550 5.7.606 Access denied, banned sending IP', 'deliverability-alert'],
    ['5.1.1', 'smtp; 550 5.1.1 user unknown; relay 10.5.7.1', 'suppress'],
    [undefined, 'smtp; 550 rejected by 5.7.1.9 gateway', 'suppress'],
    ['5.0.0', 'smtp; 550 5.7.1234 not an enhanced code', 'suppress'],
  ]) {
    event.bounce.bouncedRecipients = [{ emailAddress: 'r@example.net', status, diagnosticCode }];
    assert.equal(classifyEmailFeedback(event, options)[0].action, action, `${status} ${diagnosticCode}`);
  }
});

test('outcomes carry the subtype and feedback type', () => {
  assert.deepEqual(classifyEmailFeedback(fixture('bounce-transient-mailbox-full'), options), [{ recipient: 'full@example.net', action: 'count-transient', reason: 'transient-bounce', subType: 'MailboxFull' }]);
  assert.deepEqual(classifyEmailFeedback(fixture('complaint-fraud'), options), [{ recipient: 'fraud@example.net', action: 'suppress', reason: 'complaint', feedbackType: 'fraud' }]);
});

test('transient bounces suppress once the threshold is reached inside the window, inclusive at its boundary', () => {
  const event = fixture('bounce-transient-mailbox-full');
  const at = Date.parse(event.bounce.timestamp), { windowMs } = options.transient;
  const run = (history: number[]) => classifyEmailFeedback(event, { ...options, history: recipient => (assert.equal(recipient, 'full@example.net'), history) })[0];
  assert.equal(run([at - 1000]).action, 'count-transient');
  assert.deepEqual([run([at - windowMs, at - 1]).action, run([at - windowMs, at - 1]).reason], ['suppress', 'repeated-transient']);
  assert.equal(run([at - windowMs - 1, at - 1]).action, 'count-transient');
  assert.equal(run([at + 1, at - 1]).action, 'count-transient');
  assert.equal(classifyEmailFeedback(event, { transient: { threshold: 1, windowMs } })[0].action, 'suppress');
});

test('undetermined bounces accumulate but a single one never suppresses', () => {
  const event = fixture('bounce-undetermined');
  const at = Date.parse(event.bounce.timestamp);
  assert.equal(classifyEmailFeedback(event, { transient: { threshold: 1, windowMs: 60_000 } })[0].action, 'flag-undetermined');
  assert.equal(classifyEmailFeedback(event, { ...options, history: () => [at - 1] })[0].action, 'flag-undetermined');
  assert.equal(classifyEmailFeedback(event, { ...options, history: () => [at - 2, at - 1] })[0].action, 'suppress');
  assert.equal(classifyEmailFeedback(event, { transient: { threshold: 1, windowMs: 60_000 }, history: () => [at - 1] })[0].action, 'suppress');
});

test('Cloudflare suppression reasons map to actions, and unknown reasons are left to the caller', () => {
  const row = (reason: string, expiresAt: string | null = null) => ({ provider: 'cloudflare', email: 'cf@example.net', reason, expiresAt });
  assert.deepEqual(actions(row('hard_bounce')), [['cf@example.net', 'suppress', 'permanent-bounce']]);
  assert.deepEqual(actions(row('complaint')), [['cf@example.net', 'suppress', 'complaint']]);
  assert.deepEqual(actions(row('manual')), [['cf@example.net', 'suppress', 'manual']]);
  assert.deepEqual(actions(row('policy')), [['cf@example.net', 'deliverability-alert', 'policy-block']]);
  assert.deepEqual(classifyEmailFeedback(row('soft_bounce', '2026-10-27T00:00:00Z'), options), [
    { recipient: 'cf@example.net', action: 'count-transient', reason: 'transient-bounce', expiresAt: '2026-10-27T00:00:00Z' },
  ]);
  assert.deepEqual(actions(row('greylisted')), [['cf@example.net', 'ignore', 'unknown-reason']]);
  // A time-limited provider row keeps its expiry whatever the reason, so the caller can lift it when the provider does.
  for (const reason of ['hard_bounce', 'complaint', 'manual', 'policy', 'greylisted']) {
    assert.equal(classifyEmailFeedback(row(reason, '2026-10-27T00:00:00Z'), options)[0].expiresAt, '2026-10-27T00:00:00Z', reason);
    assert.equal('expiresAt' in classifyEmailFeedback(row(reason), options)[0], false, reason);
  }
});

test('other events are ignored, malformed input yields nothing and bad configuration throws', () => {
  const send = { eventType: 'Send', mail: fixture('delivery').mail, send: {} };
  assert.deepEqual(actions(send), [['delivered@example.net', 'ignore', 'unsupported-event']]);
  for (const value of [null, 'Bounce', [], { notificationType: 'Bounce' }, { notificationType: 'Bounce', bounce: { bounceType: 'Permanent', bouncedRecipients: [{}, 'x', null] } }]) {
    assert.deepEqual(classifyEmailFeedback(value, options), []);
  }
  for (const transient of [{ threshold: 0, windowMs: 1 }, { threshold: 1.5, windowMs: 1 }, { threshold: 2, windowMs: 0 }, { threshold: 2, windowMs: Number.NaN }]) {
    assert.throws(() => classifyEmailFeedback(fixture('delivery'), { transient }), { code: 'EMAIL_FEEDBACK_CONFIG' });
  }
});
