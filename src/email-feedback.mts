// Classifies Amazon SES feedback notifications and Cloudflare suppression rows into per-recipient actions.
// Pure: the caller loads prior transient history, applies the actions to its own suppression store and raises alerts.
// SES fields and bounce types: https://docs.aws.amazon.com/ses/latest/dg/notification-contents.html

export type EmailFeedbackAction = 'suppress' | 'record' | 'count-transient' | 'flag-undetermined' | 'deliverability-alert' | 'delivered' | 'ignore';
export type EmailFeedbackReason =
  | 'permanent-bounce' | 'provider-suppressed' | 'unsubscribed-recipient' | 'policy-block' | 'transient-bounce' | 'repeated-transient'
  | 'undetermined-bounce' | 'complaint' | 'not-spam' | 'manual' | 'delivered' | 'unsupported-event' | 'unknown-reason';
export interface EmailFeedbackOutcome {
  readonly recipient: string;
  readonly action: EmailFeedbackAction;
  readonly reason: EmailFeedbackReason;
  readonly subType?: string;
  readonly feedbackType?: string;
  readonly expiresAt?: string;
}
/** A Cloudflare Email suppression row. */
export interface CloudflareSuppression {
  readonly provider: 'cloudflare';
  readonly email: string;
  readonly reason: string;
  readonly expiresAt?: string | null;
}
export interface EmailFeedbackOptions {
  /** `threshold` transient or undetermined bounces for one recipient within `windowMs` suppress it. */
  readonly transient: { readonly threshold: number; readonly windowMs: number };
  /** Epoch-millisecond times of the recipient's earlier transient or undetermined bounces, excluding this event. */
  history?(recipient: string): readonly number[];
}

// RFC 3463 section 3.8 defines status subject X.7.XXX as "Security or Policy Status", for both persistent transient (4)
// and permanent (5) classes; RFC 5248 registers the detail codes (5.7.1 delivery not authorized, 5.7.26 multiple
// authentication checks failed, and vendor extensions such as 5.7.606). Those reflect the sender's reputation,
// authentication or content, not the mailbox, so they raise a deliverability alert and never suppress or count.
// Rule: the DSN `status` is exactly [45].7.<1-3 digits>, or `diagnosticCode` contains that code as a standalone token
// (not preceded by a digit or dot, and not followed by a digit or ".<digit>", so addresses such as 10.5.7.1 do not match).
const POLICY_STATUS = /^[45]\.7\.\d{1,3}$/;
const POLICY_DIAGNOSTIC = /(?<![\d.])[45]\.7\.\d{1,3}(?!\d|\.\d)/;
// SES did not attempt delivery: the address was already on an SES suppression list, failed SES validation, or unsubscribed.
const PROVIDER_SUPPRESSED = new Set(['OnAccountSuppressionList', 'OnTenantSuppressionList', 'EmailValidationSuppressed']);

type Json = Record<string, unknown>;
const object = (value: unknown): Json | undefined => value && typeof value === 'object' && !Array.isArray(value) ? value as Json : undefined;
const text = (value: unknown): string | undefined => typeof value === 'string' && value.length > 0 ? value : undefined;
const list = (value: unknown): unknown[] => Array.isArray(value) ? value : [];

function configError(): never {
  throw Object.assign(new Error('Invalid email feedback configuration.'), { code: 'EMAIL_FEEDBACK_CONFIG' });
}

function isPolicyBlock(recipient: Json): boolean {
  const status = text(recipient.status), diagnostic = text(recipient.diagnosticCode);
  return (status !== undefined && POLICY_STATUS.test(status.trim())) || (diagnostic !== undefined && POLICY_DIAGNOSTIC.test(diagnostic));
}

function classifyBounce(bounce: Json, at: number, options: EmailFeedbackOptions): EmailFeedbackOutcome[] {
  const type = bounce.bounceType, subType = text(bounce.bounceSubType);
  const { threshold, windowMs } = options.transient;
  const outcomes: EmailFeedbackOutcome[] = [];
  for (const entry of list(bounce.bouncedRecipients)) {
    const row = object(entry), recipient = text(row?.emailAddress);
    if (!row || !recipient) continue;
    const base = { recipient, ...(subType ? { subType } : {}) };
    if (type === 'Permanent' && subType && PROVIDER_SUPPRESSED.has(subType)) outcomes.push({ ...base, action: 'record', reason: 'provider-suppressed' });
    else if (type === 'Permanent' && subType === 'UnsubscribedRecipient') outcomes.push({ ...base, action: 'record', reason: 'unsubscribed-recipient' });
    else if (isPolicyBlock(row)) outcomes.push({ ...base, action: 'deliverability-alert', reason: 'policy-block' });
    else if (type === 'Permanent') outcomes.push({ ...base, action: 'suppress', reason: 'permanent-bounce' });
    else if (type === 'Transient' || type === 'Undetermined') {
      // The window is [at - windowMs, at], inclusive at both ends; a later out-of-order entry waits for the next bounce.
      const prior = Number.isFinite(at) ? (options.history?.(recipient) ?? []).filter(time => time >= at - windowMs && time <= at).length : 0;
      // A single undetermined bounce never suppresses, even with a threshold of one.
      const repeated = Number.isFinite(at) && prior + 1 >= threshold && (type === 'Transient' || prior > 0);
      if (repeated) outcomes.push({ ...base, action: 'suppress', reason: 'repeated-transient' });
      else if (type === 'Transient') outcomes.push({ ...base, action: 'count-transient', reason: 'transient-bounce' });
      else outcomes.push({ ...base, action: 'flag-undetermined', reason: 'undetermined-bounce' });
    } else outcomes.push({ recipient, action: 'ignore', reason: 'unsupported-event' });
  }
  return outcomes;
}

function classifyComplaint(complaint: Json): EmailFeedbackOutcome[] {
  const feedbackType = text(complaint.complaintFeedbackType), subType = text(complaint.complaintSubType);
  const extra = { ...(feedbackType ? { feedbackType } : {}), ...(subType ? { subType } : {}) };
  return list(complaint.complainedRecipients).flatMap((entry): EmailFeedbackOutcome[] => {
    const recipient = text(object(entry)?.emailAddress);
    if (!recipient) return [];
    // not-spam (RFC 6650 / IANA MARF registry) reverses a spam verdict, so it is kept for review rather than suppressed.
    if (feedbackType === 'not-spam') return [{ recipient, action: 'record', reason: 'not-spam', ...extra }];
    if (subType && PROVIDER_SUPPRESSED.has(subType)) return [{ recipient, action: 'record', reason: 'provider-suppressed', ...extra }];
    return [{ recipient, action: 'suppress', reason: 'complaint', ...extra }];
  });
}

function classifyCloudflare(row: CloudflareSuppression): EmailFeedbackOutcome[] {
  const recipient = text(row.email);
  if (!recipient) return [];
  // Any provider row can be time-limited; the caller must stop honouring it once the provider's expiry passes.
  const expiry = text(row.expiresAt) ? { expiresAt: row.expiresAt! } : {};
  switch (row.reason) {
    case 'hard_bounce': return [{ recipient, action: 'suppress', reason: 'permanent-bounce', ...expiry }];
    case 'complaint': return [{ recipient, action: 'suppress', reason: 'complaint', ...expiry }];
    case 'manual': return [{ recipient, action: 'suppress', reason: 'manual', ...expiry }];
    case 'soft_bounce': return [{ recipient, action: 'count-transient', reason: 'transient-bounce', ...expiry }];
    case 'policy': return [{ recipient, action: 'deliverability-alert', reason: 'policy-block', ...expiry }];
    default: return [{ recipient, action: 'ignore', reason: 'unknown-reason', ...expiry }];
  }
}

/**
 * Per-recipient actions for an SES notification or event-publishing record (`notificationType` or `eventType` of
 * Bounce, Complaint or Delivery) or a Cloudflare suppression row. Other SES events, and unknown Cloudflare reasons, map to
 * `ignore`; recipients without an address are skipped. Throws EMAIL_FEEDBACK_CONFIG for a threshold below 1 or a non-positive window.
 */
export function classifyEmailFeedback(event: unknown, options: EmailFeedbackOptions): readonly EmailFeedbackOutcome[] {
  const { threshold, windowMs } = options.transient;
  if (!Number.isInteger(threshold) || threshold < 1 || !(windowMs > 0)) configError();
  const root = object(event);
  if (!root) return [];
  if (root.provider === 'cloudflare') return classifyCloudflare(root as unknown as CloudflareSuppression);
  const kind = root.notificationType ?? root.eventType;
  if (kind === 'Bounce') {
    const bounce = object(root.bounce);
    return bounce ? classifyBounce(bounce, Date.parse(text(bounce.timestamp) ?? text(object(root.mail)?.timestamp) ?? ''), options) : [];
  }
  if (kind === 'Complaint') {
    const complaint = object(root.complaint);
    return complaint ? classifyComplaint(complaint) : [];
  }
  if (kind === 'Delivery') {
    return list(object(root.delivery)?.recipients).flatMap(recipient => typeof recipient === 'string' && recipient ? [{ recipient, action: 'delivered' as const, reason: 'delivered' as const }] : []);
  }
  return list(object(root.mail)?.destination).flatMap(recipient => typeof recipient === 'string' && recipient ? [{ recipient, action: 'ignore' as const, reason: 'unsupported-event' as const }] : []);
}
