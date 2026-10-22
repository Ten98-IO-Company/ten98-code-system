export type EmailFeedbackAction = 'suppress' | 'record' | 'count-transient' | 'flag-undetermined' | 'deliverability-alert' | 'delivered' | 'ignore';
export type EmailFeedbackReason = 'permanent-bounce' | 'provider-suppressed' | 'unsubscribed-recipient' | 'policy-block' | 'transient-bounce' | 'repeated-transient' | 'undetermined-bounce' | 'complaint' | 'not-spam' | 'manual' | 'delivered' | 'unsupported-event' | 'unknown-reason';
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
    readonly transient: {
        readonly threshold: number;
        readonly windowMs: number;
    };
    /** Epoch-millisecond times of the recipient's earlier transient or undetermined bounces, excluding this event. */
    history?(recipient: string): readonly number[];
}
/**
 * Per-recipient actions for an SES notification or event-publishing record (`notificationType` or `eventType` of
 * Bounce, Complaint or Delivery) or a Cloudflare suppression row. Other SES events, and unknown Cloudflare reasons, map to
 * `ignore`; recipients without an address are skipped. Throws EMAIL_FEEDBACK_CONFIG for a threshold below 1 or a non-positive window.
 */
export declare function classifyEmailFeedback(event: unknown, options: EmailFeedbackOptions): readonly EmailFeedbackOutcome[];
