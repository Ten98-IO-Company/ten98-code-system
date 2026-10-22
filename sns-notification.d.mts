export type SnsMessageType = 'Notification' | 'SubscriptionConfirmation' | 'UnsubscribeConfirmation';
export type SnsRejection = 'too-large' | 'malformed' | 'unsupported-type' | 'unsupported-signature-version' | 'certificate-url' | 'topic' | 'region-mismatch' | 'stale' | 'certificate-unavailable' | 'certificate-invalid' | 'signature' | 'subscribe-url';
export type SnsVerification = {
    readonly ok: true;
    readonly duplicate: true;
    readonly type: SnsMessageType;
    readonly messageId: string;
} | {
    readonly ok: true;
    readonly duplicate: false;
    readonly type: SnsMessageType;
    readonly messageId: string;
    readonly topicArn: string;
    /** The signed Message text. */ readonly rawMessage: string;
    /** For a Notification, `rawMessage` parsed as JSON when it parses. */ readonly message?: unknown;
    readonly subject?: string;
    /** For a SubscriptionConfirmation only: the confirmation URL rebuilt on the allowlisted SNS origin. */ readonly subscribeUrl?: string;
} | {
    readonly ok: false;
    readonly reason: SnsRejection;
};
export interface SnsVerifyOptions {
    /** AWS regions whose SNS endpoints may sign, such as `['us-east-1']`. */
    readonly allowedRegions: readonly string[];
    /** Exact topic ARNs this endpoint is subscribed to. */
    readonly topicArns: readonly string[];
    /** Returns the PEM certificate at an allowlisted SNS URL. The caller caches and bounds the request. */
    fetchCertificate(url: string): Promise<string>;
    /** True when the caller has already processed this verified MessageId. */
    isDuplicate?(messageId: string): Promise<boolean> | boolean;
    /** Maximum distance between Timestamp and now; default one hour. */
    readonly maxAgeMs?: number;
}
/**
 * Verifies a raw SNS HTTP(S) POST body: SignatureVersion 2 (SHA256withRSA) only, a certificate from an allowlisted
 * regional SNS origin, an expected TopicArn in that region and a fresh Timestamp. Rejections carry a short code and never echo input.
 * Throws SNS_CONFIG for an unknown region, an empty topic list or a non-positive maxAgeMs.
 */
export declare function verifySnsMessage(rawBody: string, options: SnsVerifyOptions): Promise<SnsVerification>;
