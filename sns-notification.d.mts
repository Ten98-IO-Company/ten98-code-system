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
type SnsFetch = (url: string, init: RequestInit) => Promise<Response>;
/**
 * A `fetchCertificate` for `verifySnsMessage`: one bounded GET per certificate URL, cached for the process. A URL that
 * failed is not fetched again for `failureBackoffMs`, and `admit` (an app's budget) is asked before every network fetch,
 * so unverified traffic cannot drive repeated requests to AWS. Only certificate URLs on an SNS origin are fetched.
 * Each map is cleared when it reaches its limit, which keeps memory bounded without an eviction policy.
 */
export declare function createSnsCertificateFetcher({ fetch: send, timeoutMs, maxBytes, maxEntries, failureBackoffMs, admit, now }?: {
    fetch?: SnsFetch;
    timeoutMs?: number;
    maxBytes?: number;
    maxEntries?: number;
    failureBackoffMs?: number;
    admit?(): boolean | Promise<boolean>;
    now?(): number;
}): (url: string) => Promise<string>;
/**
 * The HTTP status for a refused message: 503 when the signing certificate could not be fetched, which may be a genuine
 * delivery during an outage or a spent budget, so SNS retries it; 403 for every other refusal, which SNS does not retry.
 */
export declare function snsRefusalStatus(reason: SnsRejection): 403 | 503;
/**
 * Confirms a subscription by fetching the `subscribeUrl` that `verifySnsMessage` returned for a verified
 * SubscriptionConfirmation. Throws when the URL is not an SNS ConfirmSubscription URL or SNS does not answer 2xx;
 * answer 503 then, so SNS sends the confirmation again.
 */
export declare function confirmSnsSubscription(subscribeUrl: string, { fetch: send, timeoutMs }?: {
    fetch?: SnsFetch;
    timeoutMs?: number;
}): Promise<void>;
export {};
