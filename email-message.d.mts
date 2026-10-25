export interface EmailMessage {
    readonly from: string;
    readonly to: string;
    readonly subject: string;
    readonly text?: string;
    readonly html?: string;
    readonly replyTo?: string;
    readonly headers?: Readonly<Record<string, string>>;
}
export interface CheckedEmail {
    /** `from` as given, and its parts: a bare address or `Display Name <address>`. */
    from: {
        raw: string;
        address: string;
        name?: string;
    };
    to: string;
    subject: string;
    text?: string;
    html?: string;
    replyTo?: string;
    headers: readonly {
        name: string;
        value: string;
    }[];
}
/** A single mailbox address under the senders' rule: at most 254 characters, local part at most 64. */
export declare function isEmailAddress(value: unknown): value is string;
export declare function invalidEmailInput(provider: string, field: string): never;
/**
 * Validates one message for `provider` (named in errors). Header limits follow SES, the stricter provider:
 * https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_MessageHeader.html and API_Message.html.
 */
export declare function checkEmailMessage(message: unknown, provider: string, { reservedHeaderPrefix }?: {
    reservedHeaderPrefix?: string;
}): CheckedEmail;
