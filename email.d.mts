import { Socket } from 'node:net';
type Environment = Readonly<Record<string, string | undefined>>;
export type EmailTransport = 'disabled' | 'smtp' | 'cloudflare' | 'ses';
/** One plain-text message to one bare mailbox. The HTML part is generated from `text`; callers cannot supply one. */
export interface TransactionalEmail {
    to: string;
    subject: string;
    text: string;
}
export interface EmailAcceptance {
    accepted: true;
    delivery: 'unconfirmed';
}
export interface EmailStatus {
    configured: boolean;
    transport: EmailTransport;
}
export interface SendTransactionalEmailOptions {
    /** Defaults to process.env. */
    env?: Environment;
    /** The app's suppression lookup, consulted for every transport; true, a throw or a rejection refuses the send. */
    isSuppressed?: (address: string) => boolean | Promise<boolean>;
}
/** Every failure, bad configuration and input included. The message is fixed and carries no provider or message content. */
export declare class EmailDeliveryError extends Error {
    readonly status = 503;
    constructor();
}
/** Configuration only: never throws, contacts no provider and promises no delivery. Read `.configured`. */
export declare function getEmailStatus(env?: Environment): EmailStatus;
/** The nodemailer SMTP options a send passes, so a test adapter can check them. */
export interface SmtpTransportOptions {
    socket: Socket;
    host: string;
    port: number;
    secure: boolean;
    requireTLS: boolean;
    opportunisticTLS: boolean;
    ignoreTLS: boolean;
    forceAuth: boolean;
    auth: {
        user: string;
        pass: string;
    };
    tls: {
        minVersion: 'TLSv1.2';
        rejectUnauthorized: boolean;
        servername: string;
    };
    connectionTimeout: number;
    greetingTimeout: number;
    dnsTimeout: number;
    socketTimeout: number;
    maxResponseSize: number;
    logger: false;
    debug: false;
    transactionLog: false;
    disableFileAccess: boolean;
    disableUrlAccess: boolean;
    maxRecipients: number;
}
export interface SmtpMail {
    from: string;
    to: string;
    subject: string;
    text: string;
    html: string;
}
export interface SmtpSender {
    sendMail(mail: SmtpMail): Promise<unknown>;
    close(): void;
}
export interface EmailTestTransports {
    fetch?: (url: string, init: RequestInit) => Promise<Response>;
    smtp?: (options: SmtpTransportOptions) => SmtpSender;
}
/** Trusted in-process test seam only: no request, URL or deployment setting can select an adapter. */
export declare function withEmailTransportsForTests<T>(transports: EmailTestTransports, action: () => Promise<T>): Promise<T>;
/**
 * Sends one message to one recipient in one attempt, within 15 seconds overall, the suppression lookup included.
 * Success means the provider accepted the message, never that it was delivered. Every failure is the same
 * EmailDeliveryError (status 503) with no cause attached; nothing is logged.
 */
export declare function sendTransactionalEmail(input: TransactionalEmail, { env, isSuppressed }?: SendTransactionalEmailOptions): Promise<EmailAcceptance>;
export {};
