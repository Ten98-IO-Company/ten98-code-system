// Transactional email over Amazon SES, Cloudflare Email Sending or SMTP, chosen by EMAIL_TRANSPORT; exported as
// @ten98/runtime/email only. Extracted from discover's and books' src/server/email.ts. Apps keep their message text,
// their suppression list (passed in as isSuppressed), rate limits and what they tell the user.
// Needs the optional zod peer. SMTP also needs the optional nodemailer peer, imported only when an SMTP message is sent,
// so the entry loads without it.
import { AsyncLocalStorage } from 'node:async_hooks';
import { createRequire } from 'node:module';
import { Socket, isIP } from 'node:net';
import { z } from 'zod';
import { sendCloudflareEmail } from './cloudflare-email.mjs';
import { readEnvironment } from './config.mjs';
import { SES_REGIONS, sendSesEmail } from './ses-email.mjs';

type Environment = Readonly<Record<string, string | undefined>>;
export type EmailTransport = 'disabled' | 'smtp' | 'cloudflare' | 'ses';
/** One plain-text message to one bare mailbox. The HTML part is generated from `text`; callers cannot supply one. */
export interface TransactionalEmail { to: string; subject: string; text: string }
export interface EmailAcceptance { accepted: true; delivery: 'unconfirmed' }
export interface EmailStatus { configured: boolean; transport: EmailTransport }
export interface SendTransactionalEmailOptions {
  /** Defaults to process.env. */
  env?: Environment;
  /**
   * Required, so no call site sends unchecked by omission. The app's suppression lookup, consulted for every transport:
   * only `false` lets the message go, so `true`, any other result, a throw or a rejection refuses it. Pass the literal
   * `false` instead of a function when the app keeps no suppression list.
   */
  isSuppressed: ((address: string) => boolean | Promise<boolean>) | false;
}

/** Every failure, bad configuration and input included. The message is fixed and carries no provider or message content. */
export class EmailDeliveryError extends Error {
  readonly status = 503;
  constructor() { super('Email acceptance could not be confirmed. No automatic retry was made.'); this.name = 'EmailDeliveryError'; }
}

const malformedUnicode = /[\uD800-\uDFFF]/u;
const mailbox = z.email().max(254); // Exactly one bare mailbox: no display name, list or header syntax.
const messageInput = z.object({
  to: mailbox,
  subject: z.string().min(1).max(200).refine(v => !/[\p{C}\p{Zl}\p{Zp}]/u.test(v)),
  text: z.string().min(1).max(65_536).refine(v => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(v) && !malformedUnicode.test(v) && Buffer.byteLength(v, 'utf8') <= 65_536),
}).strict();
const hostname = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

function configuration(env: Environment) {
  const read = (name: string) => readEnvironment(name, env);
  const transport = z.enum(['disabled', 'smtp', 'cloudflare', 'ses']).parse(read('EMAIL_TRANSPORT') || 'disabled');
  if (transport === 'disabled') return { transport };
  const from = mailbox.parse(read('EMAIL_FROM'));
  // The SES region must be on the runtime's allowlist, whose endpoints are constant origins.
  if (transport === 'ses') {
    const configurationSet = read('EMAIL_SES_CONFIGURATION_SET');
    return { transport, from,
      region: z.string().refine(v => SES_REGIONS.includes(v)).parse(read('EMAIL_SES_REGION')),
      credentials: {
        accessKeyId: z.string().regex(/^[A-Z0-9]{16,128}$/).parse(read('EMAIL_SES_ACCESS_KEY_ID')),
        secretAccessKey: z.string().min(16).max(256).regex(/^[A-Za-z0-9/+=]+$/).parse(read('EMAIL_SES_SECRET_ACCESS_KEY')),
      },
      configurationSetName: configurationSet ? z.string().regex(/^[A-Za-z0-9_-]{1,64}$/).parse(configurationSet) : undefined,
    };
  }
  if (transport === 'cloudflare') return { transport, from,
    accountId: z.string().regex(/^[a-f0-9]{32}$/).parse(read('EMAIL_CLOUDFLARE_ACCOUNT_ID')),
    token: z.string().min(1).max(4096).regex(/^[A-Za-z0-9_-]+$/).parse(read('EMAIL_CLOUDFLARE_API_TOKEN')),
  };
  const tls = z.enum(['starttls', 'tls']).parse(read('EMAIL_SMTP_TLS') || 'starttls');
  // A name, never an IP literal, so the certificate is verified against the configured host. A last label of digits
  // only, or a hex label (`0x7f000001`, `127.0x1`), is refused too: no top-level domain is numeric, and resolvers read
  // those as addresses.
  const host = z.string().max(253).regex(hostname).refine(v => !isIP(v) && !/(?:^|\.)(?:\d+|0x[0-9a-f]*)$/iu.test(v) && !/(?:^|\.)0x[0-9a-f]*\./iu.test(v)).parse(read('EMAIL_SMTP_HOST'));
  const portText = z.string().regex(/^[1-9]\d{0,4}$/).parse(read('EMAIL_SMTP_PORT') || (tls === 'tls' ? '465' : '587'));
  const port = z.number().int().min(1).max(65_535).parse(Number(portText));
  const user = z.string().min(1).max(256).refine(v => !/[\u0000-\u001f\u007f]/.test(v) && !malformedUnicode.test(v)).parse(read('EMAIL_SMTP_USER'));
  const password = z.string().min(1).max(4096).refine(v => !/[\u0000\r\n]/.test(v) && !malformedUnicode.test(v)).parse(read('EMAIL_SMTP_PASSWORD'));
  return { transport, from, host, port, tls, user, password };
}

// Whether the optional nodemailer peer can be loaded, without loading it.
const nodemailerAvailable = (): boolean => { try { createRequire(import.meta.url).resolve('nodemailer'); return true; } catch { return false; } };

/**
 * Configuration only: never throws, contacts no provider and promises no delivery. Read `.configured`. SMTP counts as
 * configured only when the optional nodemailer peer is installed (or a test SMTP sender is in place), since a send
 * would otherwise refuse.
 */
export function getEmailStatus(env: Environment = process.env): EmailStatus {
  try {
    const config = configuration(env);
    if (config.transport === 'smtp' && !testTransports.getStore()?.smtp && !nodemailerAvailable()) return { configured: false, transport: 'smtp' };
    return { configured: config.transport !== 'disabled', transport: config.transport };
  } catch { return { configured: false, transport: 'disabled' }; }
}

/** The nodemailer SMTP options a send passes, so a test adapter can check them. */
export interface SmtpTransportOptions {
  socket: Socket; host: string; port: number; secure: boolean; requireTLS: boolean; opportunisticTLS: boolean; ignoreTLS: boolean; forceAuth: boolean;
  auth: { user: string; pass: string }; tls: { minVersion: 'TLSv1.2'; rejectUnauthorized: boolean; servername: string };
  connectionTimeout: number; greetingTimeout: number; dnsTimeout: number; socketTimeout: number; maxResponseSize: number;
  logger: false; debug: false; transactionLog: false; disableFileAccess: boolean; disableUrlAccess: boolean; maxRecipients: number;
}
export interface SmtpMail { from: string; to: string; subject: string; text: string; html: string }
export interface SmtpSender { sendMail(mail: SmtpMail): Promise<unknown>; close(): void }
export interface EmailTestTransports {
  fetch?: (url: string, init: RequestInit) => Promise<Response>;
  smtp?: (options: SmtpTransportOptions) => SmtpSender;
}
const testTransports = new AsyncLocalStorage<EmailTestTransports>();
/** Trusted in-process test seam only: no request, URL or deployment setting can select an adapter. */
export function withEmailTransportsForTests<T>(transports: EmailTestTransports, action: () => Promise<T>): Promise<T> { return testTransports.run(transports, action); }

/** `work`, or an EmailDeliveryError when it fails or `signal` aborts first; a late settlement is absorbed. */
function untilAborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const stop = () => { signal.removeEventListener('abort', stop); reject(new EmailDeliveryError()); };
    if (signal.aborted) { work.catch(() => undefined); stop(); return; }
    signal.addEventListener('abort', stop, { once: true });
    work.then(value => { signal.removeEventListener('abort', stop); resolve(value); }, () => { signal.removeEventListener('abort', stop); reject(new EmailDeliveryError()); });
  });
}

async function sendSmtp(config: Extract<ReturnType<typeof configuration>, { transport: 'smtp' }>, mail: SmtpMail, signal: AbortSignal): Promise<void> {
  const socket = new Socket(); let sender: SmtpSender | undefined;
  // destroy alone permits Socket reuse; refuse nodemailer's late DNS callback on this owned instance.
  const stop = () => { socket.connect = () => { throw new EmailDeliveryError(); }; socket.destroy(); };
  signal.addEventListener('abort', stop, { once: true });
  try {
    const create = testTransports.getStore()?.smtp ?? (await untilAborted(import('nodemailer'), signal)).createTransport;
    signal.throwIfAborted();
    sender = create({ socket, host: config.host, port: config.port, secure: config.tls === 'tls', requireTLS: true, opportunisticTLS: false, ignoreTLS: false, forceAuth: true,
      auth: { user: config.user, pass: config.password }, tls: { minVersion: 'TLSv1.2', rejectUnauthorized: true, servername: config.host },
      connectionTimeout: 5000, greetingTimeout: 5000, dnsTimeout: 5000, socketTimeout: 10_000, maxResponseSize: 16_384,
      logger: false, debug: false, transactionLog: false, disableFileAccess: true, disableUrlAccess: true, maxRecipients: 1,
    });
    const result = z.object({ accepted: z.array(mailbox).length(1), rejected: z.array(z.unknown()).length(0), pending: z.array(z.unknown()).length(0).optional() })
      .parse(await untilAborted(sender.sendMail(mail), signal));
    if (result.accepted[0] !== mail.to) throw new EmailDeliveryError();
  } finally { signal.removeEventListener('abort', stop); stop(); sender?.close(); }
}

/**
 * Sends one message to one recipient in one attempt, within 15 seconds overall, the suppression lookup included.
 * Success means the provider accepted the message, never that it was delivered. Every failure is the same
 * EmailDeliveryError (status 503) with no cause attached; nothing is logged.
 */
export async function sendTransactionalEmail(input: TransactionalEmail, options: SendTransactionalEmailOptions): Promise<EmailAcceptance> {
  let config: ReturnType<typeof configuration>, message: TransactionalEmail, isSuppressed: SendTransactionalEmailOptions['isSuppressed'];
  try {
    // Missing options, or an isSuppressed that is neither a function nor the literal false, refuse like any bad input.
    if (typeof options !== 'object' || options === null) throw new EmailDeliveryError();
    ({ isSuppressed } = options);
    if (isSuppressed !== false && typeof isSuppressed !== 'function') throw new EmailDeliveryError();
    config = configuration(options.env ?? process.env); message = messageInput.parse(input);
  } catch { throw new EmailDeliveryError(); }
  if (config.transport === 'disabled') throw new EmailDeliveryError();
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 15_000);
  const escaped = message.text.replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!);
  const mail: SmtpMail = { from: config.from, ...message, html: '<div>' + escaped.replace(/\r\n|\r|\n/g, '<br>') + '</div>' };
  try {
    if (isSuppressed !== false) {
      const lookup = isSuppressed;
      // Only an explicit false lets the message go; undefined, a truthy value or anything else refuses.
      if (await untilAborted(Promise.resolve().then(() => lookup(message.to)), controller.signal) !== false) throw new EmailDeliveryError();
    }
    const fetch = testTransports.getStore()?.fetch;
    if (config.transport === 'ses') {
      await untilAborted(sendSesEmail({ region: config.region, credentials: config.credentials, message: mail, configurationSetName: config.configurationSetName,
        signal: controller.signal, ...(fetch ? { fetch: fetch as typeof globalThis.fetch } : {}) }), controller.signal);
    } else if (config.transport === 'cloudflare') {
      // A permanent bounce or a Cloudflare-suppressed recipient is the same unconfirmed error as any thrown one.
      const { status } = await untilAborted(sendCloudflareEmail({ accountId: config.accountId, token: config.token, message: mail, signal: controller.signal, ...(fetch ? { fetch } : {}) }), controller.signal);
      if (status !== 'delivered' && status !== 'queued') throw new EmailDeliveryError();
    } else {
      await sendSmtp(config, mail, controller.signal);
    }
    return { accepted: true, delivery: 'unconfirmed' };
  } catch { throw new EmailDeliveryError(); }
  finally { clearTimeout(timer); }
}
