// One-recipient email validation shared by the SES and Cloudflare senders. Internal: index.mjs does not re-export it.
// Header names the request itself controls; a caller header must never add recipients or rewrite the envelope.
const RESERVED_HEADERS = new Set(['bcc', 'cc', 'content-disposition', 'content-id', 'content-transfer-encoding', 'content-type', 'date', 'from', 'message-id', 'mime-version', 'reply-to', 'return-path', 'sender', 'subject', 'to']);
const ADDRESS = /^[!#-'*+\-/-9=?A-Z^-~]+(?:\.[!#-'*+\-/-9=?A-Z^-~]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
export function invalidEmailInput(provider, field) {
    throw Object.assign(new TypeError(`Invalid ${provider} ${field}.`), { code: 'INVALID_INPUT' });
}
/**
 * Validates one message for `provider` (named in errors). Header limits follow SES, the stricter provider:
 * https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_MessageHeader.html and API_Message.html.
 */
export function checkEmailMessage(message, provider, { reservedHeaderPrefix } = {}) {
    const invalid = (field) => invalidEmailInput(provider, field);
    const address = (value, field) => {
        if (typeof value !== 'string' || value.length > 254 || !ADDRESS.test(value) || value.split('@')[0].length > 64)
            invalid(field);
        return value;
    };
    if (message === null || typeof message !== 'object')
        invalid('message');
    const { from, to, subject, text, html, replyTo, headers } = message;
    if (typeof subject !== 'string' || subject.length > 998 || /[\u0000-\u001f\u007f]/u.test(subject))
        invalid('subject');
    if (text !== undefined && typeof text !== 'string' || html !== undefined && typeof html !== 'string' || !text && !html)
        invalid('body');
    // The unquoted display name excludes the list and address delimiters `,;:@<>"\`.
    if (typeof from !== 'string')
        invalid('from address');
    const named = /^([ !#-+\--9=?A-Z^-~]{1,128}) <([^<>]+)>$/.exec(from);
    if (named && !named[1].trim())
        invalid('from address');
    const sender = named ? { raw: from, address: address(named[2], 'from address'), name: named[1] } : { raw: from, address: address(from, 'from address') };
    if (headers !== undefined && (headers === null || typeof headers !== 'object' || Array.isArray(headers)))
        invalid('headers');
    const entries = Object.entries(headers ?? {});
    if (entries.length > 15)
        invalid('headers');
    const seen = new Set();
    const checkedHeaders = entries.map(([name, value]) => {
        const lower = name.toLowerCase();
        if (!/^[!-9;-~]{1,126}$/.test(name) || RESERVED_HEADERS.has(lower) || reservedHeaderPrefix && lower.startsWith(reservedHeaderPrefix) || seen.has(lower))
            invalid('header name');
        if (typeof value !== 'string' || !/^[ -~]{1,995}$/.test(value) || name.length + value.length > 996)
            invalid('header value');
        seen.add(lower);
        return { name, value };
    });
    return {
        from: sender, to: address(to, 'to address'), subject,
        ...(text ? { text } : {}), ...(html ? { html } : {}),
        ...(replyTo === undefined ? {} : { replyTo: address(replyTo, 'reply-to address') }),
        headers: checkedHeaders,
    };
}
