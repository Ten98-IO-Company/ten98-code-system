// Public DNS hostnames typed by users. Promoted from Discover src/server/domains.ts normalizePublicHostname and
// src/server/context-input.ts contextHost (v0.7.4), which applied the same rule; apps keep their error messages and any
// extra length budget, such as Discover's ownership-proof record prefix.
import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

// Special-use and non-public names (RFC 6761, 6762, 7686, 8375 and 9476), the arpa infrastructure domain, and every name
// below them. Some are in the Public Suffix List, so this check stays separate from it.
const specialSuffixes = ['localhost', 'local', 'internal', 'invalid', 'test', 'example', 'onion', 'arpa', 'alt'];

// The upstream Public Suffix List, shipped unmodified (see THIRD_PARTY_NOTICES.md) and parsed on first use, so importing
// the root entry stays cheap. Only its ICANN section counts: a name under a private-section suffix such as github.io is
// an ordinary name under its ICANN suffix.
let suffixRules: ReadonlySet<string> | undefined;
function loadSuffixRules(): ReadonlySet<string> {
  const listing = readFileSync(new URL('./data/public_suffix_list.dat', import.meta.url), 'utf8');
  const begin = listing.indexOf('// ===BEGIN ICANN DOMAINS==='), end = listing.indexOf('// ===END ICANN DOMAINS===');
  if (begin < 0 || end < begin) throw new Error('The Public Suffix List has no ICANN section.');
  const rules = new Set<string>();
  for (const line of listing.slice(begin, end).split('\n')) {
    // A rule is the line up to its first whitespace; '*.' marks a wildcard and '!' an exception.
    const rule = line.trim().split(/\s/u)[0]!;
    if (!rule || rule.startsWith('//')) continue;
    const prefix = /^(?:!|\*\.)?/u.exec(rule)![0];
    const name = rule.slice(prefix.length);
    const ascii = /^[\x21-\x7e]*$/u.test(name) ? name.toLowerCase() : domainToASCII(name);
    if (!ascii) throw new Error(`The Public Suffix List rule ${rule} is not a domain name.`);
    rules.add(prefix + ascii);
  }
  return rules;
}

// The number of labels in the name's ICANN public suffix, or 0 when no ICANN rule matches it.
function publicSuffixLength(labels: readonly string[]): number {
  const rules = suffixRules ??= loadSuffixRules();
  let length = 0;
  for (let index = labels.length - 1; index >= 0; index--) {
    const name = labels.slice(index).join('.'), count = labels.length - index;
    if (rules.has(`!${name}`)) return count - 1;
    if (rules.has(name) || (count > 1 && rules.has(`*.${labels.slice(index + 1).join('.')}`))) length = count;
  }
  return length;
}

export type PublicHostnameOptions = {
  /** Tests only: accept a name whose suffix is not in the Public Suffix List's ICANN section. Never set in production. */
  allowUnlistedSuffixForTesting?: boolean;
};

/**
 * The lowercase ASCII (punycode) form of a public hostname, or null. Refuses anything that is not a bare DNS name: a
 * scheme, path, port, credentials, wildcard, percent escape, whitespace, control character or lone surrogate; an IP
 * address in any spelling; a single label; a special-use name or anything under arpa; an all-numeric top-level label; a
 * label outside 1 to 63 letters, digits and inner hyphens; or more than 253 characters. The name must end in a suffix
 * from the Public Suffix List's ICANN section, with at least one label to its left, so a suffix itself (com, co.uk) and
 * a name on an unlisted suffix (corp, home, a top-level domain newer than the shipped list) are refused. One trailing
 * dot is accepted and removed.
 */
export function normalizePublicHostname(input: unknown, options: PublicHostnameOptions = {}): string | null {
  // The length cap only keeps huge input away from domainToASCII; anything over 253 characters fails below anyway.
  if (typeof input !== 'string' || !input || input.length > 1024 || /[\s\u0000-\u001f\u007f%/\\:@?#*]/u.test(input)) return null;
  // domainToASCII returns '' for invalid input, including lone surrogates.
  const ascii = domainToASCII(input.endsWith('.') ? input.slice(0, -1) : input).toLowerCase();
  if (!ascii || ascii.length > 253 || specialSuffixes.some(suffix => ascii === suffix || ascii.endsWith(`.${suffix}`))) return null;
  const labels = ascii.split('.');
  if (labels.length < 2 || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null;
  // WHATWG URL parsing treats a numeric or hex last label as IPv4: a malformed one fails, which refuses all-numeric
  // top-level labels, and any IPv4 spelling (dotted, integer, hex, octal) becomes an address.
  const parsed = URL.parse(`https://${ascii}`);
  if (!parsed || isIP(parsed.hostname)) return null;
  const suffix = publicSuffixLength(labels);
  if (suffix ? labels.length <= suffix : options.allowUnlistedSuffixForTesting !== true) return null;
  return ascii;
}
