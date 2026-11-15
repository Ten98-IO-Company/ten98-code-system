// The issuer key of a linked OIDC identity (#143), shared by the auth preset (@ten98/runtime/auth, which exports it)
// and the team controller's invitation acceptance. Internal: not re-exported by index. No imports.

// scheme :// [userinfo@] host[:port] path rest. One expression, the same in normaliseOidcIssuerSql, so both split alike.
const ISSUER = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/((?:[^/?#]*@)?)([^/?#]*)([^?#]*)([\s\S]*)$/;
// The host and port: a bracketed literal or a name without ':', '[' or ']', then at most one port of digits (maybe none).
const HOST_PORT = /^(?:\[[^\]]*\]|[^\]:[]+)(?::[0-9]*)?$/;
// ASCII letters only, as SQL translate() does: lower() follows the database's collation, which could disagree.
const asciiLower = (value: string) => value.replace(/[A-Z]+/g, letters => letters.toLowerCase());

/**
 * The issuer as the preset stores it in `account.providerId` ('oidc:' + this): the scheme and host lowercased (ASCII
 * letters), an empty or default port removed (:443 for https, :80 for http), and one trailing slash dropped from the
 * path. Userinfo, the rest of the path and anything after it are kept as given. A value without a scheme and a host, with
 * a malformed host or port, or with a path ending in '//', throws a TypeError, so normalising twice equals normalising once.
 */
export function normaliseOidcIssuer(issuer: string): string {
  const match = typeof issuer === 'string' ? ISSUER.exec(issuer) : null;
  if (!match || !HOST_PORT.test(match[3]!) || match[4]!.endsWith('//')) throw new TypeError('An OIDC issuer is an absolute URL with a host, such as https://idp.example.com.');
  const scheme = asciiLower(match[1]!), defaultPort = scheme === 'https' ? ':443' : scheme === 'http' ? ':80' : undefined;
  const lowered = asciiLower(match[3]!), host = lowered.endsWith(':') ? lowered.slice(0, -1) : lowered, path = match[4]!;
  return `${scheme}://${match[2]}${defaultPort && host.endsWith(defaultPort) ? host.slice(0, -defaultPort.length) : host}${path.endsWith('/') ? path.slice(0, -1) : path}${match[5]}`;
}

/**
 * normaliseOidcIssuer as SQL, for an app's migration that copies identities into account rows: it creates the
 * session-scoped `pg_temp.ten98_normalise_oidc_issuer(text)`, which returns NULL where the function throws. Call it
 * schema-qualified, as `pg_temp.ten98_normalise_oidc_issuer(issuer)`, on the connection that created it.
 */
export const normaliseOidcIssuerSql = `CREATE OR REPLACE FUNCTION pg_temp.ten98_normalise_oidc_issuer(issuer text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $normalise$
  SELECT CASE WHEN m IS NULL OR m[3] !~ '^(\\[[^]]*\\]|[^]:[]+)(:[0-9]*)?$' OR right(m[4], 2) = '//' THEN NULL ELSE s || '://' || m[2]
    || CASE WHEN s = 'https' AND right(h, 4) = ':443' THEN left(h, -4) WHEN s = 'http' AND right(h, 3) = ':80' THEN left(h, -3) ELSE h END
    || CASE WHEN right(m[4], 1) = '/' THEN left(m[4], -1) ELSE m[4] END || m[5] END
  FROM regexp_match(issuer, '^([A-Za-z][A-Za-z0-9+.-]*)://((?:[^/?#]*@)?)([^/?#]*)([^?#]*)(.*)$') AS m,
    LATERAL (SELECT translate(m[1], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') AS s,
                    regexp_replace(translate(m[3], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), ':$', '') AS h) AS v
$normalise$;`;

/** The account row's `providerId` for an issuer: identities are keyed by issuer, so providers on one issuer share them. */
export const oidcProviderId = (issuer: string) => `oidc:${normaliseOidcIssuer(issuer)}`;

/**
 * An OIDC `sub`: a string of at most 255 characters (OpenID Connect Core 1.0, section 2) that is not blank and holds no
 * control character (NUL included), so a malformed value is refused before any query.
 */
export const isOidcSubject = (value: unknown): value is string =>
  typeof value === 'string' && value.length <= 255 && value.trim().length >= 1 && !/[\u0000-\u001f\u007f]/.test(value);
