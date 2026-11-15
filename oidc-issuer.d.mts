/**
 * The issuer as the preset stores it in `account.providerId` ('oidc:' + this): the scheme and host lowercased (ASCII
 * letters), an empty or default port removed (:443 for https, :80 for http), and one trailing slash dropped from the
 * path. Userinfo, the rest of the path and anything after it are kept as given. A value without a scheme and a host, with
 * a malformed host or port, or with a path ending in '//', throws a TypeError, so normalising twice equals normalising once.
 */
export declare function normaliseOidcIssuer(issuer: string): string;
/**
 * normaliseOidcIssuer as SQL, for an app's migration that copies identities into account rows: it creates the
 * session-scoped `pg_temp.ten98_normalise_oidc_issuer(text)`, which returns NULL where the function throws. Call it
 * schema-qualified, as `pg_temp.ten98_normalise_oidc_issuer(issuer)`, on the connection that created it.
 */
export declare const normaliseOidcIssuerSql = "CREATE OR REPLACE FUNCTION pg_temp.ten98_normalise_oidc_issuer(issuer text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $normalise$\n  SELECT CASE WHEN m IS NULL OR m[3] !~ '^(\\[[^]]*\\]|[^]:[]+)(:[0-9]*)?$' OR right(m[4], 2) = '//' THEN NULL ELSE s || '://' || m[2]\n    || CASE WHEN s = 'https' AND right(h, 4) = ':443' THEN left(h, -4) WHEN s = 'http' AND right(h, 3) = ':80' THEN left(h, -3) ELSE h END\n    || CASE WHEN right(m[4], 1) = '/' THEN left(m[4], -1) ELSE m[4] END || m[5] END\n  FROM regexp_match(issuer, '^([A-Za-z][A-Za-z0-9+.-]*)://((?:[^/?#]*@)?)([^/?#]*)([^?#]*)(.*)$') AS m,\n    LATERAL (SELECT translate(m[1], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') AS s,\n                    regexp_replace(translate(m[3], 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), ':$', '') AS h) AS v\n$normalise$;";
/** The account row's `providerId` for an issuer: identities are keyed by issuer, so providers on one issuer share them. */
export declare const oidcProviderId: (issuer: string) => string;
/**
 * An OIDC `sub`: a string of at most 255 characters (OpenID Connect Core 1.0, section 2) that is not blank and holds no
 * control character (NUL included), so a malformed value is refused before any query.
 */
export declare const isOidcSubject: (value: unknown) => value is string;
