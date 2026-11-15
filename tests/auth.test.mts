import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHmac, hkdfSync, scryptSync } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import test from 'node:test';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { hashPassword } from 'better-auth/crypto';
import { createTen98Auth, sessionTokenKey, storedVerificationIdentifier, ten98AuthPolicy, verifyLegacyScryptHash } from '../auth.mjs';
import type { Ten98AuthOptions } from '../auth.mjs';

// better-auth on its in-memory adapter: no database, no network. Origin and cookies go through the real handler.
// These tests drive better-auth's own password sign-in, so setup() turns allowRawPasswordSignIn on; a test below shows
// it is off by default.
const ORIGIN = 'http://localhost:3000';
const SECRET = 'test-secret-that-is-long-enough-0123456789';
const PASSWORD = 'correct horse battery';
const BACKUP_CODE = /^[A-Za-z0-9]{5}-[A-Za-z0-9]{15}$/;
type Row = Record<string, unknown>;
type Context = { internalAdapter: {
  createUser(user: Row): Promise<{ id: string }>;
  linkAccount(account: Row): Promise<unknown>;
  findAccounts(userId: string): Promise<{ providerId: string; password?: string | null }[]>;
  createVerificationValue(data: { identifier: string; value: string; expiresAt: Date }): Promise<unknown>;
}; adapter: { count(query: { model: string; where: { field: string; value: string }[] }): Promise<number> } };
type Adapter = ReturnType<typeof memoryAdapter>;

function setup(options: Partial<Ten98AuthOptions> = {}, wrap?: (adapter: Adapter) => Adapter) {
  const db: Record<string, Row[]> = { user: [], session: [], account: [], verification: [], twoFactor: [] };
  const resets: string[] = [];
  const adapter = memoryAdapter(db);
  const auth = createTen98Auth({ database: wrap ? wrap(adapter) : adapter, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test', sendResetPassword: ({ token }) => { resets.push(token); }, allowRawPasswordSignIn: true, ...options });
  const context = (auth as unknown as { $context: Promise<Context> }).$context;
  const post = (path: string, body: unknown, cookie = '', origin = ORIGIN) => auth.handler(new Request(`${ORIGIN}/api/auth${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', origin, ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body),
  }));
  const user = async (email: string, passwordHash?: string) => {
    const { internalAdapter } = await context;
    const created = await internalAdapter.createUser({ email, name: 'Test', emailVerified: true });
    if (passwordHash) await internalAdapter.linkAccount({ userId: created.id, providerId: 'credential', accountId: created.id, password: passwordHash });
    return created.id;
  };
  const signIn = async (email = 'owner@example.com', password = PASSWORD, cookie = '') => post('/sign-in/email', { email, password }, cookie);
  return { auth, db, context, post, user, signIn, resets };
}
const cookies = (response: Response) => response.headers.getSetCookie().map(value => value.split(';')[0]!).filter(pair => !pair.endsWith('='));
const cookieOf = (response: Response) => cookies(response).join('; ');
const sessionCookieName = (response: Response) => cookies(response).map(pair => pair.split('=')[0]!).find(name => name.endsWith('.session_token'));
// Campaign server/auth.ts hashPassword: the salt is the hex text itself.
const campaignHash = (password: string, salt = '0123456789abcdef0123456789abcdef') => `scrypt$${salt}$${scryptSync(password, salt, 64, { N: 65_536, maxmem: 128 * 1024 * 1024 }).toString('hex')}`;

// RFC 6238 TOTP from an otpauth URI, so tests can confirm and use two-factor exactly as an authenticator app would.
function totp(uri: string, offset = 0): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of new URL(uri).searchParams.get('secret')!.replace(/=+$/, '')) bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g)!.map(byte => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000) + offset));
  const mac = createHmac('sha1', key).update(counter).digest();
  const at = mac[mac.length - 1]! & 15;
  return String((mac.readUInt32BE(at) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}
async function withTwoFactor(env: ReturnType<typeof setup>) {
  await env.user('owner@example.com', await hashPassword(PASSWORD));
  const cookie = cookieOf(await env.signIn());
  const enabled = await (await env.post('/two-factor/enable', { password: PASSWORD }, cookie)).json() as { totpURI: string; backupCodes: string[] };
  const confirmed = await env.post('/two-factor/verify-totp', { code: totp(enabled.totpURI) }, cookie);
  assert.equal(confirmed.status, 200);
  // Confirming two-factor replaces the session, so later steps use the new cookie.
  const live = cookieOf(confirmed) || cookie;
  assert.ok(await env.auth.api.getSession({ headers: { cookie: live } }));
  return { cookie: live, uri: enabled.totpURI, backupCodes: enabled.backupCodes };
}

test('the policy is the published Ten98 identity policy', () => {
  // A JSON round trip proves the policy can be sent to browser forms unchanged.
  assert.deepEqual(JSON.parse(JSON.stringify(ten98AuthPolicy)), {
    password: { minLength: 12, maxLength: 128 },
    session: { expiresInSeconds: 604800, updateAgeSeconds: 86400 },
    twoFactor: { digits: 6, periodSeconds: 30, replaySeconds: 90, backupCodes: 10, backupCodePattern: BACKUP_CODE.source, backupCodeInputLength: 21, maxFailedAttempts: 10, lockoutSeconds: 900 },
    reset: { expiresInSeconds: 3600, revokesSessions: true },
    rateLimits: { windowSeconds: 60, signInPerClient: 60, signInPerEmail: 5, twoFactorPerClient: 60, twoFactorPerChallenge: 10, resetRequestPerClient: 20, resetRequestPerEmail: 3, resetPerClient: 60, resetPerToken: 5, accountSecurityReadsPerUser: 120, accountSecurityWritesPerUser: 30 },
  });
  assert.ok(Object.isFrozen(ten98AuthPolicy) && Object.isFrozen(ten98AuthPolicy.twoFactor));
});

test('sign-in issues a seven-day session refreshed daily, sign-up stays closed, telemetry is off', async () => {
  const env = setup();
  const id = await env.user('owner@example.com', await hashPassword(PASSWORD));
  const signedIn = await env.signIn();
  assert.equal(signedIn.status, 200);
  assert.match(signedIn.headers.getSetCookie().join('\n'), /HttpOnly/i);
  const session = await env.auth.api.getSession({ headers: { cookie: cookieOf(signedIn) } });
  assert.equal(session?.user.id, id);
  assert.ok(Math.abs(new Date(session!.session.expiresAt).getTime() - Date.now() - 604_800_000) < 60_000);
  assert.equal((env.auth as unknown as { options: { session: { updateAge: number } } }).options.session.updateAge, 86_400);
  assert.equal(env.auth.options.telemetry.enabled, false);
  assert.equal((await env.signIn('owner@example.com', 'wrong password here')).status, 401);
  assert.notEqual((await env.post('/sign-up/email', { email: 'new@example.com', password: PASSWORD, name: 'New' })).ok, true);
});

test('cookie names are scoped to the origin unless a prefix is given', async () => {
  const names: (string | undefined)[] = [];
  for (const options of [{}, { appUrl: 'http://localhost:3001' }, { cookiePrefix: 'better-auth' }]) {
    const env = setup(options);
    await env.user('owner@example.com', await hashPassword(PASSWORD));
    names.push(sessionCookieName(await env.post('/sign-in/email', { email: 'owner@example.com', password: PASSWORD }, '', options.appUrl ?? ORIGIN)));
  }
  assert.match(names[0]!, /^ten98-[0-9a-f]{16}\.session_token$/);
  assert.notEqual(names[0], names[1]);
  assert.equal(names[2], 'better-auth.session_token');
});

test('password changes enforce 12 to 128 characters', async () => {
  const env = setup();
  await env.user('owner@example.com', await hashPassword(PASSWORD));
  const cookie = cookieOf(await env.signIn());
  assert.equal((await env.post('/change-password', { currentPassword: PASSWORD, newPassword: 'x'.repeat(11) }, cookie)).status, 400);
  assert.equal((await env.post('/change-password', { currentPassword: PASSWORD, newPassword: 'x'.repeat(129) }, cookie)).status, 400);
  assert.equal((await env.post('/change-password', { currentPassword: PASSWORD, newPassword: 'y'.repeat(12) }, cookie)).status, 200);
});

test('cross-origin requests are refused, also when the environment looks like a test run', async () => {
  const env = setup();
  await env.user('owner@example.com', await hashPassword(PASSWORD));
  const cookie = cookieOf(await env.signIn());
  assert.equal((await env.post('/revoke-sessions', {}, cookie, 'https://evil.example')).status, 403);
  // better-auth disables its origin check under NODE_ENV=test or TEST unless the preset pins it.
  const script = `
    import { memoryAdapter } from 'better-auth/adapters/memory';
    import { hashPassword } from 'better-auth/crypto';
    import { createTen98Auth } from ${JSON.stringify(new URL('../auth.mjs', import.meta.url).href)};
    const auth = createTen98Auth({ database: memoryAdapter({ user: [], session: [], account: [], verification: [], twoFactor: [] }), appUrl: '${ORIGIN}', secret: '${SECRET}', appName: 'T', allowRawPasswordSignIn: true });
    const ctx = await auth.$context;
    const user = await ctx.internalAdapter.createUser({ email: 'a@example.com', name: 'A', emailVerified: true });
    await ctx.internalAdapter.linkAccount({ userId: user.id, providerId: 'credential', accountId: user.id, password: await hashPassword('${PASSWORD}') });
    const post = (path, body, cookie, origin) => auth.handler(new Request('${ORIGIN}/api/auth' + path, { method: 'POST', headers: { 'content-type': 'application/json', origin, ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) }));
    const signedIn = await post('/sign-in/email', { email: 'a@example.com', password: '${PASSWORD}' }, '', '${ORIGIN}');
    const cookie = signedIn.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
    const forged = await post('/revoke-sessions', {}, cookie, 'https://evil.example');
    const redirect = await post('/sign-in/email', { email: 'a@example.com', password: '${PASSWORD}', callbackURL: 'https://evil.example/x' }, '', '${ORIGIN}');
    console.log(JSON.stringify([forged.status, redirect.status]));`;
  for (const env of [{ TEST: '1' }, { NODE_ENV: 'test' }]) {
    const run = spawnSync(process.execPath, ['--input-type=module', '-e', script], { cwd: new URL('..', import.meta.url), env: { ...process.env, ...env }, encoding: 'utf8', timeout: 30_000 });
    assert.equal(run.status, 0, run.stderr);
    assert.deepEqual(JSON.parse(run.stdout.trim().split('\n').at(-1)!), [403, 403], JSON.stringify(env));
  }
});

test('legacy Campaign hashes verify, are replaced on the first sign-in, and a failed rehash never blocks sign-in', async () => {
  const legacy = campaignHash(PASSWORD);
  assert.equal(await verifyLegacyScryptHash(legacy, PASSWORD), true);
  assert.equal(await verifyLegacyScryptHash(legacy, 'another password'), false);
  assert.equal(await verifyLegacyScryptHash(await hashPassword(PASSWORD), PASSWORD), false);
  const env = setup({ legacyPasswords: true });
  const id = await env.user('legacy@example.com', legacy);
  const stored = async () => (await (await env.context).internalAdapter.findAccounts(id)).find(account => account.providerId === 'credential')!.password!;
  assert.equal((await env.signIn('legacy@example.com', 'wrong password here')).status, 401);
  assert.equal(await stored(), legacy);
  assert.equal((await env.signIn('legacy@example.com')).status, 200);
  assert.equal((await stored()).startsWith('scrypt$'), false);
  assert.equal((await env.signIn('legacy@example.com')).status, 200);
  // Without the option a legacy hash never verifies.
  const strict = setup();
  await strict.user('legacy@example.com', legacy);
  assert.notEqual((await strict.signIn('legacy@example.com')).status, 200);
  // A failing account update leaves the legacy hash for next time and still signs in.
  const broken = setup({ legacyPasswords: true }, adapter => options => {
    const real = adapter(options);
    return { ...real, update: async (query: { model: string }) => { if (query.model === 'account') throw new Error('write failed'); return real.update(query as never); }, updateMany: async () => { throw new Error('write failed'); } } as ReturnType<Adapter>;
  });
  await broken.user('legacy@example.com', legacy);
  assert.equal((await broken.signIn('legacy@example.com')).status, 200);
});

test('with legacy hashes accepted, unknown, current and legacy accounts take the same time', async () => {
  const env = setup({ legacyPasswords: true });
  await env.user('legacy@example.com', campaignHash(PASSWORD));
  await env.user('modern@example.com', await hashPassword(PASSWORD));
  const median = async (email: string) => {
    const times: number[] = [];
    for (let i = 0; i < 7; i++) { const start = performance.now(); await env.signIn(email, 'wrong password here'); times.push(performance.now() - start); }
    return times.sort((a, b) => a - b)[3]!;
  };
  await median('nobody@example.com');
  const medians = [await median('nobody@example.com'), await median('modern@example.com'), await median('legacy@example.com')];
  assert.ok(Math.max(...medians) / Math.min(...medians) < 1.6, medians.map(value => value.toFixed(0)).join(' / '));
});

test('two-factor uses 6-digit, 30-second TOTP and 10 recovery codes in the published format', async () => {
  const env = setup();
  const { uri, backupCodes } = await withTwoFactor(env);
  const url = new URL(uri);
  assert.deepEqual([url.protocol, url.searchParams.get('digits'), url.searchParams.get('period'), url.searchParams.get('issuer')], ['otpauth:', '6', '30', 'Ten98 Test']);
  assert.equal(backupCodes.length, 10);
  for (const code of backupCodes) assert.match(code, BACKUP_CODE);
  assert.deepEqual(await (await env.signIn()).json(), { twoFactorRedirect: true, twoFactorMethods: ['totp'] });
});

test('ten wrong codes in sign-in challenges lock the factor, even for the right code', async () => {
  const env = setup();
  const { uri } = await withTwoFactor(env);
  // Bounded: a stricter or broken lockout ends the loop and fails below instead of hanging.
  let failures = 0, challenge = '';
  for (let attempt = 0; attempt < 40 && failures < 10; attempt++) {
    if (!challenge) challenge = cookieOf(await env.signIn());
    const response = await env.post('/two-factor/verify-totp', { code: '000000' }, challenge);
    if (response.status === 401) failures++;
    else if (response.status === 429) break;
    else challenge = '';
  }
  assert.equal(failures, 10);
  const locked = await env.post('/two-factor/verify-totp', { code: totp(uri) }, cookieOf(await env.signIn()));
  assert.notEqual(locked.status, 200);
});

test('OIDC sign-in sends a two-factor account through the challenge, and rotation needs the caller\'s own session', async () => {
  const env = setup();
  const { cookie } = await withTwoFactor(env);
  const id = (await env.auth.api.getSession({ headers: { cookie } }))!.user.id;
  const challenged = await env.auth.api.completeOidcSession({ body: { oidcUserId: id }, headers: {}, asResponse: true });
  assert.equal((await challenged.json() as { twoFactorRedirect?: boolean }).twoFactorRedirect, true);
  assert.ok(cookies(challenged).some(pair => pair.split('=')[0]!.endsWith('.two_factor')));
  assert.equal(await env.auth.api.getSession({ headers: { cookie: cookieOf(challenged) } }), null);
  assert.equal((await env.auth.api.rotateVerifiedSession({ body: { verifiedUserId: id }, headers: {}, asResponse: true })).status, 401);
  const other = await env.user('other@example.com', await hashPassword(PASSWORD));
  assert.equal((await env.auth.api.rotateVerifiedSession({ body: { verifiedUserId: other }, headers: { cookie }, asResponse: true })).status, 401);
  const rotated = await env.auth.api.rotateVerifiedSession({ body: { verifiedUserId: id }, headers: { cookie }, asResponse: true });
  assert.equal(rotated.status, 200);
  assert.equal((await env.auth.api.getSession({ headers: { cookie: cookieOf(rotated) } }))?.user.id, id);
  // The session that was rotated no longer works.
  assert.equal(await env.auth.api.getSession({ headers: { cookie } }), null);
  // Over HTTP both endpoints do not exist.
  assert.equal((await env.post('/complete-oidc-session', { oidcUserId: id })).status, 404);
  assert.equal((await env.post('/rotate-verified-session', { verifiedUserId: id }, cookie)).status, 404);
});

test('a session alone cannot set up two-factor for an account without a password unless the app opts in', async () => {
  for (const [allowPasswordless, ok] of [[undefined, false], [false, false], [true, true]] as const) {
    const env = setup(allowPasswordless === undefined ? {} : { allowPasswordless });
    const id = await env.user('sso@example.com');
    const session = await env.auth.api.completeOidcSession({ body: { oidcUserId: id }, headers: {}, asResponse: true });
    const enabled = await env.post('/two-factor/enable', {}, cookieOf(session));
    assert.equal(enabled.ok, ok, `allowPasswordless ${allowPasswordless}`);
  }
});

test('a password reset revokes sessions and ends trusted devices and pending challenges', async () => {
  const env = setup();
  const { cookie, uri } = await withTwoFactor(env);
  const challenge = cookieOf(await env.signIn());
  const trusted = await env.post('/two-factor/verify-totp', { code: totp(uri, 1), trustDevice: true }, challenge);
  assert.equal(trusted.status, 200);
  const trustCookie = cookies(trusted).filter(pair => pair.split('=')[0]!.endsWith('.trust_device')).join('; ');
  assert.ok(trustCookie);
  const pending = cookieOf(await env.signIn());
  assert.equal((await env.post('/request-password-reset', { email: 'owner@example.com', redirectTo: '/' })).status, 200);
  assert.equal((await env.post('/reset-password', { token: env.resets.at(-1), newPassword: 'a brand new password' })).status, 200);
  assert.equal(await env.auth.api.getSession({ headers: { cookie } }), null);
  assert.deepEqual(await (await env.signIn('owner@example.com', 'a brand new password', trustCookie)).json(), { twoFactorRedirect: true, twoFactorMethods: ['totp'] });
  assert.notEqual((await env.post('/two-factor/verify-totp', { code: totp(uri) }, pending)).status, 200);
});

test('a password reset ends trusted devices even behind more than 100 pending challenges', async () => {
  const env = setup();
  const { uri } = await withTwoFactor(env);
  const trusted = await env.post('/two-factor/verify-totp', { code: totp(uri, 1), trustDevice: true }, cookieOf(await env.signIn()));
  const trustCookie = cookies(trusted).filter(pair => pair.split('=')[0]!.endsWith('.trust_device')).join('; ');
  for (let i = 0; i < 101; i++) await env.signIn();
  // Signing in with the trust cookie rotates the trusted-device row, so it sits after the 101 pending challenges.
  assert.equal((await env.signIn('owner@example.com', PASSWORD, trustCookie)).status, 200);
  const rotatedTrust = (await env.signIn('owner@example.com', PASSWORD, trustCookie)).headers.getSetCookie().map(value => value.split(';')[0]!).filter(pair => pair.split('=')[0]!.endsWith('.trust_device') && !pair.endsWith('=')).join('; ') || trustCookie;
  const owned = env.db.verification!.filter(row => row.value !== '0').length;
  assert.ok(owned > 100, String(owned));
  assert.equal((await env.post('/request-password-reset', { email: 'owner@example.com', redirectTo: '/' })).status, 200);
  assert.equal((await env.post('/reset-password', { token: env.resets.at(-1), newPassword: 'a brand new password' })).status, 200);
  assert.equal(env.db.verification!.filter(row => typeof row.identifier === 'string' && /^(trust-device-|2fa-(?!attempts-))/.test(row.identifier)).length, 0);
  assert.deepEqual(await (await env.signIn('owner@example.com', 'a brand new password', rotatedTrust)).json(), { twoFactorRedirect: true, twoFactorMethods: ['totp'] });
});

test('unexpected adapter errors become a bare 500 without their text', async () => {
  const { post } = setup({}, adapter => options => {
    const real = adapter(options);
    return { ...real, findOne: async () => { throw new Error('SELECT password FROM account WHERE secret=1'); }, findMany: async () => { throw new Error('SELECT password FROM account WHERE secret=1'); } };
  });
  const response = await post('/sign-in/email', { email: 'owner@example.com', password: PASSWORD });
  assert.equal(response.status, 500);
  assert.equal((await response.text()).includes('SELECT'), false);
});

test('createTen98Auth refuses an invalid URL, a short secret, no app name or a bad cookie prefix', () => {
  const database = memoryAdapter({});
  for (const options of [{ appUrl: 'ftp://example.com' }, { appUrl: 'http://example.com' }, { secret: 'short' }, { appName: ' ' }, { cookiePrefix: 'a;b' }, { cookiePrefix: '' }]) {
    assert.throws(() => createTen98Auth({ database, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test', ...options }), TypeError, JSON.stringify(options));
  }
});

test('the instance an app holds refuses better-auth\'s own password sign-in unless allowRawPasswordSignIn is set', async () => {
  const strict = setup({ allowRawPasswordSignIn: false });
  await strict.user('owner@example.com', await hashPassword(PASSWORD));
  for (const path of ['/sign-in/email', '/sign-in/email/', '/sign-in/email//', '/Sign-In/Email', '/SIGN-IN/EMAIL/']) {
    const response = await strict.post(path, { email: 'owner@example.com', password: PASSWORD });
    assert.equal(response.status, 404, path);
    assert.equal(response.headers.getSetCookie().length, 0, path);
  }
  assert.equal((await strict.auth.handler(new Request(`${ORIGIN}/api/auth/sign-in/email`, { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: '{}' }))).status, 404);
  assert.throws(() => strict.auth.api.signInEmail({ body: { email: 'owner@example.com', password: PASSWORD }, asResponse: true }), /signInWithPassword/);
  assert.equal(strict.db.session!.length, 0);
  // Every other route still works.
  assert.equal((await strict.post('/request-password-reset', { email: 'owner@example.com', redirectTo: '/' })).status, 200);
  // The explicit option turns it back on.
  const raw = setup({ allowRawPasswordSignIn: true });
  await raw.user('owner@example.com', await hashPassword(PASSWORD));
  assert.equal((await raw.signIn()).status, 200);
});

// Tokens at rest (#131). The expected values are computed here from the published labels and rule, independently of
// the preset, so a changed label, key derivation or prefix rule fails these tests.
const keyFor = (label: string) => Buffer.from(hkdfSync('sha256', SECRET, '', label, 32));
const hmacOf = (label: string, value: string) => createHmac('sha256', keyFor(label)).update(value).digest('base64url');
const expectedHandle = (token: string) => `v1.${hmacOf('ten98-auth:session-token:v1', token)}`;
const expectedIdentifier = (identifier: string): string => {
  if (identifier.startsWith('2fa-attempts-')) return `2fa-attempts-${expectedIdentifier(identifier.slice('2fa-attempts-'.length))}`;
  const prefix = ['2fa-otp-', '2fa-', 'trust-device-', 'reset-password:'].find(candidate => identifier.startsWith(candidate));
  const label = 'ten98-auth:verification-identifier:v1';
  return prefix ? prefix + hmacOf(label, identifier.slice(prefix.length)) : `v1.${hmacOf(label, identifier)}`;
};
// A cookie's value without its better-call signature, and a value signed as better-call signs it.
const cookieValue = (response: Response, suffix: string) => {
  const pair = cookies(response).find(item => item.split('=')[0]!.endsWith(suffix))!;
  const value = decodeURIComponent(pair.slice(pair.indexOf('=') + 1));
  return value.slice(0, value.lastIndexOf('.'));
};
const signedCookie = (name: string, value: string) => `${name}=${encodeURIComponent(`${value}.${createHmac('sha256', SECRET).update(value).digest('base64')}`)}`;
const get = (env: ReturnType<typeof setup>, path: string, cookie: string) => env.auth.handler(new Request(`${ORIGIN}/api/auth${path}`, { headers: cookie ? { cookie } : {} }));

test('every better-auth 1.7.7 session-token path is one the storage wrapper was reviewed for', () => {
  const dist = new URL('../node_modules/better-auth/dist/', import.meta.url);
  const internal = readFileSync(new URL('db/internal-adapter.mjs', dist), 'utf8');
  assert.deepEqual([...internal.matchAll(/^\t\t(\w*Session\w*): async/gm)].map(match => match[1]).sort(),
    ['createSession', 'deleteSession', 'deleteSessions', 'deleteUserSessions', 'findSession', 'findSessions', 'listSessions', 'updateSession']);
  const places: string[] = [];
  for (const path of readdirSync(dist, { recursive: true, encoding: 'utf8' })) {
    if (!path.endsWith('.mjs')) continue;
    const file = path.replaceAll('\\', '/');
    const found = readFileSync(new URL(file, dist), 'utf8').split('model: "session"').length - 1;
    for (let at = 0; at < found; at++) places.push(file);
  }
  assert.deepEqual(places, Array(5).fill('db/internal-adapter.mjs'));
  // Every "session" literal in dist, file by file, whatever the method is called: a session path routed through
  // deleteManyWithHooks(…, "session") or any other helper changes these counts. The non-adapter ones are schema field
  // filters and client events.
  const literals: Record<string, number> = {};
  for (const path of readdirSync(dist, { recursive: true, encoding: 'utf8' })) {
    if (!path.endsWith('.mjs')) continue;
    const file = path.replaceAll('\\', '/'), found = readFileSync(new URL(file, dist), 'utf8').split('"session"').length - 1;
    if (found) literals[file] = found;
  }
  assert.deepEqual(literals, {
    'api/routes/session.mjs': 1, 'client/broadcast-channel.mjs': 1, 'client/session-refresh.mjs': 1, 'client/vue/index.mjs': 1,
    'db/internal-adapter.mjs': 12, 'db/schema.mjs': 4, 'plugins/two-factor/backup-codes/index.mjs': 1,
  });
  // The hook-routed session writes the wrapper was reviewed for (create, update, delete, deleteMany), with their callers.
  assert.equal(internal.split(/WithHooks\((?:[^()]|\([^()]*\))*?, "session"/).length - 1, 7);
});

test('only the reviewed plugins run: no multi-session (its deleteSessions deletes by a listed handle) and no admin', () => {
  const { auth } = setup();
  const ids = (auth as unknown as { options: { plugins: { id: string }[] } }).options.plugins.map(plugin => plugin.id);
  assert.deepEqual(ids, ['two-factor', 'ten98-oidc-session', 'ten98-session-revocation']);
});

test('revoke-other ends only the caller\'s own other sessions, and count and deleteMany by token hash the token', async () => {
  const env = setup();
  const a = await env.user('a@example.com', await hashPassword(PASSWORD));
  const b = await env.user('b@example.com', await hashPassword(PASSWORD));
  const [a1] = [cookieOf(await env.signIn('a@example.com')), cookieOf(await env.signIn('a@example.com'))];
  const bs = [await env.signIn('b@example.com'), await env.signIn('b@example.com')];
  const { adapter } = await env.context as unknown as { adapter: { count(query: unknown): Promise<number>; deleteMany(query: unknown): Promise<number> } };
  const live = (userId: string) => adapter.count({ model: 'session', where: [{ field: 'userId', value: userId }] });
  assert.deepEqual(await (await env.post('/revoke-other-sessions', {}, a1!)).json(), { status: true, revoked: 1 });
  assert.deepEqual([await live(a), await live(b)], [1, 2]);
  for (const response of bs) assert.ok(await env.auth.api.getSession({ headers: { cookie: cookieOf(response) } }));
  // By raw token, as better-auth's own calls give it: both find the stored handle.
  const token = cookieValue(bs[0]!, '.session_token');
  assert.equal(await adapter.count({ model: 'session', where: [{ field: 'token', value: token }] }), 1);
  assert.equal(await adapter.deleteMany({ model: 'session', where: [{ field: 'token', value: token }] }), 1);
  assert.equal(await env.auth.api.getSession({ headers: { cookie: cookieOf(bs[0]!) } }), null);
  assert.equal(await live(b), 1);
});

test('sessions are stored as keyed handles while the cookie, lookups and refreshes keep the raw token', async () => {
  const env = setup();
  await env.user('owner@example.com', await hashPassword(PASSWORD));
  const signedIn = await env.signIn();
  const token = cookieValue(signedIn, '.session_token');
  assert.equal(env.db.session!.length, 1);
  assert.equal(env.db.session![0]!.token, expectedHandle(token));
  assert.equal(env.auth.sessionTokenKey(token), expectedHandle(token));
  assert.equal(sessionTokenKey(SECRET, token), expectedHandle(token));
  assert.equal(JSON.stringify(env.db).includes(token), false);
  assert.equal((env.auth as unknown as { options: { session: { cookieCache: { enabled: boolean } } } }).options.session.cookieCache.enabled, false);
  const cookie = cookieOf(signedIn);
  assert.equal((await env.auth.api.getSession({ headers: { cookie } }))?.session.token, token);
  // Past updateAge the session is extended and its cookie re-set; it must carry the raw token, not the handle.
  env.db.session![0]!.expiresAt = new Date(Date.now() + (604_800 - 86_400 - 60) * 1000);
  const refreshed = await get(env, '/get-session', cookie);
  assert.equal(refreshed.status, 200);
  assert.equal(cookieValue(refreshed, '.session_token'), token);
  assert.ok((env.db.session![0]!.expiresAt as Date).getTime() > Date.now() + 604_000_000);
  assert.ok(await env.auth.api.getSession({ headers: { cookie: cookieOf(refreshed) } }));
  assert.equal(JSON.stringify(env.db).includes(token), false);
});

test('enabling two-factor replaces the session with another hashed one', async () => {
  const env = setup();
  const { cookie } = await withTwoFactor(env);
  const pair = cookie.split('; ').find(item => item.split('=')[0]!.endsWith('.session_token'))!;
  const value = decodeURIComponent(pair.slice(pair.indexOf('=') + 1));
  const token = value.slice(0, value.lastIndexOf('.'));
  assert.deepEqual(env.db.session!.map(row => row.token), [expectedHandle(token)]);
  assert.equal(JSON.stringify(env.db.session).includes(token), false);
});

test('listings show handles; revoke-other keeps the current session by id; a handle neither revokes nor signs in', async () => {
  const env = setup();
  const id = await env.user('owner@example.com', await hashPassword(PASSWORD));
  const responses = [await env.signIn(), await env.signIn(), await env.signIn()];
  const [a, b, c] = responses.map(cookieOf) as [string, string, string];
  const name = sessionCookieName(responses[0]!)!;
  const live = async () => (await env.context).adapter.count({ model: 'session', where: [{ field: 'userId', value: id }] });
  const valid = async (cookie: string) => !!(await env.auth.api.getSession({ headers: { cookie } }));
  assert.equal(await live(), 3);
  const listed = await (await get(env, '/list-sessions', a)).json() as { id: string; token: string }[];
  assert.equal(listed.length, 3);
  assert.ok(listed.every(session => session.token.startsWith('v1.')));
  const handleOfB = listed.find(session => session.token === expectedHandle(cookieValue(responses[1]!, '.session_token')))!.token;
  // A listed handle given to /revoke-session finds nothing, so it fails closed.
  await env.post('/revoke-session', { token: handleOfB }, a);
  assert.equal(await valid(b), true);
  // A leaked handle signed into a cookie is hashed again and matches nothing; the same signing of the raw token works.
  assert.equal(signedCookie(name, cookieValue(responses[1]!, '.session_token')), b.split('; ').find(item => item.startsWith(`${name}=`)));
  assert.equal(await valid(signedCookie(name, handleOfB)), false);
  const revoked = await env.post('/revoke-other-sessions', {}, a);
  assert.deepEqual(await revoked.json(), { status: true, revoked: 2 });
  assert.deepEqual([await valid(a), await valid(b), await valid(c)], [true, false, false]);
  assert.equal(await live(), 1);
  // The server call returns the same count.
  const d = cookieOf(await env.signIn());
  assert.equal(await live(), 2);
  assert.deepEqual(await env.auth.api.revokeOtherSessions({ headers: { cookie: d } }), { status: true, revoked: 1 });
  assert.deepEqual([await valid(a), await valid(d)], [false, true]);
  assert.equal((await env.post('/sign-out', {}, d)).status, 200);
  assert.equal(await valid(d), false);
  assert.equal(await live(), 0);
});

test('verification identifiers keep their prefix, hash the rest, and match the exported helpers', async () => {
  const env = setup();
  const { uri } = await withTwoFactor(env);
  const stored = () => env.db.verification!.map(row => row.identifier as string);
  const agree = (identifier: string) => {
    const expected = expectedIdentifier(identifier);
    assert.equal(env.auth.storedVerificationIdentifier(identifier), expected, identifier);
    assert.equal(storedVerificationIdentifier(SECRET, identifier), expected, identifier);
    return expected;
  };
  // A sign-in challenge and its attempt counter: '2fa-attempts-' || <stored challenge identifier>.
  const challenge = await env.signIn();
  const challengeId = cookieValue(challenge, '.two_factor');
  assert.ok(stored().includes(agree(challengeId)));
  assert.ok(stored().includes(agree(`2fa-attempts-${challengeId}`)));
  assert.equal(agree(`2fa-attempts-${challengeId}`), `2fa-attempts-${env.auth.storedVerificationIdentifier(challengeId)}`);
  const trusted = await env.post('/two-factor/verify-totp', { code: totp(uri, 1), trustDevice: true }, cookieOf(challenge));
  assert.equal(trusted.status, 200);
  const trustId = cookieValue(trusted, '.trust_device').split('!')[1]!;
  assert.ok(trustId.startsWith('trust-device-') && stored().includes(agree(trustId)));
  assert.equal((await env.post('/request-password-reset', { email: 'owner@example.com', redirectTo: '/' })).status, 200);
  assert.ok(stored().includes(agree(`reset-password:${env.resets.at(-1)}`)));
  // The prefixes no flow above creates, written through the same adapter.
  const { internalAdapter } = await env.context;
  for (const identifier of ['2fa-otp-abc123', 'delete-account-xyz789']) {
    await internalAdapter.createVerificationValue({ identifier, value: 'x', expiresAt: new Date(Date.now() + 60_000) });
    assert.ok(stored().includes(agree(identifier)), identifier);
  }
  assert.match(agree('delete-account-xyz789'), /^v1\.[A-Za-z0-9_-]{43}$/);
  const text = JSON.stringify(env.db.verification);
  for (const secret of [challengeId.slice(4), trustId.slice('trust-device-'.length), env.resets.at(-1)!, 'abc123', 'xyz789']) assert.equal(text.includes(secret), false, secret);
});

test('a reset link works end to end, its stored row cannot be redeemed, and the reset still ends hashed trusted devices', async () => {
  const env = setup();
  const { uri } = await withTwoFactor(env);
  const trusted = await env.post('/two-factor/verify-totp', { code: totp(uri, 1), trustDevice: true }, cookieOf(await env.signIn()));
  const trustCookie = cookies(trusted).filter(pair => pair.split('=')[0]!.endsWith('.trust_device')).join('; ');
  await env.signIn();
  const prefixed = () => env.db.verification!.filter(row => row.value !== '0' && /^(trust-device-|2fa-(?!attempts-))/.test(row.identifier as string));
  assert.ok(prefixed().length >= 2);
  assert.equal((await env.post('/request-password-reset', { email: 'owner@example.com', redirectTo: '/' })).status, 200);
  const token = env.resets.at(-1)!;
  const row = env.db.verification!.find(item => (item.identifier as string).startsWith('reset-password:'))!;
  // Someone who reads the row gets only its hash: sending the stored tail as the token is refused.
  assert.notEqual((await env.post('/reset-password', { token: (row.identifier as string).slice('reset-password:'.length), newPassword: 'a brand new password' })).status, 200);
  const callback = await get(env, `/reset-password/${token}?callbackURL=/done`, '');
  assert.match(callback.headers.get('location') ?? '', new RegExp(`token=${token}`));
  assert.equal((await env.post('/reset-password', { token, newPassword: 'a brand new password' })).status, 200);
  assert.equal(prefixed().length, 0);
  assert.deepEqual(await (await env.signIn('owner@example.com', 'a brand new password', trustCookie)).json(), { twoFactorRedirect: true, twoFactorMethods: ['totp'] });
});

test('the storage wrapper refuses what it cannot hash', async () => {
  assert.throws(() => createTen98Auth({ database: {} as never, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test' }), TypeError);
  assert.throws(() => storedVerificationIdentifier('short', 'reset-password:x'), TypeError);
  assert.throws(() => sessionTokenKey(SECRET, 1 as never), TypeError);
  // An adapter method better-auth 1.7.7 does not define would bypass the wrapper, so the adapter is refused.
  const extra = setup({}, adapter => options => ({ ...adapter(options), findByToken: async () => null }) as ReturnType<Adapter>);
  await assert.rejects(extra.context, /findByToken/);
  const { adapter } = await setup().context as unknown as { adapter: { findMany(query: unknown): Promise<unknown> } };
  await assert.rejects(adapter.findMany({ model: 'session', where: [{ field: 'token', operator: 'starts_with', value: 'v1.' }] }), TypeError);
});
