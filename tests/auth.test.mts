import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHmac, scryptSync } from 'node:crypto';
import test from 'node:test';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { hashPassword } from 'better-auth/crypto';
import { createTen98Auth, ten98AuthPolicy, verifyLegacyScryptHash } from '../auth.mjs';
import type { Ten98AuthOptions } from '../auth.mjs';

// better-auth on its in-memory adapter: no database, no network. Origin and cookies go through the real handler.
const ORIGIN = 'http://localhost:3000';
const SECRET = 'test-secret-that-is-long-enough-0123456789';
const PASSWORD = 'correct horse battery';
const BACKUP_CODE = /^[A-Za-z0-9]{5}-[A-Za-z0-9]{15}$/;
type Row = Record<string, unknown>;
type Context = { internalAdapter: {
  createUser(user: Row): Promise<{ id: string }>;
  linkAccount(account: Row): Promise<unknown>;
  findAccounts(userId: string): Promise<{ providerId: string; password?: string | null }[]>;
} };
type Adapter = ReturnType<typeof memoryAdapter>;

function setup(options: Partial<Ten98AuthOptions> = {}, wrap?: (adapter: Adapter) => Adapter) {
  const db: Record<string, Row[]> = { user: [], session: [], account: [], verification: [], twoFactor: [] };
  const resets: string[] = [];
  const adapter = memoryAdapter(db);
  const auth = createTen98Auth({ database: wrap ? wrap(adapter) : adapter, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test', sendResetPassword: ({ token }) => { resets.push(token); }, ...options });
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
    const auth = createTen98Auth({ database: memoryAdapter({ user: [], session: [], account: [], verification: [], twoFactor: [] }), appUrl: '${ORIGIN}', secret: '${SECRET}', appName: 'T' });
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
