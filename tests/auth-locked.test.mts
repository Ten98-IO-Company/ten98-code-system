import assert from 'node:assert/strict';
import { createHmac, hkdfSync, randomBytes, randomUUID, scryptSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { hashPassword } from 'better-auth/crypto';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { boolean, integer, pgTable, text, timestamp } from 'drizzle-orm/pg-core';
import pg from 'pg';
import { AmbiguousAccountError, createTen98Auth, signInOidcUser, linkOidcIdentity, LockedAuthClosedError, LockedAuthTransactionError, LockedAuthUserNotFoundError, MissingEmailIndexError,
  normaliseOidcIssuer, normaliseOidcIssuerSql, OidcIdentityError, oidcProviderId, revokeProviderSessions, SchemaMismatchError, tokenStorageUpgradeStatements, unlinkOidcIdentity } from '../auth.mjs';
import type { PasswordAttempt, Ten98Auth, Ten98AuthOptions } from '../auth.mjs';
import { session, transaction, TransactionRolledBackError, user } from '../db.mjs';
import { createWorkspaceTeam } from '../index.mjs';
import type { TeamClient } from '../index.mjs';
import { createTenancy } from '../tenancy.mjs';

// Locked auth (#132) and hashed token storage (#131) on real PostgreSQL through better-auth's Drizzle adapter, opt-in:
// set TEN98_TEST_DATABASE_URL to a disposable server (a superuser URL; each run creates and drops its own database).
const admin = process.env.TEN98_TEST_DATABASE_URL;
const skip = admin ? false : 'set TEN98_TEST_DATABASE_URL to a disposable PostgreSQL to run the locked-auth integration tests';
const ORIGIN = 'http://localhost:3000';
const SECRET = 'test-secret-that-is-long-enough-0123456789';
const PASSWORD = 'correct horse battery';
const NEW_PASSWORD = 'a brand new password';

// better-auth's tables for the preset (core plus the two-factor plugin), over workspace-team.sql's user, session and account.
const stamp = (name: string) => timestamp(name, { withTimezone: true });
const account = pgTable('account', {
  id: text('id').primaryKey(), accountId: text('accountId').notNull(), providerId: text('providerId').notNull(), userId: text('userId').notNull(),
  accessToken: text('accessToken'), refreshToken: text('refreshToken'), idToken: text('idToken'), accessTokenExpiresAt: stamp('accessTokenExpiresAt'),
  refreshTokenExpiresAt: stamp('refreshTokenExpiresAt'), scope: text('scope'), password: text('password'), createdAt: stamp('createdAt').notNull(), updatedAt: stamp('updatedAt').notNull(),
});
const verification = pgTable('verification', {
  id: text('id').primaryKey(), identifier: text('identifier').notNull(), value: text('value').notNull(), expiresAt: stamp('expiresAt').notNull(),
  createdAt: stamp('createdAt').notNull(), updatedAt: stamp('updatedAt').notNull(),
});
const twoFactor = pgTable('twoFactor', {
  id: text('id').primaryKey(), secret: text('secret').notNull(), backupCodes: text('backupCodes').notNull(), userId: text('userId').notNull(),
  verified: boolean('verified'), failedVerificationCount: integer('failedVerificationCount'), lockedUntil: stamp('lockedUntil'),
});
const schema = { user, session, account, verification, twoFactor };
// Plus an installation row (first-user setup), an app limiter table like campaign's, and a log of password writes.
const betterAuthTables = `
  ALTER TABLE account ADD COLUMN "accessToken" text, ADD COLUMN "refreshToken" text, ADD COLUMN "idToken" text,
    ADD COLUMN "accessTokenExpiresAt" timestamptz, ADD COLUMN "refreshTokenExpiresAt" timestamptz, ADD COLUMN scope text;
  CREATE TABLE verification (id text PRIMARY KEY, identifier text NOT NULL, value text NOT NULL, "expiresAt" timestamptz NOT NULL,
    "createdAt" timestamptz NOT NULL DEFAULT now(), "updatedAt" timestamptz NOT NULL DEFAULT now());
  CREATE TABLE "twoFactor" (id text PRIMARY KEY, secret text NOT NULL, "backupCodes" text NOT NULL, "userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    verified boolean, "failedVerificationCount" integer, "lockedUntil" timestamptz);
  CREATE TABLE installation (id integer PRIMARY KEY, claimed_by text);
  INSERT INTO installation VALUES (1, NULL);
  CREATE TABLE login_limits (key text PRIMARY KEY, count integer NOT NULL);
  CREATE TABLE password_writes (user_id text NOT NULL);
  CREATE FUNCTION log_password_write() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.password IS DISTINCT FROM OLD.password THEN INSERT INTO password_writes VALUES (NEW."userId"); END IF; RETURN NEW; END $$;
  CREATE TRIGGER password_writes AFTER UPDATE ON account FOR EACH ROW EXECUTE FUNCTION log_password_write();`;

type Database = ReturnType<typeof drizzle<typeof schema>>;
let pool: pg.Pool | undefined;
let db: Database;
let auth: Ten98Auth;
let database = '';
let url = '';
let deviceCookie = '';
let hashes: { old: string; new: string; legacy: string };
const team = createWorkspaceTeam({ hashPassword });
const tenancy = createTenancy({ setting: 'app.workspace_ids', column: 'workspace_id', tables: ['workspace_invitation'] });
const adapterOver = (client: unknown) => drizzleAdapter(client as Database, { provider: 'pg', schema });
const authOver = (target: Database, options: Partial<Ten98AuthOptions> = {}) =>
  createTen98Auth({ database: adapterOver(target), transactionDatabase: adapterOver, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test', ...options });
// The two-step limiter with the source step allowing everything and the given account step.
const accountStep = (account: (attempt: PasswordAttempt) => unknown) => ({ source: () => true, account: account as (attempt: PasswordAttempt) => boolean });
const allow = accountStep(() => true);

test.before(async () => {
  if (!admin) return;
  database = `ten98_auth_${randomBytes(6).toString('hex')}`;
  const root = new pg.Client({ connectionString: admin });
  await root.connect();
  await root.query(`CREATE DATABASE ${database}`);
  await root.end();
  const target = new URL(admin);
  target.pathname = `/${database}`;
  url = target.href;
  pool = new pg.Pool({ connectionString: url, max: 8 });
  await pool.query(readFileSync(new URL('../workspace-team.sql', import.meta.url), 'utf8'));
  await pool.query(betterAuthTables);
  db = drizzle(pool, { schema });
  auth = authOver(db);
  deviceCookie = (await (auth as unknown as { $context: Promise<{ createAuthCookie(name: string): { name: string } }> }).$context).createAuthCookie('known_device').name;
  // Campaign's legacy format: scrypt$<salt>$<key>, the 32 hex characters of salt passed to scrypt as text.
  const salt = '0123456789abcdef0123456789abcdef';
  hashes = { old: await hashPassword(PASSWORD), new: await hashPassword(NEW_PASSWORD),
    legacy: `scrypt$${salt}$${scryptSync(PASSWORD, salt, 64, { N: 65_536, maxmem: 128 * 1024 * 1024 }).toString('hex')}` };
});
test.after(async () => {
  if (!admin || !pool) return;
  await pool.end();
  const root = new pg.Client({ connectionString: admin });
  await root.connect();
  await root.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
  await root.end();
});

async function account_(email: string, { twoFactor: enabled = false, hash = hashes.old as string | null } = {}) {
  const id = randomUUID();
  await pool!.query('INSERT INTO "user"(id,name,email,"twoFactorEnabled") VALUES($1,$2,$3,$4)', [id, 'Test', email, enabled]);
  await pool!.query('INSERT INTO account(id,"accountId","providerId","userId",password) VALUES($1,$2,\'credential\',$2,$3)', [randomUUID(), id, hash]);
  return id;
}
const address = (label: string) => `${label}-${randomUUID()}@example.com`;
// The supported password sign-in, from one fixed source; the limiter allows everything.
const SOURCE = 'ip:test-client';
const signIn = (email: string, password = PASSWORD) => auth.signInWithPassword(db, { source: SOURCE, email, password }, allow);
const cookieOf = (response: Response) => response.headers.getSetCookie().map(value => value.split(';')[0]!).filter(pair => !pair.endsWith('=')).join('; ');
const rawToken = (cookie: string) => {
  const pair = cookie.split('; ').find(item => item.split('=')[0]!.endsWith('.session_token'))!;
  const value = decodeURIComponent(pair.slice(pair.indexOf('=') + 1));
  return value.slice(0, value.lastIndexOf('.'));
};
const sessions = async (userId: string) => (await pool!.query<{ n: number }>('SELECT count(*)::int AS n FROM session WHERE "userId"=$1', [userId])).rows[0]!.n;
const storedPassword = async (userId: string) => (await pool!.query<{ password: string }>('SELECT password FROM account WHERE "userId"=$1', [userId])).rows[0]!.password;
const setPassword = (tx: { execute(query: ReturnType<typeof sql>): Promise<unknown> }, userId: string) =>
  tx.execute(sql`UPDATE account SET password = ${hashes.new} WHERE "userId" = ${userId} AND "providerId" = 'credential'`);
// The pg connection under a locked-auth transaction, as an app passes it to the team controller.
const clientOf = (tx: unknown) => (tx as { _: { session: { client: TeamClient } } })._.session.client;
const refused = (error: unknown) => error instanceof LockedAuthTransactionError && error.code === 'LOCKED_AUTH_TRANSACTION';
// Drizzle reports a failed statement as DrizzleQueryError with the driver's error as its cause.
const causeOf = (error: unknown): unknown => (error as { cause?: unknown } | null)?.cause ?? error;
const closed = (error: unknown) => [error, causeOf(error)].some(item => item instanceof LockedAuthClosedError && item.code === 'LOCKED_AUTH_CLOSED');
const sqlState = (error: unknown) => (causeOf(error) as { code?: string }).code;
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
// Settles to 'timeout' instead of hanging, so a missing timeout fails the test rather than stalling the suite.
const within = <T,>(promise: Promise<T>, ms: number) => Promise.race([promise, delay(ms).then(() => 'timeout' as const)]);
// A promise the test settles, so one connection can hold its locks while the other is observed waiting.
function gate() {
  let open!: () => void;
  const opened = new Promise<void>(resolve => { open = resolve; });
  return { open, opened };
}
// True once some backend of this database waits on a lock: the second connection is queued, not racing.
async function someoneWaits() {
  for (let attempt = 0; attempt < 200; attempt++) {
    const { rows } = await pool!.query<{ n: number }>("SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'");
    if (rows[0]!.n > 0) return true;
    await delay(25);
  }
  return false;
}
async function inTransaction<T>(run: (client: TeamClient) => Promise<T>, held?: Promise<void>, on: pg.Pool = pool!): Promise<T> {
  const client = await on.connect();
  try {
    await client.query('BEGIN');
    const result = await run(client as unknown as TeamClient);
    await held;
    await client.query('COMMIT');
    return result;
  } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; }
  finally { client.release(); }
}
async function workspaceOf(owner: string) {
  const { workspace } = await inTransaction(client => team.createWorkspace(client, owner, { name: 'Acme' }));
  return workspace.id;
}
type ChangePassword = { changePassword(input: { body: Record<string, unknown>; headers: HeadersInit; asResponse: true }): Promise<Response> };
const oidcSession = (bound: { api: Ten98Auth['api'] }, userId: string) => bound.api.completeOidcSession({ body: { oidcUserId: userId, provider: 'idp' }, headers: {}, asResponse: true });
const answer = async (response: Response) => ({ status: response.status, body: await response.text(), headers: [...response.headers].filter(([name]) => name !== 'date') });

test('through Drizzle, no raw token is stored; listings count by user; revoke-other inside withLockedAuth reports its count', { skip }, async () => {
  const email = address('stored');
  const id = await account_(email);
  const cookies = [cookieOf(await signIn(email)), cookieOf(await signIn(email)), cookieOf(await signIn(email))];
  const stored = (await pool!.query<{ token: string }>('SELECT token FROM session WHERE "userId"=$1', [id])).rows.map(row => row.token).sort();
  assert.deepEqual(stored, cookies.map(cookie => auth.sessionTokenKey(rawToken(cookie))).sort());
  const { adapter } = await (auth as unknown as { $context: Promise<{ adapter: { count(query: unknown): Promise<number> } }> }).$context;
  assert.equal(await adapter.count({ model: 'session', where: [{ field: 'userId', value: id }] }), 3);
  assert.deepEqual(await auth.withLockedAuth(db, id, bound => bound.api.revokeOtherSessions({ headers: { cookie: cookies[0]! } })), { status: true, revoked: 2 });
  assert.equal(await adapter.count({ model: 'session', where: [{ field: 'userId', value: id }] }), 1);
  assert.ok(await auth.api.getSession({ headers: { cookie: cookies[0]! } }));
  // A reset requested under the email lock stores the hashed identifier.
  const resets: string[] = [];
  const resetting = authOver(db, { sendResetPassword: ({ token }) => { resets.push(token); } });
  await resetting.withLockedAuthByEmail(db, email, bound => (bound.api as unknown as { requestPasswordReset(input: { body: { email: string; redirectTo: string } }): Promise<unknown> }).requestPasswordReset({ body: { email, redirectTo: '/' } }));
  const identifiers = (await pool!.query<{ identifier: string }>('SELECT identifier FROM verification WHERE value=$1', [id])).rows.map(row => row.identifier);
  assert.deepEqual(identifiers, [resetting.storedVerificationIdentifier(`reset-password:${resets[0]}`)]);
});

test('an old password checked before a CLI reset committed gets 401 under the lock and creates no session', { skip }, async () => {
  const email = address('cli');
  const id = await account_(email);
  assert.equal((await signIn(email)).status, 200);
  const held = gate(), entered = gate();
  const reset = auth.withLockedAuth(db, id, async (bound, tx) => {
    await setPassword(tx, id);
    await bound.revokeAllSessions();
    entered.open();
    await held.opened;
  });
  await entered.opened;
  // The first check reads the committed (old) hash and passes; the second, under the lock, sees the new one.
  const oldPassword = auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow);
  assert.equal(await someoneWaits(), true);
  held.open();
  await reset;
  assert.deepEqual(await answer(await oldPassword), await answer(await auth.signInWithPassword(db, { source: SOURCE, email: address('unknown'), password: PASSWORD }, allow)));
  assert.equal(await sessions(id), 0);
  const signedIn = await auth.signInWithPassword(db, { source: SOURCE, email, password: NEW_PASSWORD }, allow);
  assert.equal(signedIn.status, 200);
  assert.ok(await auth.api.getSession({ headers: { cookie: cookieOf(signedIn) } }));
});

test('a password change cannot recreate a session revoked while it waited', { skip }, async () => {
  const email = address('change');
  const id = await account_(email);
  const cookie = cookieOf(await signIn(email));
  const held = gate(), entered = gate();
  const revoke = auth.withLockedAuth(db, id, async bound => { await bound.revokeAllSessions(); entered.open(); await held.opened; });
  await entered.opened;
  const change = auth.withLockedAuth(db, id, bound => (bound.api as unknown as ChangePassword).changePassword({
    body: { currentPassword: PASSWORD, newPassword: NEW_PASSWORD, revokeOtherSessions: true }, headers: { cookie }, asResponse: true,
  }));
  assert.equal(await someoneWaits(), true);
  held.open();
  await revoke;
  assert.equal((await change).status, 401);
  assert.equal(await sessions(id), 0);
  assert.equal(await storedPassword(id), hashes.old);
});

test('a transaction killed mid-callback, or a callback that throws, persists nothing', { skip }, async () => {
  const id = await account_(address('kill'));
  await assert.rejects(auth.withLockedAuth(db, id, async (bound, tx) => {
    await setPassword(tx, id);
    assert.equal((await oidcSession(bound, id)).status, 200);
    const { rows } = await tx.execute(sql`SELECT pg_backend_pid() AS pid`) as unknown as { rows: { pid: number }[] };
    await pool!.query('SELECT pg_terminate_backend($1)', [rows[0]!.pid]);
    await tx.execute(sql`SELECT 1`);
  }));
  assert.equal(await storedPassword(id), hashes.old);
  assert.equal(await sessions(id), 0);
  const failure = new Error('the callback failed');
  await assert.rejects(auth.withLockedAuth(db, id, async (bound, tx) => {
    await setPassword(tx, id);
    assert.equal((await oidcSession(bound, id)).status, 200);
    throw failure;
  }), error => error === failure);
  assert.equal(await storedPassword(id), hashes.old);
  assert.equal(await sessions(id), 0);
});

test('after its callback returns, a locked instance and its transaction refuse every use and persist nothing', { skip }, async () => {
  const id = await account_(address('closed'));
  let kept: { bound: Parameters<Parameters<Ten98Auth['withLockedAuth']>[2]>[0]; tx: { execute(query: ReturnType<typeof sql>): Promise<unknown> } } | undefined;
  let late: Promise<unknown> | undefined;
  await auth.withLockedAuth(db, id, async (bound, tx) => {
    kept = { bound, tx };
    // Not awaited: it runs after the callback has returned. Handled at once, so a COMMIT slower than the delay never
    // leaves its rejection unhandled; assert.rejects below still checks it.
    late = delay(50).then(() => oidcSession(bound, id));
    late.catch(() => undefined);
  });
  await assert.rejects(late!, closed);
  assert.throws(() => oidcSession(kept!.bound, id), closed);
  assert.throws(() => kept!.bound.handler(new Request(`${ORIGIN}/api/auth/get-session`)), closed);
  await assert.rejects(kept!.bound.revokeAllSessions(), closed);
  await assert.rejects(kept!.tx.execute(sql`INSERT INTO session(id,"expiresAt",token,"createdAt","updatedAt","userId") VALUES ('late',now()+interval '1 day','late',now(),now(),${id})`), closed);
  // Even better-auth's own context, reached past the wrapper, runs on the closed transaction.
  const { internalAdapter } = await (kept!.bound as unknown as { $context: Promise<{ internalAdapter: { createSession(userId: string): Promise<unknown> } }> }).$context;
  await assert.rejects(internalAdapter.createSession(id), closed);
  assert.equal(await sessions(id), 0);
});

test('the workspace team operations, the tenancy helpers and a misordered lockEmail refuse a locked-auth transaction', { skip }, async () => {
  const email = address('refuse');
  const id = await account_(email);
  const workspaceId = await workspaceOf(id);
  const allowed = ['isInstanceOperator', 'lockEmail', 'requireInstanceOperator', 'requireNamedInstanceOperator', 'setInstanceOperator'];
  const workspaceLevel = Object.keys(team).filter(name => !allowed.includes(name)).sort();
  // Every method that is not explicitly allowed must refuse; a new one fails here until it is classified.
  assert.deepEqual(workspaceLevel, ['acceptInvitation', 'acceptVerifiedOidcInvitation', 'changeRole', 'createWorkspace', 'getTeam', 'inspectInvitation', 'inviteMember',
    'memberNeedsFactor', 'removeMember', 'renameWorkspace', 'revokeInvitation', 'rotateInvitation', 'setTwoFactorRequirement', 'transferOwnership']);
  // One connection, so the unmarked transactions below run on the connection the locked one used.
  const single = new pg.Pool({ connectionString: url, max: 1 });
  const singleDb = drizzle(single, { schema });
  try {
    await auth.withLockedAuth(singleDb, id, async (_bound, tx) => {
      const client = clientOf(tx);
      for (const name of workspaceLevel) {
        const operation = (team as unknown as Record<string, (...input: unknown[]) => Promise<unknown>>)[name]!;
        await assert.rejects(operation(client, workspaceId, id, { name: 'x', email, role: 'viewer', required: false, token: 'x'.repeat(43) }, {}), refused, name);
      }
      await assert.rejects(tenancy.withWorkspace(tx, id, workspaceId, 'read', async () => 1), refused);
      await assert.rejects(tenancy.withWorkspace(singleDb, id, workspaceId, 'write', async () => 1, tx), refused);
      await assert.rejects(tenancy.withWorkspaces(tx, id, [workspaceId], async () => 1), refused);
      await assert.rejects(tx.transaction(inner => tenancy.withWorkspace(inner, id, workspaceId, 'read', async () => 1)), refused);
      // After the user row, the email lock would reverse the global order, even for the user's own email.
      await assert.rejects(team.lockEmail(client, email), refused);
    });
    await auth.withLockedAuthByEmail(singleDb, email, async (_bound, tx) => {
      // By email the transaction already holds this email's lock first; another email's would come after the user row.
      await team.lockEmail(clientOf(tx), ` ${email.toUpperCase()} `);
      await assert.rejects(team.lockEmail(clientOf(tx), address('other')), refused);
      await assert.rejects(team.getTeam(clientOf(tx), workspaceId, id), refused);
    });
    assert.equal(await transaction(singleDb, tx => tenancy.withWorkspace(tx, id, workspaceId, 'read', async (_tx, access) => access.role)), 'owner');
    assert.equal(await tenancy.withWorkspace(singleDb, id, workspaceId, 'read', async (_tx, access) => access.role), 'owner');
    assert.equal(await inTransaction(async client => { await team.lockEmail(client, email); return (await team.getTeam(client, workspaceId, id)).role; }, undefined, single), 'owner');
  } finally { await single.end(); }
});

test('lockEmail after a by-id lock is refused instead of deadlocking against a sign-in by email', { skip }, async () => {
  const email = address('order');
  const id = await account_(email);
  const held = gate(), entered = gate();
  const byId = auth.withLockedAuth(db, id, async (_bound, tx) => { entered.open(); await held.opened; await team.lockEmail(clientOf(tx), email); });
  await entered.opened;
  // The sign-in takes the email lock, then queues on the user row the first transaction holds.
  const byEmail = auth.withLockedAuthByEmail(db, email, async (_bound, _tx, userId) => userId);
  assert.equal(await someoneWaits(), true);
  held.open();
  await assert.rejects(byId, refused);
  assert.equal(await byEmail, id);
});

test('withLockedAuth refuses a missing user, a transaction, a missing binding, nesting and password sign-in inside', { skip }, async () => {
  await assert.rejects(auth.withLockedAuth(db, randomUUID(), async () => 1), error => error instanceof LockedAuthUserNotFoundError && error.status === 404);
  const email = address('refusals');
  const id = await account_(email);
  await assert.rejects(transaction(db, tx => auth.withLockedAuth(tx as unknown as Database, id, async () => 1)), TypeError);
  await assert.rejects(createTen98Auth({ database: adapterOver(db), appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test' }).withLockedAuth(db, id, async () => 1), /transactionDatabase/);
  await auth.withLockedAuth(db, id, async (bound, tx) => {
    // A second locked-auth transaction would wait on this one's locks: refused at once, for any user and by email.
    assert.equal(await within(auth.withLockedAuth(db, id, async () => 1).then(() => 'ran', error => refused(error) ? 'refused' : String(error)), 3000), 'refused');
    assert.equal(await within(auth.withLockedAuthByEmail(db, email, async () => 1).then(() => 'ran', error => refused(error) ? 'refused' : String(error)), 3000), 'refused');
    assert.equal(await within(auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow).then(() => 'ran', error => refused(error) ? 'refused' : String(error)), 3000), 'refused');
    // Password sign-in here would hash while holding the connection and the lock.
    assert.throws(() => bound.api.signInEmail({ body: { email, password: PASSWORD }, asResponse: true }), /signInWithPassword/);
    for (const path of ['/api/auth/sign-in/email', '/api/auth/sign-in/email/', '/api/auth/Sign-In/Email']) {
      assert.throws(() => bound.handler(new Request(`${ORIGIN}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: '{}' })), /signInWithPassword/, path);
    }
    void tx;
  });
  // From outside the callback's async context, a Drizzle database over the locked connection is refused by its mark.
  const held = gate(), entered = gate();
  let connection: unknown;
  const locked = auth.withLockedAuth(db, id, async (_bound, tx) => { connection = clientOf(tx); entered.open(); await held.opened; });
  await entered.opened;
  assert.equal(await within(auth.withLockedAuth(drizzle(connection as pg.PoolClient, { schema }), id, async () => 1).then(() => 'ran', error => refused(error) ? 'refused' : String(error)), 3000), 'refused');
  held.open();
  await locked;
  const nobody = address('nobody');
  assert.deepEqual(await auth.withLockedAuthByEmail(db, nobody, async (bound, _tx, userId) => { await bound.revokeAllSessions(); return userId; }), undefined);
});

test('the helper\'s lock_timeout and the pool\'s turn self-waits into SQLSTATE 55P03 instead of a hang', { skip }, async () => {
  const id = await account_(address('timeout'), { twoFactor: true });
  // Another transaction holds the user row: the helper's own lock statement gives up after lockTimeoutMs.
  const holder = await pool!.connect();
  try {
    await holder.query('BEGIN');
    await holder.query('SELECT id FROM "user" WHERE id=$1 FOR UPDATE', [id]);
    const quick = authOver(db, { lockTimeoutMs: 300 });
    const outcome = await within(quick.withLockedAuth(db, id, async () => 'ran').then(value => value, sqlState), 5000);
    assert.equal(outcome, '55P03');
  } finally { await holder.query('ROLLBACK'); holder.release(); }
  // A team helper on its own pool connection inside the callback waits on this transaction's row; only that pool's
  // lock_timeout (the guide's requirement) ends the wait.
  const workspaceId = await workspaceOf(id);
  const timed = new pg.Pool({ connectionString: url, max: 2, lock_timeout: 300 } as pg.PoolConfig);
  try {
    const outcome = await auth.withLockedAuth(db, id, async () => within(
      inTransaction(client => team.setTwoFactorRequirement(client, workspaceId, id, { required: true }), undefined, timed).then(() => 'ran', sqlState), 5000));
    assert.equal(outcome, '55P03');
  } finally { await timed.end(); }
});

test('acceptInvitation and withLockedAuthByEmail on the same email wait for each other in either order', { skip }, async () => {
  const owner = await account_(address('owner'));
  const workspaceId = await workspaceOf(owner);
  const invite = async (email: string) => (await inTransaction(client => team.inviteMember(client, workspaceId, owner, { email, role: 'editor' }))).token;
  // The locked-auth transaction holds the email lock and the user row; the acceptance queues on the email lock.
  const first = address('invitee');
  const firstId = await account_(first);
  const firstToken = await invite(first);
  const held = gate(), entered = gate();
  const locked = auth.withLockedAuthByEmail(db, first, async (bound, _tx, userId) => { await bound.revokeAllSessions(); entered.open(); await held.opened; return userId; });
  await entered.opened;
  const accepted = inTransaction(client => team.acceptInvitation(client, { token: firstToken }, { id: firstId, email: first }));
  assert.equal(await someoneWaits(), true);
  held.open();
  assert.equal(await locked, firstId);
  assert.equal((await accepted).joined, true);
  // The acceptance holds workspace, invitation and email locks; the locked-auth transaction queues on the email lock.
  const second = address('invitee');
  const secondId = await account_(second);
  const secondToken = await invite(second);
  const release = gate(), taken = gate();
  const acceptedFirst = inTransaction(async client => {
    const result = await team.acceptInvitation(client, { token: secondToken }, { id: secondId, email: second });
    taken.open();
    return result;
  }, release.opened);
  await taken.opened;
  const lockedAfter = auth.withLockedAuthByEmail(db, second, async (_bound, _tx, userId) => userId);
  assert.equal(await someoneWaits(), true);
  release.open();
  assert.equal((await acceptedFirst).joined, true);
  assert.equal(await lockedAfter, secondId);
});

test('setTwoFactorRequirement and a locked password change wait for each other in either order', { skip }, async () => {
  const owner = await account_(address('factor'), { twoFactor: true });
  const workspaceId = await workspaceOf(owner);
  const held = gate(), entered = gate();
  const change = auth.withLockedAuth(db, owner, async (_bound, tx) => { await setPassword(tx, owner); entered.open(); await held.opened; });
  await entered.opened;
  const requirement = inTransaction(client => team.setTwoFactorRequirement(client, workspaceId, owner, { required: true }));
  assert.equal(await someoneWaits(), true);
  held.open();
  await change;
  assert.deepEqual(await requirement, { twoFactorRequired: true });
  // The requirement holds the owner's row FOR SHARE; the locked change's lock statement queues behind it.
  const release = gate(), locked = gate();
  const requiredFirst = inTransaction(async client => { const result = await team.setTwoFactorRequirement(client, workspaceId, owner, { required: true }); locked.open(); return result; }, release.opened);
  await locked.opened;
  const changeAfter = auth.withLockedAuth(db, owner, async (_bound, tx) => { await setPassword(tx, owner); return 'changed'; });
  assert.equal(await someoneWaits(), true);
  release.open();
  assert.deepEqual(await requiredFirst, { twoFactorRequired: true });
  assert.equal(await changeAfter, 'changed');
});

test('first-user setup (installation row, then the email lock) makes a locked-auth transaction by email wait, then find the account', { skip }, async () => {
  const email = address('first');
  const release = gate(), claimed = gate();
  const userId = randomUUID();
  const setup = inTransaction(async client => {
    await client.query('SELECT id FROM installation WHERE id=1 FOR UPDATE');
    await team.lockEmail(client, email);
    await client.query('INSERT INTO "user"(id,name,email) VALUES($1,$2,$3)', [userId, 'Owner', email]);
    await client.query('INSERT INTO account(id,"accountId","providerId","userId",password) VALUES($1,$2,\'credential\',$2,$3)', [randomUUID(), userId, hashes.old]);
    await client.query('UPDATE installation SET claimed_by=$1 WHERE id=1', [userId]);
    claimed.open();
  }, release.opened);
  await claimed.opened;
  const found = auth.withLockedAuthByEmail(db, email, async (_bound, _tx, userId) => userId);
  assert.equal(await someoneWaits(), true);
  release.open();
  await setup;
  assert.equal(await found, userId);
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow)).status, 200);
});

test('signInWithPassword: limit first, one uniform failure, and a session only for the right password', { skip }, async () => {
  const email = address('password');
  const id = await account_(email);
  const passwordless = address('passwordless');
  await account_(passwordless, { hash: null });
  // The limit runs before the credential read (and so before any hash); refused, nothing is read.
  const order: string[] = [];
  const watched = new Proxy(db, { get(target, key, receiver) { if (key === 'select') order.push('read'); return Reflect.get(target, key, receiver); } });
  const limited = await auth.signInWithPassword(watched, { source: SOURCE, email, password: PASSWORD }, { source: attempt => { order.push(`source:${attempt.email}`); return false; }, account: () => { order.push('account'); return true; } });
  assert.deepEqual([limited.status, order], [429, [`source:${email}`]]);
  assert.equal((await auth.signInWithPassword(watched, { source: SOURCE, email: ` ${email.toUpperCase()} `, password: 'wrong password guess' }, { source: attempt => { order.push(`source:${attempt.email}`); return true; }, account: attempt => { order.push(`account:${attempt.email}`); return true; } })).status, 401);
  assert.deepEqual(order.slice(1), [`source:${email}`, `account:${email}`, 'read']);
  // Anything but true refuses: a limiter that forgets to return is not an allowance.
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, accountStep((() => undefined) as unknown as () => boolean))).status, 429);
  // Unknown email, wrong password and an account without a password answer identically.
  const unknown = await answer(await auth.signInWithPassword(db, { source: SOURCE, email: address('nobody'), password: PASSWORD }, allow));
  assert.equal(unknown.status, 401);
  assert.deepEqual(await answer(await auth.signInWithPassword(db, { source: SOURCE, email, password: 'wrong password guess' }, allow)), unknown);
  assert.deepEqual(await answer(await auth.signInWithPassword(db, { source: SOURCE, email: passwordless, password: PASSWORD }, allow)), unknown);
  assert.equal(await sessions(id), 0);
  const signedIn = await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { 'user-agent': 'fixture-agent' } }, allow);
  assert.equal(signedIn.status, 200);
  assert.equal((await auth.api.getSession({ headers: { cookie: cookieOf(signedIn) } }))?.user.id, id);
  assert.equal((await pool!.query<{ agent: string }>('SELECT "userAgent" AS agent FROM session WHERE "userId"=$1', [id])).rows[0]!.agent, 'fixture-agent');
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: 1 as unknown as string }, allow)).status, 400);
  // A cross-site browser request is refused before the limit counts it; the app's own origin goes ahead.
  let counted = 0;
  const counting = () => { counted++; return true; };
  for (const headers of [{ origin: 'https://evil.example' }, { 'sec-fetch-site': 'cross-site' }, { 'sec-fetch-site': 'CROSS-SITE' }, { origin: ORIGIN, 'sec-fetch-site': 'Same-Site' }] as Record<string, string>[]) {
    assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers }, accountStep(counting))).status, 403, JSON.stringify(headers));
  }
  assert.equal(counted, 0);
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { origin: ORIGIN, 'sec-fetch-site': 'same-origin' } }, accountStep(counting))).status, 200);
  // A password over the policy's maximum is wrong for every account: the same 401, without a derivation.
  const started = performance.now();
  assert.deepEqual(await answer(await auth.signInWithPassword(db, { source: SOURCE, email, password: 'x'.repeat(129) }, allow)), unknown);
  assert.ok(performance.now() - started < 100);
});

test('signInWithPassword costs the same for unknown, current, legacy and passwordless accounts', { skip }, async () => {
  const current = address('timing'), legacy = address('timing'), none = address('timing');
  await account_(current);
  await account_(legacy, { hash: hashes.legacy });
  await account_(none, { hash: null });
  // Wall time and process CPU time (all threads, so both scrypt derivations count): the two run in parallel, so a
  // skipped dummy derivation shows in the work done even where the slower one hides it from the latency.
  // Interleaved, so load drifting over the run touches the four cases alike; the first two rounds warm up.
  const cases = [address('nobody'), current, legacy, none];
  const samples = cases.map(() => ({ times: [] as number[], work: [] as number[] }));
  for (let round = 0; round < 9; round++) {
    for (const [at, email] of cases.entries()) {
      const started = performance.now(), cpu = process.cpuUsage();
      assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: 'wrong password guess' }, allow)).status, 401);
      const used = process.cpuUsage(cpu);
      if (round < 2) continue;
      samples[at]!.times.push(performance.now() - started);
      samples[at]!.work.push((used.user + used.system) / 1000);
    }
  }
  const middle = (values: number[]) => values.sort((a, b) => a - b)[Math.floor(values.length / 2)]!;
  const medians = samples.map(({ times, work }) => [middle(times), middle(work)] as const);
  const spread = (values: number[]) => Math.max(...values) / Math.min(...values);
  const shown = medians.map(([time, cpu]) => `${time.toFixed(0)} ms, ${cpu.toFixed(0)} ms CPU`).join(' / ');
  assert.ok(spread(medians.map(([time]) => time)) < 1.6, shown);
  // A skipped dummy derivation drops the work by about 40% (a spread near 1.7); load alone stays well under 1.45.
  assert.ok(spread(medians.map(([, cpu]) => cpu)) < 1.45, shown);
});

test('signInWithPassword answers 503 when the verification bound is reached, never waiting past it', { skip }, async () => {
  const email = address('bound');
  await account_(email);
  const guess = (target: Ten98Auth) => target.signInWithPassword(db, { source: SOURCE, email, password: 'wrong password guess' }, allow).then(response => response.status);
  const single = authOver(db, { passwordVerification: { concurrency: 1, queue: 0 } });
  assert.deepEqual((await Promise.all([guess(single), guess(single)])).sort(), [401, 503]);
  const brief = authOver(db, { passwordVerification: { concurrency: 1, queue: 1, waitMs: 1 } });
  assert.deepEqual((await Promise.all([guess(brief), guess(brief), guess(brief)])).sort(), [401, 503, 503]);
  const busy = await single.signInWithPassword(db, { source: SOURCE, email, password: 'x' }, allow);
  assert.equal(busy.status, 401);
});

test('signInWithPassword replaces a legacy hash once, under the lock, however many sign-ins race', { skip }, async () => {
  const email = address('legacy');
  const id = await account_(email, { hash: hashes.legacy });
  const legacyAuth = authOver(db, { legacyPasswords: true });
  const outcomes = await Promise.all(Array.from({ length: 3 }, () => legacyAuth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow).then(response => response.status)));
  assert.deepEqual(outcomes, [200, 200, 200]);
  assert.equal((await pool!.query('SELECT 1 FROM password_writes WHERE user_id=$1', [id])).rowCount, 1);
  assert.equal((await storedPassword(id)).startsWith('scrypt$'), false);
  assert.equal(await sessions(id), 3);
  // Without the option a legacy hash never verifies, on either check.
  const strictEmail = address('strict');
  await account_(strictEmail, { hash: hashes.legacy });
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email: strictEmail, password: PASSWORD }, allow)).status, 401);
});

test('60 parallel wrong passwords at one account on a pool of 10: 50 × 401, 10 × 429, no connect timeout, the pool stays usable', { skip }, async () => {
  const email = address('flood');
  await account_(email);
  const flood = new pg.Pool({ connectionString: url, max: 10, connectionTimeoutMillis: 5000 });
  try {
    const floodDb = drizzle(flood, { schema });
    const floodAuth = authOver(floodDb);
    // Campaign's limiter shape: one conditional upsert per attempt, 50 per account.
    const limit = async ({ email: account }: { email: string }) => (await flood.query(
      'INSERT INTO login_limits VALUES ($1, 1) ON CONFLICT (key) DO UPDATE SET count = login_limits.count + 1 WHERE login_limits.count < 50', [`email:${account}`])).rowCount === 1;
    const attempts = Array.from({ length: 60 }, () => floodAuth.signInWithPassword(floodDb, { source: SOURCE, email, password: 'wrong password guess' }, accountStep(limit))
      .then(response => String(response.status), (error: Error) => `error: ${error.message}`));
    await delay(300);
    const started = performance.now();
    await flood.query('SELECT 1');
    const probe = performance.now() - started;
    const outcomes = await Promise.all(attempts);
    const tally = (value: string) => outcomes.filter(outcome => outcome === value).length;
    assert.deepEqual([tally('401'), tally('429'), outcomes.filter(outcome => outcome.startsWith('error')).length], [50, 10, 0], [...new Set(outcomes)].join(', '));
    // A stalled pool kept other requests waiting about 10 s; under a loaded test run a free one answers within 2.5 s.
    assert.ok(probe < 2500, `another request waited ${probe.toFixed(0)} ms for a connection`);
  } finally { await flood.end(); }
});

test('the published upgrade statements end plain sessions and better-auth verification rows, bind sessions to providers and store emails lower-case', { skip }, async () => {
  // A pre-0.29.0 schema: no session.oidcProvider, no user_email_lowercase, and no unique index on lower(email), so
  // case-variant twins can exist (as in an app that never had user_email_normalized_idx).
  await pool!.query(`CREATE SCHEMA pre; CREATE TABLE pre."user" (LIKE public."user" INCLUDING DEFAULTS);
    CREATE TABLE pre.session (LIKE public.session INCLUDING DEFAULTS); ALTER TABLE pre.session DROP COLUMN "oidcProvider";
    CREATE TABLE pre.verification (LIKE public.verification INCLUDING DEFAULTS);`);
  const pre = new pg.Pool({ connectionString: url, max: 1, options: '-c search_path=pre' });
  try {
    const users = [['a2', 'twin-a@example.com'], ['a1', 'Twin-A@example.com'], ['b1', 'twin-b@example.com'], ['b2', 'TWIN-B@example.com'], ['c1', 'Mixed@Example.COM'], ['d1', 'plain@example.com']];
    for (const [id, email] of users) await pre.query('INSERT INTO "user"(id,name,email) VALUES($1,$2,$3)', [id, 'Pre', email]);
    await pre.query('INSERT INTO session(id,"expiresAt",token,"userId") VALUES($1,now()+interval \'1 day\',$2,$3)', [randomUUID(), 'plainsessiontoken', 'd1']);
    const identifiers = ['reset-password:abc', 'trust-device-abc', '2fa-abc', '2fa-otp-abc', '2fa-attempts-2fa-abc', 'totp-used:user:digest', 'other-row'];
    for (const identifier of identifiers) await pre.query('INSERT INTO verification(id,identifier,value,"expiresAt") VALUES($1,$2,$3,now()+interval \'1 hour\')', [randomUUID(), identifier, 'd1']);
    const emails = async () => (await pre.query<{ id: string; email: string }>('SELECT id, email FROM "user" ORDER BY id')).rows.map(row => `${row.id}:${row.email}`);
    const before = await emails();
    // Twins stop the migration with their account ids, grouped per address and never the address itself; being one
    // implicit transaction, nothing before the pre-check persists either.
    await assert.rejects(pre.query(tokenStorageUpgradeStatements), (error: Error) => {
      assert.equal(error.message, 'user_email_lowercase: 2 email address(es) belong to more than one user when case is ignored (accounts: [a1, a2], [b1, b2]); resolve them before this migration');
      return true;
    });
    assert.deepEqual(await emails(), before);
    assert.equal((await pre.query('SELECT 1 FROM session')).rowCount, 1);
    // An operator resolves the twins; then the migration runs.
    await pre.query('DELETE FROM "user" WHERE id IN (\'a1\', \'b2\')');
    await pre.query(tokenStorageUpgradeStatements);
    assert.equal((await pre.query('SELECT 1 FROM session')).rowCount, 0);
    const left = (await pre.query<{ identifier: string }>('SELECT identifier FROM verification WHERE value=$1 ORDER BY identifier', ['d1'])).rows.map(row => row.identifier);
    assert.deepEqual(left, ['other-row', 'totp-used:user:digest']);
    assert.deepEqual(await emails(), ['a2:twin-a@example.com', 'b1:twin-b@example.com', 'c1:mixed@example.com', 'd1:plain@example.com']);
    await pre.query('INSERT INTO session(id,"expiresAt",token,"userId","oidcProvider") VALUES($1,now()+interval \'1 day\',$2,$3,$4)', [randomUUID(), 'bound', 'd1', 'idp']);
    await assert.rejects(pre.query('INSERT INTO "user"(id,name,email) VALUES($1,$2,$3)', ['e1', 'Pre', 'Later@example.com']),
      (error: { code?: string; constraint?: string }) => error.code === '23514' && error.constraint === 'user_email_lowercase');
    // The constraint was added NOT VALID and then validated; a second run passes and adds nothing.
    const constraints = async () => (await pre.query<{ convalidated: boolean }>(`SELECT convalidated FROM pg_constraint WHERE conname = 'user_email_lowercase' AND conrelid = '"user"'::regclass`)).rows;
    assert.deepEqual(await constraints(), [{ convalidated: true }]);
    await pre.query(tokenStorageUpgradeStatements);
    assert.deepEqual(await constraints(), [{ convalidated: true }]);
    assert.equal((await pre.query('SELECT 1 FROM information_schema.columns WHERE table_schema = \'pre\' AND table_name = \'session\' AND column_name = \'oidcProvider\'')).rowCount, 1);
  } finally { await pre.end(); }
  // The adoption guide publishes exactly these statements.
  assert.ok(readFileSync(new URL('../docs/FEATURE-ADOPTION.md', import.meta.url), 'utf8').includes(tokenStorageUpgradeStatements));
});

// Known devices: a browser's cookie jar, carried between attempts as a browser would.
const DEVICE = /(^|\.)known_device$/;
// The published key label and tag, computed here so a test can bind a device id to any account.
const deviceKey = () => Buffer.from(hkdfSync('sha256', SECRET, '', 'ten98-auth:known-device:v1', 32));
const tagFor = (userId: string, deviceId: string) => createHmac('sha256', deviceKey()).update(`${userId}\u0000${deviceId}`).digest('base64url');
const setCookieOf = (response: Response) => response.headers.getSetCookie().find(value => DEVICE.test(value.split('=')[0]!))!;
function jar(cookie = '') {
  const pairs = new Map(cookie.split('; ').filter(Boolean).map(pair => [pair.slice(0, pair.indexOf('=')), pair.slice(pair.indexOf('=') + 1)] as const));
  return {
    take(response: Response) {
      for (const value of response.headers.getSetCookie()) {
        const pair = value.split(';')[0]!, name = pair.slice(0, pair.indexOf('=')), content = pair.slice(pair.indexOf('=') + 1);
        if (content) pairs.set(name, content); else pairs.delete(name);
      }
      return this;
    },
    device: () => [...pairs].find(([name]) => DEVICE.test(name))?.[1],
    header: () => [...pairs].map(([name, value]) => `${name}=${value}`).join('; '),
    with: (value: string) => { pairs.set(deviceCookie, value); },
  };
}
const issued = (response: Response) => response.headers.getSetCookie().some(value => DEVICE.test(value.split('=')[0]!));
// The app's limiter while the account-wide bucket is full: only a known device passes (its other buckets are open).
const accountFull = (attempt: PasswordAttempt) => attempt.knownDevice;
const deviceRows = async (userId: string) => (await pool!.query<{ identifier: string }>("SELECT identifier FROM verification WHERE value=$1 AND identifier LIKE 'known-device%' ORDER BY identifier", [userId])).rows.map(row => row.identifier);
const attempts = async (userId: string) => (await deviceRows(userId)).filter(identifier => identifier.startsWith('known-device-attempt:')).length;
const knownAs = async (browser: ReturnType<typeof jar>, email: string, password = PASSWORD) => {
  let known: boolean | undefined;
  const response = await auth.signInWithPassword(db, { source: SOURCE, email, password, headers: { cookie: browser.header() } }, accountStep(attempt => { known = attempt.knownDevice; return true; }));
  return { known, status: response.status, response };
};

test('a known device signs in while the account-wide bucket is full; an unknown one, a forged one and another account\'s do not', { skip }, async () => {
  const email = address('device'), other = address('device');
  const id = await account_(email);
  const otherId = await account_(other);
  const browser = jar();
  const first = await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { cookie: browser.header() } }, allow);
  assert.equal(first.status, 200);
  assert.ok(issued(first));
  browser.take(first);
  const entry = browser.device()!;
  assert.match(entry, /^[A-Za-z0-9_-]{32}\.[A-Za-z0-9_-]{43}$/);
  // The row's identifier is hashed by the #131 rule, its value is the user id.
  assert.deepEqual(await deviceRows(id), [auth.storedVerificationIdentifier(`known-device:${entry.split('.')[0]}`)]);
  const cookie = setCookieOf(first);
  assert.match(cookie, /HttpOnly/i);
  assert.match(cookie, /SameSite=Lax/i);
  assert.match(cookie, /Max-Age=7776000/);
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { cookie: browser.header() } }, accountStep(accountFull))).status, 200);
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, accountStep(accountFull))).status, 429);
  // A forged tag, another account's entry, and a case variant of the right email (the same account) normalised alike.
  const forged = jar(); forged.with(`${'A'.repeat(32)}.${'B'.repeat(43)}`);
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { cookie: forged.header() } }, accountStep(accountFull))).status, 429);
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email: other, password: PASSWORD, headers: { cookie: browser.header() } }, accountStep(accountFull))).status, 429);
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email: ` ${email.toUpperCase()} `, password: PASSWORD, headers: { cookie: browser.header() } }, accountStep(accountFull))).status, 429, 'the entry rotated on the last success');
  // A correct tag for the other account on a live device id of this account: the tag verifies, but the row belongs to
  // this account, so the other account is not spared.
  const current = jar().take(await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow));
  const live = current.device()!.split('.')[0]!;
  // A live device id of this very account with a forged tag: only the tag check refuses it.
  const tampered = jar(); tampered.with(`${live}.${tagFor(otherId, live)}`);
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { cookie: tampered.header() } }, accountStep(accountFull))).status, 429);
  const relabelled = jar(); relabelled.with(`${live}.${tagFor(otherId, live)}`);
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email: other, password: PASSWORD, headers: { cookie: relabelled.header() } }, accountStep(accountFull))).status, 429);
  // The live entry, under a case variant of the email: the same account, so it is known.
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email: ` ${email.toUpperCase()} `, password: PASSWORD, headers: { cookie: current.header() } }, accountStep(accountFull))).status, 200);
});

test('a known device never authenticates: the password is always checked, and it shortens no other account\'s lockout', { skip }, async () => {
  const email = address('never'), other = address('never');
  const id = await account_(email);
  await account_(other);
  const browser = jar().take(await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow));
  const wrong = await auth.signInWithPassword(db, { source: SOURCE, email, password: 'wrong password guess', headers: { cookie: browser.header() } }, accountStep(accountFull));
  assert.equal(wrong.status, 401);
  assert.equal(issued(wrong), false);
  assert.equal(await sessions(id), 1);
  // The other account's lockout stands for this browser, with the right password for that account too.
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email: other, password: PASSWORD, headers: { cookie: browser.header() } }, accountStep(accountFull))).status, 429);
});

test('a known device is forgotten on a password change, a reset, revoke-all, revoke-other, sign-out everywhere and an expired row', { skip }, async () => {
  const resets: string[] = [];
  const resetting = authOver(db, { sendResetPassword: ({ token }) => { resets.push(token); } });
  // Signs in from the browser and follows its rotated entry, as a browser would; true when it counted as known.
  const known = async (email: string, browser: ReturnType<typeof jar>, password = PASSWORD) => {
    const outcome = await knownAs(browser, email, password);
    browser.take(outcome.response);
    return outcome.known;
  };
  const fresh = async () => {
    const email = address('forget');
    const id = await account_(email);
    const browser = jar().take(await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow));
    assert.equal(await known(email, browser), true);
    return { email, id, browser };
  };
  const post = (target: Ten98Auth, path: string, cookie: string, body: unknown) => target.handler(new Request(`${ORIGIN}/api/auth${path}`, { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN, cookie }, body: JSON.stringify(body) }));
  {
    const { email, browser } = await fresh();
    assert.equal((await post(auth, '/change-password', browser.header(), { currentPassword: PASSWORD, newPassword: NEW_PASSWORD })).status, 200);
    assert.equal(await known(email, browser, NEW_PASSWORD), false);
  }
  {
    const { email, browser } = await fresh();
    await resetting.withLockedAuthByEmail(db, email, bound => (bound.api as unknown as { requestPasswordReset(input: { body: { email: string; redirectTo: string } }): Promise<unknown> }).requestPasswordReset({ body: { email, redirectTo: '/' } }));
    assert.equal((await post(resetting, '/reset-password', '', { token: resets.at(-1), newPassword: NEW_PASSWORD })).status, 200);
    assert.equal(await known(email, browser, NEW_PASSWORD), false);
  }
  {
    const { email, id, browser } = await fresh();
    await auth.withLockedAuth(db, id, bound => bound.revokeAllSessions());
    assert.equal(await known(email, browser), false);
  }
  {
    const { email, browser } = await fresh();
    assert.equal((await post(auth, '/revoke-other-sessions', browser.header(), {})).status, 200);
    assert.equal(await known(email, browser), false);
  }
  {
    const { email, browser } = await fresh();
    assert.equal((await post(auth, '/revoke-sessions', browser.header(), {})).status, 200);
    assert.equal(await known(email, browser), false);
  }
  {
    const { email, id, browser } = await fresh();
    await pool!.query("UPDATE verification SET \"expiresAt\" = now() - interval '1 second' WHERE value=$1 AND identifier LIKE 'known-device:%'", [id]);
    assert.equal(await known(email, browser), false);
  }
  {
    // An OIDC-only account (no password): its revoke-all forgets the device its OIDC sign-in was issued.
    const email = address('oidc');
    const id = await account_(email, { hash: null });
    const browser = jar().take(await auth.api.completeOidcSession({ body: { oidcUserId: id, provider: 'idp' }, headers: {}, asResponse: true }));
    assert.equal((await deviceRows(id)).length, 1);
    await auth.withLockedAuth(db, id, bound => bound.revokeAllSessions());
    assert.deepEqual(await deviceRows(id), []);
    assert.ok(browser.device());
  }
});

test('a known device rotates on every success, and five failures end its trust until the next one', { skip }, async () => {
  const email = address('rotate');
  const id = await account_(email);
  const browser = jar().take(await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow));
  const before = browser.device()!;
  const old = jar(browser.header());
  const rotated = await knownAs(browser, email);
  assert.deepEqual([rotated.known, rotated.status], [true, 200]);
  browser.take(rotated.response);
  assert.notEqual(browser.device(), before);
  assert.equal((await knownAs(old, email)).known, false);
  for (let attempt = 0; attempt < 5; attempt++) assert.equal((await knownAs(browser, email, 'wrong password guess')).known, true, String(attempt));
  assert.equal(await attempts(id), 5);
  assert.equal((await knownAs(browser, email, 'wrong password guess')).known, false);
  // The next success (counted as an unknown device) rotates and resets the budget.
  const recovered = await knownAs(browser, email);
  assert.deepEqual([recovered.known, recovered.status], [false, 200]);
  browser.take(recovered.response);
  assert.equal(await attempts(id), 0);
  assert.equal((await knownAs(browser, email, 'wrong password guess')).known, true);
});

test('concurrent failures from one known device claim exactly its five attempts; a refused attempt gives its claim back', { skip }, async () => {
  const email = address('concurrent');
  const id = await account_(email);
  const browser = jar().take(await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow));
  // Refused by the limiter or the verification bound, the attempt never checked a password: its claim is returned.
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { cookie: browser.header() } }, accountStep(() => false))).status, 429);
  const full = authOver(db, { passwordVerification: { concurrency: 1, queue: 0, knownDevices: { concurrency: 1, queue: 0 } } });
  const holder = address('concurrent');
  await account_(holder);
  const holderCookie = jar().take(await full.signInWithPassword(db, { source: SOURCE, email: holder, password: PASSWORD }, allow)).header();
  // Another known device holds the only lane slot while it hashes; this known device's attempt finds none and gets 503.
  const busy = full.signInWithPassword(db, { source: SOURCE, email: holder, password: 'x', headers: { cookie: holderCookie } }, allow);
  await delay(80);
  assert.equal((await full.signInWithPassword(db, { source: SOURCE, email, password: 'x', headers: { cookie: browser.header() } }, allow)).status, 503);
  await busy;
  assert.equal(await attempts(id), 0);
  const outcomes = await Promise.all(Array.from({ length: 8 }, () => knownAs(browser, email, 'wrong password guess')));
  assert.deepEqual(outcomes.map(outcome => outcome.status), Array(8).fill(401));
  assert.equal(outcomes.filter(outcome => outcome.known).length, 5);
  assert.equal(await attempts(id), 5);
});

test('no cookie on a failure, a refusal or a pending second factor; malformed and oversized cookies are ignored; at most five entries', { skip }, async () => {
  const email = address('issue');
  await account_(email);
  for (const response of [
    await auth.signInWithPassword(db, { source: SOURCE, email, password: 'wrong password guess' }, allow),
    await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, accountStep(() => false)),
    await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { origin: 'https://evil.example' } }, allow),
  ]) assert.equal(issued(response), false);
  const factor = address('factor');
  await account_(factor, { twoFactor: true });
  const pending = await auth.signInWithPassword(db, { source: SOURCE, email: factor, password: PASSWORD }, allow);
  assert.equal((await pending.clone().json() as { twoFactorRedirect?: boolean }).twoFactorRedirect, true);
  assert.equal(issued(pending), false);
  // A live entry is ignored when the cookie around it is oversized; malformed values are ignored, never an error.
  const live = jar().take(await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow)).device()!;
  for (const value of [`${live}~${'x'.repeat(1100)}`, 'garbage', `${'A'.repeat(32)}.${'B'.repeat(42)}`, '~~~', `${'A'.repeat(31)}!.${'B'.repeat(43)}`]) {
    const browser = jar(); browser.with(value);
    const outcome = await knownAs(browser, email);
    assert.deepEqual([outcome.known, outcome.status], [false, 200], value.slice(0, 20));
  }
  // One browser, six accounts: an entry each, with distinct random device ids, and the oldest dropped past five.
  const browser = jar();
  const emails = await Promise.all(Array.from({ length: 6 }, async () => { const next = address('shared'); await account_(next); return next; }));
  for (const next of emails) browser.take(await auth.signInWithPassword(db, { source: SOURCE, email: next, password: PASSWORD, headers: { cookie: browser.header() } }, allow));
  const ids = browser.device()!.split('~').map(item => item.split('.')[0]);
  assert.equal(ids.length, 5);
  assert.equal(new Set(ids).size, 5);
  assert.equal((await knownAs(browser, emails[0]!)).known, false);
  assert.equal((await knownAs(browser, emails[5]!)).known, true);
});

test('an account whose email moved away before the lock was granted is not signed in, nor the account that took the email', { skip }, async () => {
  const email = address('moved');
  const first = await account_(email);
  const second = randomUUID();
  // Counts better-auth's own user lookups by email under the lock: with no account locked, its sign-in never runs.
  let lookups = 0;
  type Query = { model: string; where?: { field: string }[] };
  const counting = (client: unknown) => ((options: never) => {
    const real = (adapterOver(client) as unknown as (input: never) => Record<string, (query: Query) => Promise<unknown>>)(options);
    const count = (query: Query) => { if (query.model === 'user' && query.where?.some(item => item.field === 'email')) lookups++; return query; };
    return { ...real, findOne: (query: Query) => real.findOne!(count(query)), findMany: (query: Query) => real.findMany!(count(query)) };
  }) as unknown as ReturnType<typeof adapterOver>;
  const watched = createTen98Auth({ database: adapterOver(db), transactionDatabase: counting, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test' });
  const mover = await pool!.connect();
  try {
    // Uncommitted: the first account's email moves away and a second account takes it, with the same password.
    await mover.query('BEGIN');
    await mover.query('UPDATE "user" SET email = $1 WHERE id = $2', [address('elsewhere'), first]);
    await mover.query('INSERT INTO "user"(id,name,email) VALUES($1,$2,$3)', [second, 'Second', email]);
    await mover.query('INSERT INTO account(id,"accountId","providerId","userId",password) VALUES($1,$2,\'credential\',$2,$3)', [randomUUID(), second, hashes.old]);
    // The check before the lock reads the committed first account and passes; the locked lookup waits on its row and,
    // once the move commits, finds no account at that email.
    const attempt = watched.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow);
    assert.equal(await someoneWaits(), true);
    await mover.query('COMMIT');
    assert.deepEqual(await answer(await attempt), await answer(await signIn(address('nobody'))));
    assert.deepEqual([await sessions(first), await sessions(second)], [0, 0]);
    assert.equal(lookups, 0);
  } finally { mover.release(); }
  // Negative control: with nothing in flight the second account signs in.
  assert.equal((await signIn(email)).status, 200);
});

test('a session better-auth creates for any other account than the locked one is rolled back and refused', { skip }, async () => {
  const email = address('locked'), other = address('decoy');
  const id = await account_(email);
  const decoy = await account_(other);
  // An app adapter whose user lookup by email resolves to another account (a mapping fault, say).
  type Query = { model: string; where?: { field: string; value: unknown }[] };
  const redirecting = (client: unknown) => ((options: never) => {
    const real = (adapterOver(client) as unknown as (input: never) => Record<string, (query: Query) => Promise<unknown>>)(options);
    const redirect = (query: Query): Query => query.model === 'user' && query.where?.some(item => item.field === 'email') ? { ...query, where: [{ field: 'id', value: decoy }] } : query;
    return { ...real, findOne: (query: Query) => real.findOne!(redirect(query)), findMany: (query: Query) => real.findMany!(redirect(query)) };
  }) as unknown as ReturnType<typeof adapterOver>;
  const faulty = createTen98Auth({ database: adapterOver(db), transactionDatabase: redirecting, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test' });
  const unknown = await answer(await signIn(address('nobody')));
  assert.deepEqual(await answer(await faulty.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow)), unknown);
  assert.deepEqual([await sessions(id), await sessions(decoy)], [0, 0]);
  // Negative control: the same app with a faithful adapter signs the locked account in.
  assert.equal((await signIn(email)).status, 200);
});

test('locked auth refuses to run without the unique index on lower(email), and refuses two matching accounts', { skip }, async () => {
  assert.equal(await auth.assertEmailIndex(db), undefined);
  // A schema without the index, holding case-variant twins.
  // Every other table and index the schema check asks for is there, so only the email index is missing.
  await pool!.query(`CREATE SCHEMA bare; CREATE TABLE bare."user" (LIKE public."user" INCLUDING DEFAULTS); CREATE TABLE bare.account (LIKE public.account INCLUDING DEFAULTS);
    ALTER TABLE bare.account ADD UNIQUE ("providerId", "accountId");
    CREATE TABLE bare.session (LIKE public.session INCLUDING ALL); CREATE TABLE bare.verification (LIKE public.verification INCLUDING ALL);
    CREATE SCHEMA dropped; CREATE TABLE dropped."user" (LIKE public."user" INCLUDING ALL); CREATE TABLE dropped.account (LIKE public.account INCLUDING ALL);
    ALTER TABLE dropped."user" DROP CONSTRAINT user_email_lowercase;
    CREATE TABLE dropped.session (LIKE public.session INCLUDING ALL); CREATE TABLE dropped.verification (LIKE public.verification INCLUDING ALL);`);
  const twins = async (schemaName: string) => {
    const base = `twin-${randomUUID()}@example.com`;
    for (const variant of [base, base.replace('twin', 'Twin')]) {
      const twin = randomUUID();
      await pool!.query(`INSERT INTO ${schemaName}."user"(id,name,email) VALUES($1,'Twin',$2)`, [twin, variant]);
      await pool!.query(`INSERT INTO ${schemaName}.account(id,"accountId","providerId","userId",password,"createdAt","updatedAt") VALUES($1,$2,'credential',$2,$3,now(),now())`, [randomUUID(), twin, hashes.old]);
    }
    return base;
  };
  const pools = ['bare', 'dropped'].map(name => new pg.Pool({ connectionString: url, max: 2, options: `-c search_path=${name}` }));
  try {
    const [bareDb, droppedDb] = pools.map(item => drizzle(item, { schema }));
    const bareAuth = authOver(bareDb!), droppedAuth = authOver(droppedDb!);
    const bareTwin = await twins('bare');
    await assert.rejects(bareAuth.assertEmailIndex(bareDb!), MissingEmailIndexError);
    await assert.rejects(bareAuth.signInWithPassword(bareDb!, { source: SOURCE, email: bareTwin, password: PASSWORD }, allow), MissingEmailIndexError);
    await assert.rejects(bareAuth.withLockedAuthByEmail(bareDb!, bareTwin, async () => 1), MissingEmailIndexError);
    // The index was there at start-up and dropped later: the locked lookup finds two accounts and refuses both.
    assert.equal(await droppedAuth.withLockedAuthByEmail(droppedDb!, address('none'), async (_bound, _tx, userId) => userId), undefined);
    const { rows } = await pool!.query<{ name: string }>("SELECT indexname AS name FROM pg_indexes WHERE schemaname = 'dropped' AND tablename = 'user' AND indexdef LIKE '%lower(email)%'");
    await pool!.query(`DROP INDEX dropped."${rows[0]!.name}"`);
    const droppedTwin = await twins('dropped');
    await assert.rejects(droppedAuth.withLockedAuthByEmail(droppedDb!, droppedTwin, async () => 1), AmbiguousAccountError);
    assert.deepEqual(await answer(await droppedAuth.signInWithPassword(droppedDb!, { source: SOURCE, email: droppedTwin, password: PASSWORD }, allow)), await answer(await signIn(address('nobody'))));
  } finally { await Promise.all(pools.map(item => item.end())); }
});

test('a rolled-back locked transaction is never reported as success; a failed legacy upgrade leaves the sign-in standing', { skip }, async () => {
  const id = await account_(address('rollback'));
  // The callback swallows a failed statement: PostgreSQL answers COMMIT with ROLLBACK, and that is an error.
  await assert.rejects(auth.withLockedAuth(db, id, async (_bound, tx) => { await tx.execute(sql`SELECT 1/0`).catch(() => undefined); return 'reported'; }), TransactionRolledBackError);
  assert.equal(await auth.withLockedAuth(db, id, async () => 'committed'), 'committed');
  const email = address('legacy-fail');
  const legacyId = await account_(email, { hash: hashes.legacy });
  await pool!.query(`CREATE FUNCTION refuse_password() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'refused'; END $$;
    CREATE TRIGGER refuse_password BEFORE UPDATE OF password ON account FOR EACH ROW WHEN (NEW."userId" = '${legacyId}') EXECUTE FUNCTION refuse_password();`);
  try {
    const legacyAuth = authOver(db, { legacyPasswords: true });
    const response = await legacyAuth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow);
    assert.equal(response.status, 200);
    assert.ok(await legacyAuth.api.getSession({ headers: { cookie: cookieOf(response) } }));
    assert.equal(await sessions(legacyId), 1);
    assert.equal(await storedPassword(legacyId), hashes.legacy);
  } finally { await pool!.query('DROP TRIGGER refuse_password ON account; DROP FUNCTION refuse_password();'); }
});

test('a closed account, or one the app\'s isAccountUsable refuses, gets the uniform 401 and no session', { skip }, async () => {
  const unknown = await answer(await signIn(address('nobody')));
  const email = address('closed');
  const id = await account_(email);
  await pool!.query('UPDATE "user" SET closed_at = now() WHERE id = $1', [id]);
  assert.deepEqual(await answer(await signIn(email)), unknown);
  assert.equal(await sessions(id), 0);
  const refusedEmail = address('refused');
  const refusedId = await account_(refusedEmail);
  const picky = authOver(db, { isAccountUsable: account => account.id !== refusedId });
  assert.deepEqual(await answer(await picky.signInWithPassword(db, { source: SOURCE, email: refusedEmail, password: PASSWORD }, allow)), unknown);
  assert.equal(await sessions(refusedId), 0);
  // Negative control: the hook decides, so allowing every account lets the closed one in.
  const lenient = authOver(db, { isAccountUsable: () => true });
  assert.equal((await lenient.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow)).status, 200);
});

test('a flood of distinct emails from one source is cut by its per-source limit before the queue, so a real user still signs in', { skip }, async () => {
  const email = address('real');
  await account_(email);
  const counts = new Map<string, number>();
  const perSource = ({ source }: { source: string }) => { const seen = (counts.get(source) ?? 0) + 1; counts.set(source, seen); return seen <= 10; };
  const flood = Array.from({ length: 60 }, (_, at) => auth.signInWithPassword(db, { source: 'ip:flood', email: address(`flood${at}`), password: 'wrong password guess' }, { source: perSource, account: () => true }).then(response => response.status));
  await delay(50);
  const started = performance.now();
  const real = await auth.signInWithPassword(db, { source: 'ip:real', email, password: PASSWORD }, { source: perSource, account: () => true });
  const waited = performance.now() - started;
  assert.equal(real.status, 200);
  assert.ok(waited < 5000, `the real user waited ${waited.toFixed(0)} ms`);
  const statuses = await Promise.all(flood);
  assert.deepEqual([statuses.filter(status => status === 401).length, statuses.filter(status => status === 429).length], [10, 50]);
  // Without a source the call is refused outright.
  await assert.rejects(auth.signInWithPassword(db, { email, password: PASSWORD } as never, allow), /source/);
});

test('the instance an app holds refuses password sign-in on its route and api; the bound one refuses it too', { skip }, async () => {
  const email = address('route');
  const id = await account_(email);
  for (const path of ['/sign-in/email', '/sign-in/email/', '/Sign-In/EMAIL']) {
    const response = await auth.handler(new Request(`${ORIGIN}/api/auth${path}`, { method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify({ email, password: PASSWORD }) }));
    assert.equal(response.status, 404, path);
  }
  assert.throws(() => auth.api.signInEmail({ body: { email, password: PASSWORD }, asResponse: true }), /signInWithPassword/);
  await auth.withLockedAuth(db, id, async bound => {
    assert.throws(() => bound.api.signInEmail({ body: { email, password: PASSWORD }, asResponse: true }), /signInWithPassword/);
    assert.throws(() => bound.handler(new Request(`${ORIGIN}/api/auth/sign-in/email/`, { method: 'POST' })), /signInWithPassword/);
    assert.throws(() => (bound as unknown as { fetch(request: Request): unknown }).fetch(new Request(`${ORIGIN}/api/auth/sign-in/email`, { method: 'POST' })), /signInWithPassword/);
  });
  assert.equal(await sessions(id), 0);
});

// RFC 6238 TOTP from an otpauth URI, as an authenticator app computes it.
function totp(uri: string, offset = 0): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of new URL(uri).searchParams.get('secret')!.replace(/=+$/, '')) bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g)!.map(byte => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000) + offset));
  const digest = createHmac('sha1', key).update(counter).digest();
  const at = digest[digest.length - 1]! & 15;
  return String((digest.readUInt32BE(at) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}
const post = (path: string, cookie: string, body: unknown) => new Request(`${ORIGIN}/api/auth${path}`, {
  method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN, ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body),
});
// An account with TOTP enrolled through the preset (enabling needs a session, not a challenge), and its pending challenge.
async function challenged(label: string) {
  const email = address(label);
  const id = await account_(email);
  const session = cookieOf(await signIn(email));
  const { totpURI } = await (await auth.handler(post('/two-factor/enable', session, { password: PASSWORD }))).json() as { totpURI: string };
  assert.equal((await auth.handler(post('/two-factor/verify-totp', session, { code: totp(totpURI) }))).status, 200);
  const challenge = await signIn(email);
  assert.equal((await challenge.clone().json() as { twoFactorRedirect?: boolean }).twoFactorRedirect, true);
  return { email, id, uri: totpURI, challenge: cookieOf(challenge) };
}

test('an account closed after its two-factor challenge does not complete the sign-in, nor get a known device', { skip }, async () => {
  const open = await challenged('factor-open');
  const before = await sessions(open.id);
  const completed = await auth.verifyTwoFactor(db, post('/two-factor/verify-totp', open.challenge, { code: totp(open.uri, 1) }));
  assert.equal(completed.status, 200);
  assert.equal(await sessions(open.id), before + 1);
  assert.ok(issued(completed));
  const closed = await challenged('factor-closed');
  const sessionsBefore = await sessions(closed.id);
  // The sign-in that enrolled the factor (before two-factor was on) issued one; the refused completion adds none.
  const devicesBefore = (await deviceRows(closed.id)).filter(identifier => identifier.startsWith('known-device:')).length;
  await pool!.query('UPDATE "user" SET closed_at = now() WHERE id = $1', [closed.id]);
  const refused = await auth.verifyTwoFactor(db, post('/two-factor/verify-totp', closed.challenge, { code: totp(closed.uri, 1) }));
  // The same answer as a wrong code, no session and no known-device entry.
  const again = cookieOf(await signIn(open.email));
  const wrongCode = await auth.verifyTwoFactor(db, post('/two-factor/verify-totp', again, { code: '000000' }));
  assert.deepEqual(await answer(refused), await answer(wrongCode));
  assert.equal(refused.status, 401);
  assert.equal(issued(refused), false);
  assert.equal(await sessions(closed.id), sessionsBefore);
  assert.equal((await deviceRows(closed.id)).filter(identifier => identifier.startsWith('known-device:')).length, devicesBefore);
});

test('the instance an app holds refuses a sign-in challenge outside verifyTwoFactor; the bound one too', { skip }, async () => {
  const pending = await challenged('factor-raw');
  for (const path of ['/two-factor/verify-totp', '/two-factor/verify-totp/', '/Two-Factor/Verify-Backup-Code']) {
    assert.equal((await auth.handler(post(path, pending.challenge, { code: totp(pending.uri, 1) }))).status, 404, path);
  }
  const api = auth.api as unknown as { verifyTOTP(input: { body: { code: string }; headers: HeadersInit }): unknown };
  assert.throws(() => api.verifyTOTP({ body: { code: totp(pending.uri, 1) }, headers: { cookie: pending.challenge } }), /verifyTwoFactor/);
  await auth.withLockedAuth(db, pending.id, async bound => {
    assert.throws(() => bound.handler(post('/two-factor/verify-totp', pending.challenge, { code: totp(pending.uri, 1) })), /verifyTwoFactor/);
  });
  // The challenge is still usable through verifyTwoFactor.
  assert.equal((await auth.verifyTwoFactor(db, post('/two-factor/verify-totp', pending.challenge, { code: totp(pending.uri, 1) }))).status, 200);
});

test('assertSchema fails at start-up on campaign-style table names, naming the expected and the missing ones', { skip }, async () => {
  assert.equal(await auth.assertSchema(db), undefined);
  await pool!.query(`CREATE SCHEMA campaign;
    CREATE TABLE campaign.users (id text PRIMARY KEY, email text NOT NULL, closed_at timestamptz);
    CREATE TABLE campaign.accounts (id text PRIMARY KEY, user_id text, provider_id text, password text, updated_at bigint);
    CREATE TABLE campaign.sessions (id text PRIMARY KEY, token text, user_id text, expires_at bigint);
    CREATE TABLE campaign.verifications (id text PRIMARY KEY, identifier text, value text, expires_at bigint);
    CREATE SCHEMA partial; CREATE TABLE partial."user" (LIKE public."user" INCLUDING ALL); ALTER TABLE partial."user" DROP COLUMN closed_at;
    CREATE TABLE partial.account (LIKE public.account INCLUDING ALL); CREATE TABLE partial.session (LIKE public.session INCLUDING ALL);
    ALTER TABLE partial.session DROP COLUMN "oidcProvider"; CREATE TABLE partial.verification (LIKE public.verification INCLUDING ALL);
    CREATE SCHEMA nounique; CREATE TABLE nounique."user" (LIKE public."user" INCLUDING ALL); CREATE TABLE nounique.account (LIKE public.account INCLUDING DEFAULTS);
    CREATE TABLE nounique.session (LIKE public.session INCLUDING ALL); CREATE TABLE nounique.verification (LIKE public.verification INCLUDING ALL);`);
  const pools = ['campaign', 'partial', 'nounique'].map(name => new pg.Pool({ connectionString: url, max: 2, options: `-c search_path=${name}` }));
  try {
    const [campaignDb, partialDb, nouniqueDb] = pools.map(item => drizzle(item, { schema }));
    const campaignAuth = authOver(campaignDb!);
    const mismatch = (pattern: RegExp) => (error: unknown) => error instanceof SchemaMismatchError && error.code === 'AUTH_SCHEMA_MISMATCH' && pattern.test(error.message);
    const names = /Locked auth needs the tables "user" \(id, email, closed_at\), account \(userId, providerId, password, updatedAt\), session \(id, token, userId, expiresAt, oidcProvider\), verification \(id, identifier, value, expiresAt\)\. Missing: table "user"; table account; table session; table verification\./;
    await assert.rejects(campaignAuth.assertSchema(campaignDb!), mismatch(names));
    // Not a refused sign-in at first use: the same loud error.
    await assert.rejects(campaignAuth.signInWithPassword(campaignDb!, { source: SOURCE, email: address('campaign'), password: PASSWORD }, allow), mismatch(names));
    await assert.rejects(campaignAuth.withLockedAuth(campaignDb!, randomUUID(), async () => 1), mismatch(names));
    await assert.rejects(authOver(partialDb!).assertSchema(partialDb!), mismatch(/Missing: "user"\.closed_at; session\.oidcProvider\./));
    // Every column is there, but nothing makes (providerId, accountId) unique: linked identities could repeat.
    await assert.rejects(authOver(nouniqueDb!).assertSchema(nouniqueDb!), mismatch(/Missing: account unique \("providerId", "accountId"\)\./));
  } finally { await Promise.all(pools.map(item => item.end())); }
});

test('an account keeps at most five known devices: a sixth browser evicts the oldest', { skip }, async () => {
  const email = address('browsers');
  const id = await account_(email);
  const browsers: ReturnType<typeof jar>[] = [];
  for (let at = 0; at < 6; at++) browsers.push(jar().take(await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow)));
  assert.equal((await deviceRows(id)).filter(identifier => identifier.startsWith('known-device:')).length, 5);
  assert.equal((await knownAs(browsers[0]!, email)).known, false);
  assert.equal((await knownAs(browsers[5]!, email)).known, true);
});

// Linked OIDC identities (#143): account rows keyed by 'oidc:' + the normalised issuer and the subject, with no tokens.
const ISSUER = 'https://idp.example.com/realms/acme';
const trusted = { trustVerifiedEmail: true };
const subject = () => `sub-${randomUUID()}`;
const claimsFor = (email: string, sub = subject(), extra: Record<string, unknown> = {}) => ({ iss: ISSUER, sub, email, email_verified: true, name: 'Provider User', ...extra });
const refusedWith = (code: string, status?: number) => (error: unknown) => error instanceof OidcIdentityError && error.code === code && (status === undefined || error.status === status);
const identitiesOf = async (userId: string) => (await pool!.query<{ providerId: string; accountId: string }>(
  'SELECT "providerId","accountId" FROM account WHERE "userId"=$1 AND "providerId" LIKE \'oidc:%\' ORDER BY "providerId","accountId"', [userId])).rows;
const usersAt = async (email: string) => (await pool!.query('SELECT 1 FROM "user" WHERE lower(email)=lower($1)', [email])).rowCount;
/** The raw challenge identifier a two_factor cookie carries (signed by better-call). */
const challengeOf = (cookie: string) => {
  const pair = cookie.split('; ').find(item => item.split('=')[0]!.endsWith('.two_factor'))!;
  const value = decodeURIComponent(pair.slice(pair.indexOf('=') + 1));
  return value.slice(0, value.lastIndexOf('.'));
};
/** True once at least `count` backends of this database wait on a lock, so a forced interleaving is in place. */
async function waitersAtLeast(count: number) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const { rows } = await pool!.query<{ n: number }>("SELECT count(*)::int AS n FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'");
    if (rows[0]!.n >= count) return true;
    await delay(25);
  }
  return false;
}
/**
 * A trigger that pauses matching inserts into `table` on advisory lock `key` until the test's own connection, which
 * holds it, commits: the way these tests force one side of a race to stop between two of its statements.
 */
async function pauseInserts(table: 'session' | 'verification', key: number, when: string) {
  const name = `pause_${table}_${key}`;
  await pool!.query(`CREATE FUNCTION ${name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(${key}); RETURN NEW; END $$;
    CREATE TRIGGER ${name} BEFORE INSERT ON ${table} FOR EACH ROW WHEN (${when}) EXECUTE FUNCTION ${name}();`);
  const holder = await pool!.connect();
  await holder.query('BEGIN');
  await holder.query('SELECT pg_advisory_xact_lock($1)', [key]);
  return {
    holder,
    async release() { await holder.query('COMMIT'); },
    async drop() { holder.release(); await pool!.query(`DROP TRIGGER ${name} ON ${table}; DROP FUNCTION ${name}();`); },
  };
}
const providerSignIn = (userId: string, provider: string, target: Ten98Auth = auth) => target.api.completeOidcSession({ body: { oidcUserId: userId, provider }, headers: {}, asResponse: true });
const boundSessions = async (provider: string) => (await pool!.query('SELECT 1 FROM session WHERE "oidcProvider"=$1', [provider])).rowCount;
const issuerCases: [string, string][] = [
  ['https://IdP.Example.COM/', 'https://idp.example.com'],
  ['HTTPS://idp.example.com:443/realms/Acme/', 'https://idp.example.com/realms/Acme'],
  ['http://LOCALHOST:80/', 'http://localhost'],
  ['http://localhost:8080/', 'http://localhost:8080'],
  ['https://idp.example.com:80/', 'https://idp.example.com:80'],
  ['https://idp.example.com:4430', 'https://idp.example.com:4430'],
  ['https://idp.example.com:/', 'https://idp.example.com'],
  ['https://[::1]:/realms/', 'https://[::1]/realms'],
  ['https://login.example.com/Tenant-ID/v2.0', 'https://login.example.com/Tenant-ID/v2.0'],
  ['https://idp.example.com/a%2Fb/?Tenant=X#Frag', 'https://idp.example.com/a%2Fb?Tenant=X#Frag'],
  ['https://Admin@IdP.example.com/', 'https://Admin@idp.example.com'],
  ['https://[2001:DB8::1]:443/', 'https://[2001:db8::1]'],
  ['https://İDP.example.com/', 'https://İdp.example.com'],
  ['custom+Scheme://Host/', 'custom+scheme://host'],
  ['https://idp.example.com', 'https://idp.example.com'],
];
// Malformed authorities (a second port, a non-numeric port, a bare bracket) and a path ending in '//' are refused, so a
// normalised issuer normalises to itself.
const badIssuers = ['idp.example.com', '', 'https://', 'https:///realms', 'https://:443/', ' https://idp.example.com', 'https://h:443:443/', 'https://h:x/',
  'https://h]/', 'https://[::1/', 'https://idp.example.com//', 'https://h/a//?q'];
const tryNormalise = (raw: string) => { try { return normaliseOidcIssuer(raw); } catch { return null; } };
// Seeded, so a failure reproduces: issuers built from the characters the rule treats specially.
function generatedIssuers(count: number): string[] {
  let seed = 143;
  const next = (n: number) => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed % n; };
  const schemes = ['https://', 'HTTP://', 'https://', 'x+y://', 'https:/', ''];
  const parts = ['Idp', 'h', '.example', ':', ':443', ':80', ':', '[', ']', '[::1]', '@', 'U@', '/', '//', '/', '?', '#', 'q=A', '%2F', 'İ', ' ', '\n', '0'];
  return Array.from({ length: count }, () => schemes[next(schemes.length)]! + Array.from({ length: 1 + next(7) }, () => parts[next(parts.length)]!).join(''));
}

test('normaliseOidcIssuer lowercases the scheme and host, drops an empty or default port and one trailing slash, keeps the rest, and is idempotent', () => {
  for (const [raw, expected] of issuerCases) {
    assert.equal(normaliseOidcIssuer(raw), expected, raw);
    assert.equal(oidcProviderId(raw), `oidc:${expected}`, raw);
  }
  for (const raw of [...badIssuers, 42, undefined]) assert.throws(() => normaliseOidcIssuer(raw as string), TypeError, String(raw));
  // Normalising twice equals normalising once.
  for (const raw of [...issuerCases.map(([value]) => value), ...generatedIssuers(5000)]) {
    const once = tryNormalise(raw);
    if (once !== null) assert.equal(normaliseOidcIssuer(once), once, JSON.stringify(raw));
  }
});

test('normaliseOidcIssuerSql gives the function\'s result for every case and 5000 generated issuers, and NULL where it throws', { skip }, async () => {
  const client = await pool!.connect();
  try {
    await client.query(normaliseOidcIssuerSql);
    const inputs = [...issuerCases.map(([value]) => value), ...badIssuers, ...generatedIssuers(5000)];
    const { rows } = await client.query<{ raw: string; normalised: string | null }>('SELECT raw, pg_temp.ten98_normalise_oidc_issuer(raw) AS normalised FROM unnest($1::text[]) AS raw', [inputs]);
    assert.equal(rows.length, inputs.length);
    for (const { raw, normalised } of rows) assert.equal(normalised, tryNormalise(raw), JSON.stringify(raw));
  } finally { client.release(); }
});

test('a first provider sign-in creates the account with its verified email, and no path stores a provider token', { skip }, async () => {
  const email = address('first');
  const sub = subject();
  const tokens = { id_token: 'header.payload.signature', access_token: 'access-token', refresh_token: 'refresh-token' };
  const first = await signInOidcUser(db, claimsFor(` ${email.toUpperCase()} `, sub, tokens), trusted);
  assert.equal(first.created, true);
  assert.deepEqual((await pool!.query('SELECT email, "emailVerified", name FROM "user" WHERE id=$1', [first.userId])).rows, [{ email, emailVerified: true, name: 'Provider User' }]);
  // Any spelling of the issuer that normalises alike finds the same identity, with no email needed.
  assert.deepEqual(await signInOidcUser(db, { iss: 'HTTPS://IDP.example.com:443/realms/acme/', sub }, {}), { userId: first.userId, created: false });
  assert.deepEqual(await identitiesOf(first.userId), [{ providerId: `oidc:${ISSUER}`, accountId: sub }]);
  // An identity linked explicitly, and one linked by accepting an invitation.
  const linked = await account_(address('linked'));
  await auth.withLockedAuth(db, linked, (_bound, tx) => linkOidcIdentity(tx, { issuer: ISSUER, subject: subject() }));
  const owner = await account_(address('owner'));
  const invited = address('invited');
  const { token } = await inTransaction(async client => team.inviteMember(client, await workspaceOf(owner), owner, { email: invited, role: 'viewer' }));
  await inTransaction(client => team.acceptVerifiedOidcInvitation(client, token, { email: invited, name: 'Invited', issuer: ISSUER, subject: subject() }));
  // Not one account row holds a provider token or, for an identity, a password.
  const stored = (await pool!.query<{ n: number }>(`SELECT count(*)::int AS n FROM account WHERE "accessToken" IS NOT NULL OR "refreshToken" IS NOT NULL OR "idToken" IS NOT NULL
    OR "accessTokenExpiresAt" IS NOT NULL OR "refreshTokenExpiresAt" IS NOT NULL OR scope IS NOT NULL OR ("providerId" LIKE 'oidc:%' AND password IS NOT NULL)`)).rows[0]!.n;
  assert.equal(stored, 0);
  assert.equal((await pool!.query('SELECT 1 FROM account WHERE "providerId" LIKE \'oidc:%\'')).rowCount! >= 3, true);
});

test('a provider sign-in never links to an existing account, even with a verified email from a trusted provider', { skip }, async () => {
  const email = address('exists');
  const id = await account_(email);
  await assert.rejects(signInOidcUser(db, claimsFor(email.toUpperCase()), trusted), refusedWith('OIDC_ACCOUNT_EXISTS', 409));
  assert.deepEqual(await identitiesOf(id), []);
  assert.equal(await usersAt(email), 1);
  // Not inside a locked-auth transaction either: account creation takes the email lock, which comes before the user row.
  await assert.rejects(auth.withLockedAuth(db, id, (_bound, tx) => signInOidcUser(tx, claimsFor(address('inside')), trusted)), refused);
});

test('without trustVerifiedEmail: true a verified email creates no account, and an unverified one never does', { skip }, async () => {
  const email = address('untrusted');
  for (const provider of [{}, { trustVerifiedEmail: false }, { trustVerifiedEmail: 'true' as unknown as boolean }, undefined as unknown as {}]) {
    await assert.rejects(signInOidcUser(db, claimsFor(email), provider), refusedWith('OIDC_EMAIL_UNVERIFIED', 403));
  }
  for (const claims of [claimsFor(email, subject(), { email_verified: 'true' }), claimsFor(email, subject(), { email_verified: false }), { iss: ISSUER, sub: subject(), email_verified: true }]) {
    await assert.rejects(signInOidcUser(db, claims, trusted), refusedWith('OIDC_EMAIL_UNVERIFIED', 403));
  }
  assert.equal(await usersAt(email), 0);
  // The unverified refusal comes first, so an untrusted provider cannot learn which emails have accounts.
  const existing = address('probe');
  await account_(existing);
  await assert.rejects(signInOidcUser(db, claimsFor(existing), {}), refusedWith('OIDC_EMAIL_UNVERIFIED'));
  assert.equal((await signInOidcUser(db, claimsFor(email), trusted)).created, true);
});

test('an invitation is accepted through a provider only by its own email, and then links the identity', { skip }, async () => {
  const owner = await account_(address('inviter'));
  const workspace = await workspaceOf(owner);
  const invited = address('invitee');
  const { token } = await inTransaction(client => team.inviteMember(client, workspace, owner, { email: invited, role: 'viewer' }));
  const sub = subject();
  await assert.rejects(inTransaction(client => team.acceptVerifiedOidcInvitation(client, token, { email: address('someone-else'), name: 'Other', issuer: ISSUER, subject: sub })),
    (error: { code?: string; status?: number }) => error.code === 'OIDC_INVITE_EMAIL_MISMATCH' && error.status === 403);
  assert.equal((await pool!.query('SELECT 1 FROM account WHERE "accountId"=$1', [sub])).rowCount, 0);
  const accepted = await inTransaction(client => team.acceptVerifiedOidcInvitation(client, token, { email: invited, name: 'Invitee', issuer: `${ISSUER}/`, subject: sub }));
  assert.deepEqual(await signInOidcUser(db, { iss: ISSUER, sub }, {}), { userId: accepted.userId, created: false });
});

test('a signed-in user links an identity only inside withLockedAuth, and cannot unlink the last way to sign in', { skip }, async () => {
  const id = await account_(address('link'), { hash: null });
  const identity = { issuer: ISSUER, subject: subject() }, second = { issuer: 'https://other.example.com', subject: subject() };
  await assert.rejects(linkOidcIdentity(db, identity), TypeError);
  await assert.rejects(transaction(db, tx => linkOidcIdentity(tx, identity)), TypeError);
  await assert.rejects(auth.withLockedAuthByEmail(db, address('nobody'), (_bound, tx) => linkOidcIdentity(tx, identity)), TypeError);
  // A transaction by email locks the account behind an email being signed in to, not a signed-in user.
  const byEmailAccount = address('by-email');
  await account_(byEmailAccount);
  await assert.rejects(auth.withLockedAuthByEmail(db, byEmailAccount, (_bound, tx) => linkOidcIdentity(tx, identity)), TypeError);
  assert.deepEqual(await identitiesOf(id), []);
  assert.deepEqual(await auth.withLockedAuth(db, id, (_bound, tx) => linkOidcIdentity(tx, identity)), { linked: true });
  assert.deepEqual(await auth.withLockedAuth(db, id, (_bound, tx) => linkOidcIdentity(tx, identity)), { linked: false });
  assert.deepEqual(await signInOidcUser(db, { iss: identity.issuer, sub: identity.subject }, {}), { userId: id, created: false });
  // Its credential row has no password, so this identity is the only way to sign in.
  const unlink = (target: typeof identity) => auth.withLockedAuth(db, id, (_bound, tx) => unlinkOidcIdentity(tx, target));
  await assert.rejects(unlink(identity), refusedWith('OIDC_LAST_SIGN_IN_METHOD', 409));
  await assert.rejects(unlinkOidcIdentity(db, identity), TypeError);
  await assert.rejects(unlink({ issuer: ISSUER, subject: subject() }), refusedWith('OIDC_IDENTITY_NOT_FOUND', 404));
  assert.equal((await identitiesOf(id)).length, 1);
  // Another identity, or a password, is another way in.
  await auth.withLockedAuth(db, id, (_bound, tx) => linkOidcIdentity(tx, second));
  await unlink(identity);
  await assert.rejects(unlink(second), refusedWith('OIDC_LAST_SIGN_IN_METHOD'));
  await pool!.query('UPDATE account SET password=$1 WHERE "userId"=$2 AND "providerId"=\'credential\'', [hashes.old, id]);
  await unlink(second);
  assert.deepEqual(await identitiesOf(id), []);
});

test('an identity is unique per (issuer, subject): one account holds it, whatever the issuer\'s spelling', { skip }, async () => {
  const first = await account_(address('unique-a')), other = await account_(address('unique-b'));
  const sub = subject();
  await auth.withLockedAuth(db, first, (_bound, tx) => linkOidcIdentity(tx, { issuer: 'https://IdP.Example.com:443/realms/acme/', subject: sub }));
  await assert.rejects(auth.withLockedAuth(db, other, (_bound, tx) => linkOidcIdentity(tx, { issuer: ISSUER, subject: sub })), refusedWith('OIDC_IDENTITY_IN_USE', 409));
  assert.deepEqual(await identitiesOf(other), []);
  assert.deepEqual(await signInOidcUser(db, { iss: ISSUER, sub }, {}), { userId: first, created: false });
  // The same subject at another issuer is another identity; the constraint itself refuses a second row.
  assert.deepEqual(await auth.withLockedAuth(db, other, (_bound, tx) => linkOidcIdentity(tx, { issuer: 'https://idp.example.org/realms/acme', subject: sub })), { linked: true });
  await assert.rejects(pool!.query('INSERT INTO account(id,"accountId","providerId","userId") VALUES($1,$2,$3,$4)', [randomUUID(), sub, oidcProviderId(ISSUER), other]),
    (error: { code?: string }) => error.code === '23505');
});

test('revokeProviderSessions ends that provider\'s sessions and pending challenges only; the binding survives hashing, rotation and the challenge', { skip }, async () => {
  const providerSession = async (userId: string, provider: string) => cookieOf(await auth.api.completeOidcSession({ body: { oidcUserId: userId, provider }, headers: {}, asResponse: true }));
  const one = await account_(address('p1')), two = await account_(address('p2'));
  const localEmail = address('local');
  await account_(localEmail);
  const s1 = await providerSession(one, 'p1'), s2 = await providerSession(two, 'p2'), local = cookieOf(await signIn(localEmail));
  // The stored token is the #131 handle; the binding is its own column, and getSession reads it back.
  assert.deepEqual((await pool!.query('SELECT token, "oidcProvider" FROM session WHERE "userId"=$1', [one])).rows, [{ token: auth.sessionTokenKey(rawToken(s1)), oidcProvider: 'p1' }]);
  assert.equal((await auth.api.getSession({ headers: { cookie: s1 } }))!.session.oidcProvider, 'p1');
  assert.equal((await auth.api.getSession({ headers: { cookie: local } }))!.session.oidcProvider ?? null, null);
  // Rotation keeps the binding, and so does the session a password change creates in place of the current one.
  const rotated = cookieOf(await auth.api.rotateVerifiedSession({ body: { verifiedUserId: two }, headers: { cookie: s2 }, asResponse: true }));
  assert.equal((await auth.api.getSession({ headers: { cookie: rotated } }))!.session.oidcProvider, 'p2');
  const changed = await auth.withLockedAuth(db, two, bound => (bound.api as unknown as ChangePassword).changePassword({
    body: { currentPassword: PASSWORD, newPassword: NEW_PASSWORD, revokeOtherSessions: true }, headers: { cookie: rotated }, asResponse: true,
  }));
  assert.equal(changed.status, 200);
  const s2r = cookieOf(changed);
  assert.equal(await auth.api.getSession({ headers: { cookie: rotated } }), null);
  assert.equal((await auth.api.getSession({ headers: { cookie: s2r } }))!.session.oidcProvider, 'p2');
  // Two-factor accounts signing in through each provider: their challenges are pending.
  const factorOne = await challenged('p1-factor'), factorTwo = await challenged('p2-factor');
  const c1 = await providerSession(factorOne.id, 'p1'), c2 = await providerSession(factorTwo.id, 'p2');
  assert.equal((await pool!.query('SELECT 1 FROM verification WHERE starts_with(identifier, \'oidc-challenge:\') AND value IN (\'p1\', \'p2\')')).rowCount, 2);
  const counterOf = (cookie: string) => auth.storedVerificationIdentifier(`2fa-attempts-${challengeOf(cookie)}`);
  const counted = async (cookie: string) => (await pool!.query('SELECT 1 FROM verification WHERE identifier=$1', [counterOf(cookie)])).rowCount;
  assert.deepEqual([await counted(c1), await counted(c2)], [1, 1]);
  // A one-factor provider sign-in issued a known device; so did the password sign-in, which the revocation spares.
  assert.ok((await deviceRows(one)).length > 0);
  const localDevices = await deviceRows((await pool!.query<{ id: string }>('SELECT id FROM "user" WHERE email=$1', [localEmail])).rows[0]!.id);
  assert.ok(localDevices.length > 0);
  assert.equal(await revokeProviderSessions(db, 'p1'), 1);
  assert.equal(await auth.api.getSession({ headers: { cookie: s1 } }), null);
  assert.ok(await auth.api.getSession({ headers: { cookie: s2r } }));
  assert.ok(await auth.api.getSession({ headers: { cookie: local } }));
  // The challenge's attempt counter went with it, and so did the known devices of the user signed out.
  assert.deepEqual([await counted(c1), await counted(c2)], [0, 1]);
  assert.deepEqual(await deviceRows(one), []);
  // p1's challenge went with it, so it cannot complete into a session; p2's completes into a session bound to p2.
  assert.equal((await auth.verifyTwoFactor(db, post('/two-factor/verify-totp', c1, { code: totp(factorOne.uri, 1) }))).status, 401);
  const completed = await auth.verifyTwoFactor(db, post('/two-factor/verify-totp', c2, { code: totp(factorTwo.uri, 1) }));
  assert.equal(completed.status, 200);
  assert.equal((await auth.api.getSession({ headers: { cookie: cookieOf(completed) } }))!.session.oidcProvider, 'p2');
  assert.equal((await pool!.query('SELECT 1 FROM verification WHERE starts_with(identifier, \'oidc-challenge:\') AND value IN (\'p1\', \'p2\')')).rowCount, 0);
  assert.equal(await revokeProviderSessions(db, 'p2'), 2);
  assert.equal(await auth.api.getSession({ headers: { cookie: cookieOf(completed) } }), null);
  assert.ok(await auth.api.getSession({ headers: { cookie: local } }));
  // A provider key is required, and a locked-auth transaction (one user's rows) cannot end other users' sessions.
  assert.equal((await auth.api.completeOidcSession({ body: { oidcUserId: one } as { oidcUserId: string; provider: string }, headers: {}, asResponse: true })).status, 400);
  for (const blank of ['', ' ', '\t']) await assert.rejects(revokeProviderSessions(db, blank), TypeError);
  assert.equal((await auth.api.completeOidcSession({ body: { oidcUserId: one, provider: '  ' }, headers: {}, asResponse: true })).status, 400);
  await assert.rejects(auth.withLockedAuth(db, one, (_bound, tx) => revokeProviderSessions(tx, 'p1')), refused);
});

test('a first provider sign-in takes the email lock: it waits for a sign-in by email, and a sign-in by email waits for it, without deadlock', { skip }, async () => {
  // A transaction by email holds the lock and creates the account meanwhile, as another account-creation path would.
  const email = address('race');
  let held = gate(), entered = gate();
  const creator = auth.withLockedAuthByEmail(db, email, async (_bound, tx, userId) => {
    assert.equal(userId, undefined);
    entered.open();
    await held.opened;
    await tx.execute(sql`INSERT INTO "user"(id,name,email) VALUES(${randomUUID()}, 'Racer', ${email})`);
  });
  await entered.opened;
  const provisioning = signInOidcUser(db, claimsFor(email), trusted);
  // The gate opens before the assertion, so a failure never leaves the held transaction waiting.
  let waited = await someoneWaits();
  held.open();
  assert.equal(waited, true);
  assert.notEqual(await within(creator, 10_000), 'timeout');
  await assert.rejects(provisioning, refusedWith('OIDC_ACCOUNT_EXISTS'));
  assert.equal(await usersAt(email), 1);
  // The other order: provisioning holds the lock until its caller's transaction commits; the sign-in by email waits,
  // then finds the new account.
  const second = address('race-second');
  held = gate(); entered = gate();
  let created = '';
  const provisioner = transaction(db, async tx => {
    created = (await signInOidcUser(tx, claimsFor(second), trusted)).userId;
    entered.open();
    await held.opened;
  });
  await entered.opened;
  const byEmail = auth.withLockedAuthByEmail(db, second, async (_bound, _tx, userId) => userId);
  waited = await someoneWaits();
  held.open();
  assert.equal(waited, true);
  assert.notEqual(await within(provisioner, 10_000), 'timeout');
  assert.equal(await within(byEmail, 10_000), created);
});

test('a right password on an unusable account answers at a wrong password\'s cost, with the known-device lane on', { skip }, async () => {
  // The lane is always on; it is configured explicitly here so the parity is checked with it in place.
  const lane = { knownDevices: { concurrency: 1, queue: 20 } };
  for (const target of [authOver(db, { passwordVerification: lane }), authOver(db, { legacyPasswords: true, passwordVerification: lane })]) {
    const known = address('parity'), closed = address('parity');
    await account_(known);
    const closedId = await account_(closed);
    await pool!.query('UPDATE "user" SET closed_at = now() WHERE id = $1', [closedId]);
    // Interleaved, so load drifting over the run touches the three cases alike.
    const cases = [[known, 'wrong password guess'], [address('nobody'), PASSWORD], [closed, PASSWORD]] as const;
    const samples = cases.map(() => ({ times: [] as number[], work: [] as number[] }));
    for (let round = 0; round < 9; round++) {
      for (const [at, [email, password]] of cases.entries()) {
        const started = performance.now(), cpu = process.cpuUsage();
        assert.equal((await target.signInWithPassword(db, { source: SOURCE, email, password }, allow)).status, 401);
        const used = process.cpuUsage(cpu);
        if (round < 2) continue;
        samples[at]!.times.push(performance.now() - started);
        samples[at]!.work.push((used.user + used.system) / 1000);
      }
    }
    const middle = (values: number[]) => values.sort((a, b) => a - b)[Math.floor(values.length / 2)]!;
    const medians = samples.map(({ times, work }) => [middle(times), middle(work)] as const);
    const spread = (values: number[]) => Math.max(...values) / Math.min(...values);
    const shown = medians.map(([time, cpu]) => `${time.toFixed(0)} ms, ${cpu.toFixed(0)} ms CPU`).join(' / ');
    // A further derivation for the unusable account would add a third to a half of the work.
    assert.ok(spread(medians.map(([, cpu]) => cpu)) < 1.3, shown);
    assert.ok(spread(medians.map(([time]) => time)) < 1.4, shown);
  }
});

test('on a database over a single pg Client, a rolled-back transaction is an error too, and locked auth works', { skip }, async () => {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    const single = drizzle(client, { schema });
    await assert.rejects(transaction(single, async tx => {
      await tx.execute(sql`CREATE TABLE swallowed (id int)`);
      await tx.execute(sql`SELECT 1/0`).catch(() => undefined);
      return 12;
    }), TransactionRolledBackError);
    assert.equal((await client.query("SELECT to_regclass('swallowed') AS found")).rows[0].found, null);
    assert.equal(await transaction(single, async tx => { await tx.execute(sql`SELECT 1`); return 12; }), 12);
    const email = address('single');
    const id = await account_(email);
    const singleAuth = authOver(single as unknown as Database);
    await assert.rejects(singleAuth.withLockedAuth(single, id, async (_bound, tx) => { await tx.execute(sql`SELECT 1/0`).catch(() => undefined); return 'reported'; }), TransactionRolledBackError);
    const signedIn = await singleAuth.signInWithPassword(single, { source: SOURCE, email, password: PASSWORD }, allow);
    assert.equal(signedIn.status, 200);
    assert.equal(await sessions(id), 1);
  } finally { await client.end(); }
});

test('the limiter runs before the verification queue: a refused attempt gets 429 even while the queue is full', { skip }, async () => {
  const email = address('order');
  await account_(email);
  const full = authOver(db, { passwordVerification: { concurrency: 1, queue: 0 } });
  const busy = full.signInWithPassword(db, { source: SOURCE, email: address('busy'), password: 'wrong password guess' }, allow);
  await delay(80);
  let asked = 0;
  const response = await full.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, accountStep(() => { asked++; return false; }));
  assert.deepEqual([response.status, asked], [429, 1]);
  // Negative control: an allowed attempt in the same moment finds the queue full.
  assert.equal((await full.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow)).status, 503);
  await busy;
});

test('the email index may be lower(email), lower(email::text) on varchar or a unique citext column; a refusal is checked again', { skip }, async () => {
  await pool!.query('CREATE EXTENSION IF NOT EXISTS citext');
  const tables = (name: string, emailType: string, index: string) => `CREATE SCHEMA ${name};
    CREATE TABLE ${name}."user" (LIKE public."user" INCLUDING DEFAULTS); ALTER TABLE ${name}."user" ALTER COLUMN email TYPE ${emailType};
    ${index}
    CREATE TABLE ${name}.account (LIKE public.account INCLUDING ALL); CREATE TABLE ${name}.session (LIKE public.session INCLUDING ALL);
    CREATE TABLE ${name}.verification (LIKE public.verification INCLUDING ALL);`;
  await pool!.query(tables('vc', 'varchar(320)', 'CREATE UNIQUE INDEX ON vc."user" (lower(email));'));
  await pool!.query(tables('ci', 'public.citext', 'CREATE UNIQUE INDEX ON ci."user" (email);'));
  await pool!.query(tables('late', 'text', ''));
  const { rows } = await pool!.query<{ definition: string }>("SELECT pg_get_expr(i.indexprs, i.indrelid) AS definition FROM pg_index i WHERE i.indrelid = 'vc.\"user\"'::regclass AND i.indexprs IS NOT NULL");
  assert.equal(rows[0]!.definition, 'lower((email)::text)');
  const pools = ['vc', 'ci', 'late'].map(name => new pg.Pool({ connectionString: url, max: 2, options: `-c search_path=${name},public` }));
  try {
    const [vcDb, ciDb, lateDb] = pools.map(item => drizzle(item, { schema }));
    assert.equal(await authOver(vcDb!).assertSchema(vcDb!), undefined);
    assert.equal(await authOver(ciDb!).assertSchema(ciDb!), undefined);
    const lateAuth = authOver(lateDb!);
    await assert.rejects(lateAuth.assertSchema(lateDb!), MissingEmailIndexError);
    // The index added while the app runs: the next call passes, with no restart.
    await pool!.query('CREATE UNIQUE INDEX ON late."user" (lower(email))');
    await delay(2100);
    assert.equal(await lateAuth.assertSchema(lateDb!), undefined);
    assert.equal(await lateAuth.withLockedAuthByEmail(lateDb!, address('none'), async (_bound, _tx, userId) => userId), undefined);
  } finally { await Promise.all(pools.map(item => item.end())); }
});

// One shared verification slot and one lane slot, nothing waiting: a flood fills the shared slot at once.
const narrow = { passwordVerification: { concurrency: 1, queue: 0, knownDevices: { concurrency: 1, queue: 0 } } };
// Holds the shared slot for one verification (about a quarter of a second) and lets it be taken first.
async function holdShared(target: Ten98Auth) {
  const held = target.signInWithPassword(db, { source: 'ip:holder', email: address('holder'), password: 'wrong password guess' }, allow);
  await delay(40);
  return held;
}
const attempt = (target: Ten98Auth, email: string, password: string, cookie = '', limit: (attempt: PasswordAttempt) => boolean = () => true) =>
  target.signInWithPassword(db, { source: `ip:${randomUUID()}`, email, password, headers: cookie ? { cookie } : {} }, accountStep(limit));

test('a distributed flood fills the shared queue; a known device still signs in through its lane', { skip }, async () => {
  const flooded = authOver(db, narrow);
  const email = address('lane');
  await account_(email);
  const browser = jar().take(await flooded.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow));
  const flood = Array.from({ length: 20 }, () => attempt(flooded, address('flood'), 'wrong password guess').then(response => response.status));
  await delay(20);
  const started = performance.now();
  const signedIn = await attempt(flooded, email, PASSWORD, browser.header());
  assert.equal(signedIn.status, 200);
  assert.ok(performance.now() - started < 3000);
  const statuses = await Promise.all(flood);
  assert.ok(statuses.filter(status => status === 503).length >= 15, statuses.join(','));
});

test('without a verified claim, a real account, an unknown email and a foreign cookie answer alike during a flood', { skip }, async () => {
  const flooded = authOver(db, narrow);
  const a = address('alike'), b = address('alike');
  await account_(a);
  await account_(b);
  const aCookie = jar().take(await flooded.signInWithPassword(db, { source: SOURCE, email: a, password: PASSWORD }, allow)).header();
  const held = holdShared(flooded);
  await delay(0);
  const outcomes = [];
  for (let round = 0; round < 2; round++) {
    outcomes.push(await answer(await attempt(flooded, b, PASSWORD)));                      // a real account, no cookie
    outcomes.push(await answer(await attempt(flooded, address('nobody'), PASSWORD)));      // an unknown email
    outcomes.push(await answer(await attempt(flooded, address('nobody'), PASSWORD, aCookie))); // A's valid cookie, unknown email
    outcomes.push(await answer(await attempt(flooded, b, PASSWORD, aCookie)));             // A's valid cookie, B's email
  }
  await held;
  assert.equal(outcomes[0]!.status, 503);
  for (const outcome of outcomes) assert.deepEqual(outcome, outcomes[0]);
});

test('a forged or revoked device cookie gets no lane: it is an attempt like any other', { skip }, async () => {
  const flooded = authOver(db, narrow);
  const email = address('revoked');
  const id = await account_(email);
  const valid = jar().take(await flooded.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow));
  const forged = jar(); forged.with(`${'A'.repeat(32)}.${'B'.repeat(43)}`);
  const seen: boolean[] = [];
  const recording = (entry: PasswordAttempt) => { seen.push(entry.knownDevice); return true; };
  await flooded.withLockedAuth(db, id, bound => bound.revokeAllSessions());
  const held = holdShared(flooded);
  const forgedOutcome = await attempt(flooded, email, PASSWORD, forged.header(), recording);
  const revokedOutcome = await attempt(flooded, email, PASSWORD, valid.header(), recording);
  await held;
  assert.deepEqual([forgedOutcome.status, revokedOutcome.status, seen], [503, 503, [false, false]]);
});

test('the lane has its own bound: valid cookies beyond it get 503 and take no shared capacity', { skip }, async () => {
  const flooded = authOver(db, narrow);
  const first = address('bound'), second = address('bound');
  await account_(first);
  await account_(second);
  const firstCookie = jar().take(await flooded.signInWithPassword(db, { source: SOURCE, email: first, password: PASSWORD }, allow)).header();
  const secondCookie = jar().take(await flooded.signInWithPassword(db, { source: SOURCE, email: second, password: PASSWORD }, allow)).header();
  // One known device holds the lane; the next is refused instead of spilling into the free shared slot.
  const laneHolder = attempt(flooded, first, 'wrong password guess', firstCookie);
  await delay(40);
  const beyond = await attempt(flooded, second, 'wrong password guess', secondCookie);
  // The shared slot stayed free throughout: an attempt without a claim still gets it while the lane is full.
  const shared = await attempt(flooded, address('nobody'), 'wrong password guess');
  assert.deepEqual([beyond.status, shared.status, (await laneHolder).status], [503, 401, 401]);
  assert.throws(() => authOver(db, { passwordVerification: { knownDevices: { concurrency: 0 } } }), /passwordVerification.knownDevices.concurrency must be/);
});

test('the limiter runs before the lane too: a refused known device gets 429 while the lane is full, and keeps its attempt', { skip }, async () => {
  const flooded = authOver(db, narrow);
  const email = address('lane-order'), other = address('lane-order');
  const id = await account_(email);
  await account_(other);
  const mine = jar().take(await flooded.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow)).header();
  const theirs = jar().take(await flooded.signInWithPassword(db, { source: SOURCE, email: other, password: PASSWORD }, allow)).header();
  const laneHolder = attempt(flooded, other, 'wrong password guess', theirs);
  await delay(40);
  let asked = 0;
  const refused = await attempt(flooded, email, PASSWORD, mine, entry => { asked++; return entry.knownDevice && false; });
  assert.deepEqual([refused.status, asked], [429, 1]);
  assert.equal(await attempts(id), 0);
  await laneHolder;
});

// Races around revokeProviderSessions, each forced: pauseInserts stops one side between two of its statements.
test('a two-factor challenge opened while its provider is revoked never completes into a session', { skip }, async () => {
  const factor = await challenged('window');
  const before = await sessions(factor.id);
  // The challenge row's insert waits; its binding row, written just before it, is already committed.
  const pause = await pauseInserts('verification', 424_201, `NEW.value = '${factor.id}' AND starts_with(NEW.identifier, '2fa-') AND NOT starts_with(NEW.identifier, '2fa-attempts-')`);
  try {
    const signing = providerSignIn(factor.id, 'window');
    const waited = await someoneWaits();
    const bindings = (await pool!.query("SELECT 1 FROM verification WHERE starts_with(identifier, 'oidc-challenge:') AND value = 'window'")).rowCount;
    const revoked = await revokeProviderSessions(db, 'window');
    await pause.release();
    assert.deepEqual([waited, bindings, revoked], [true, 1, 0]);
    const challenge = cookieOf(await signing);
    assert.ok(challengeOf(challenge));
    // The challenge exists, but its binding went with the revocation, so it cannot complete.
    const completed = await auth.verifyTwoFactor(db, post('/two-factor/verify-totp', challenge, { code: totp(factor.uri, 1) }));
    assert.equal(completed.status, 401);
    assert.deepEqual([await sessions(factor.id), await boundSessions('window')], [before, 0]);
  } finally { await pause.drop(); }
});

test('a challenge completing while its provider is revoked leaves no session, because challenges are revoked before sessions', { skip }, async () => {
  const factor = await challenged('race-order');
  const challenge = cookieOf(await providerSignIn(factor.id, 'race'));
  // The completion waits as it inserts its session, holding the challenge, its counter and its binding, uncommitted.
  const pause = await pauseInserts('session', 424_202, `NEW."oidcProvider" = 'race'`);
  try {
    const completing = auth.verifyTwoFactor(db, post('/two-factor/verify-totp', challenge, { code: totp(factor.uri, 1) }));
    const first = await someoneWaits();
    const revoking = revokeProviderSessions(db, 'race');
    revoking.catch(() => undefined);
    // The revocation now waits on the rows the completion holds.
    const both = await waitersAtLeast(2);
    await pause.release();
    assert.deepEqual([first, both], [true, true]);
    const [completed, revoked] = await Promise.all([completing, revoking]);
    assert.deepEqual([completed.status, revoked, await boundSessions('race')], [200, 1, 0]);
    assert.equal(await auth.api.getSession({ headers: { cookie: cookieOf(completed) } }), null);
  } finally { await pause.drop(); }
});

test('a provider sign-in that commits while a revocation pass runs is ended by the next pass', { skip }, async () => {
  const early = await account_(address('loop-a')), late = await account_(address('loop-b'));
  assert.equal((await providerSignIn(early, 'loop')).status, 200);
  const holder = await pool!.connect();
  try {
    await holder.query('BEGIN');
    // The pass's session DELETE waits on this row; a session committed meanwhile is not in its snapshot.
    await holder.query('SELECT 1 FROM session WHERE "userId"=$1 FOR UPDATE', [early]);
    const revoking = revokeProviderSessions(db, 'loop');
    revoking.catch(() => undefined);
    const waited = await someoneWaits();
    const lateSignIn = await providerSignIn(late, 'loop');
    await holder.query('COMMIT');
    assert.deepEqual([waited, lateSignIn.status], [true, 200]);
    assert.equal(await revoking, 2);
    assert.equal(await boundSessions('loop'), 0);
  } finally { await holder.query('ROLLBACK').catch(() => undefined); holder.release(); }
});

test('a challenge completion a deadlock aborts answers a retryable 503, and the same request then signs in', { skip }, async () => {
  const factor = await challenged('deadlock');
  const challenge = cookieOf(await providerSignIn(factor.id, 'dl'));
  const stored = auth.storedVerificationIdentifier(challengeOf(challenge));
  const pause = await pauseInserts('session', 424_203, `NEW."oidcProvider" = 'dl'`);
  const request = () => post('/two-factor/verify-totp', challenge, { code: totp(factor.uri, 1) });
  try {
    const completing = auth.verifyTwoFactor(db, request());
    assert.equal(await someoneWaits(), true);
    // The holder waits on the challenge row the completion consumed: a cycle. The completion's wait began first, so its
    // deadlock check runs first (the holder's is delayed) and PostgreSQL aborts it with 40P01.
    await pause.holder.query("SET LOCAL deadlock_timeout = '10s'");
    const holding = pause.holder.query('DELETE FROM verification WHERE identifier=$1', [stored]);
    const completed = await completing;
    await holding;
    await pause.holder.query('ROLLBACK');
    assert.equal(completed.status, 503);
    assert.equal(completed.headers.get('retry-after'), '1');
    assert.equal((await completed.json() as { code: string }).code, 'SIGN_IN_RETRY');
    assert.equal(await boundSessions('dl'), 0);
    // Nothing the aborted completion did persisted: the challenge stands and completes.
    const retried = await auth.verifyTwoFactor(db, request());
    assert.equal(retried.status, 200);
    assert.equal(await boundSessions('dl'), 1);
  } finally { await pause.drop(); }
});

test('first provider sign-ins of one identity queued on its email lock resolve to one account: the identity is read again under the lock', { skip }, async () => {
  const email = address('queued'), sub = subject();
  const holder = await pool!.connect();
  try {
    await holder.query('BEGIN');
    await holder.query('SELECT pg_advisory_xact_lock(109859, hashtext($1))', [email]);
    const signIns = Promise.allSettled([signInOidcUser(db, claimsFor(email, sub), trusted), signInOidcUser(db, claimsFor(email, sub), trusted)]);
    const waited = await waitersAtLeast(2);
    await holder.query('COMMIT');
    assert.equal(waited, true);
    const settled = await signIns;
    assert.deepEqual(settled.map(item => item.status), ['fulfilled', 'fulfilled'], JSON.stringify(settled));
    const results = settled.map(item => (item as PromiseFulfilledResult<{ userId: string; created: boolean }>).value);
    assert.equal(new Set(results.map(item => item.userId)).size, 1);
    assert.deepEqual(results.map(item => item.created).sort(), [false, true]);
    assert.equal(await usersAt(email), 1);
  } finally { await holder.query('ROLLBACK').catch(() => undefined); holder.release(); }
});

test('first provider sign-ins of one identity under two emails at once resolve to one account: the loser falls back to it', { skip }, async () => {
  const first = address('twin-a'), second = address('twin-b'), sub = subject();
  const holder = await pool!.connect();
  try {
    await holder.query('BEGIN');
    for (const email of [first, second]) await holder.query('SELECT pg_advisory_xact_lock(109859, hashtext($1))', [email]);
    const signIns = Promise.allSettled([first, second].map(email => signInOidcUser(db, claimsFor(email, sub), trusted)));
    const waited = await waitersAtLeast(2);
    await holder.query('COMMIT');
    assert.equal(waited, true);
    const settled = await signIns;
    assert.deepEqual(settled.map(item => item.status), ['fulfilled', 'fulfilled'], JSON.stringify(settled));
    const results = settled.map(item => (item as PromiseFulfilledResult<{ userId: string; created: boolean }>).value);
    assert.equal(new Set(results.map(item => item.userId)).size, 1);
    assert.deepEqual(results.map(item => item.created).sort(), [false, true]);
    assert.equal((await usersAt(first))! + (await usersAt(second))!, 1);
  } finally { await holder.query('ROLLBACK').catch(() => undefined); holder.release(); }
});

test('unlinking waits for a concurrent change to the user\'s other sign-in methods and counts what remains', { skip }, async () => {
  const id = await account_(address('unlink-race'), { hash: null });
  const kept = { issuer: ISSUER, subject: subject() }, other = { issuer: 'https://other.example.com', subject: subject() };
  for (const identity of [kept, other]) await auth.withLockedAuth(db, id, (_bound, tx) => linkOidcIdentity(tx, identity));
  const holder = await pool!.connect();
  try {
    await holder.query('BEGIN');
    // A writer that does not hold the user row (an app's own statement, say) removes the other identity meanwhile.
    await holder.query('DELETE FROM account WHERE "providerId"=$1 AND "accountId"=$2', [oidcProviderId(other.issuer), other.subject]);
    const unlinking = auth.withLockedAuth(db, id, (_bound, tx) => unlinkOidcIdentity(tx, kept));
    unlinking.catch(() => undefined);
    const waited = await someoneWaits();
    await holder.query('COMMIT');
    assert.equal(waited, true);
    await assert.rejects(unlinking, refusedWith('OIDC_LAST_SIGN_IN_METHOD'));
    assert.deepEqual((await identitiesOf(id)).map(row => row.accountId), [kept.subject]);
  } finally { await holder.query('ROLLBACK').catch(() => undefined); holder.release(); }
});

test('only a way that can sign in keeps an identity unlinkable: a verifiable password, or an identity of a usable issuer', { skip }, async () => {
  const id = await account_(address('methods'), { hash: null });
  const identity = { issuer: ISSUER, subject: subject() }, retired = { issuer: 'https://retired.example.com', subject: subject() };
  await auth.withLockedAuth(db, id, (_bound, tx) => linkOidcIdentity(tx, identity));
  const unlink = (options: Parameters<typeof unlinkOidcIdentity>[2] = {}) => auth.withLockedAuth(db, id, (_bound, tx) => unlinkOidcIdentity(tx, identity, options));
  const setPassword = (value: string | null) => pool!.query('UPDATE account SET password=$1 WHERE "userId"=$2 AND "providerId"=\'credential\'', [value, id]);
  // Not ways in: another provider's account row, an empty or malformed hash, or a legacy hash with legacy passwords off.
  await pool!.query('INSERT INTO account(id,"accountId","providerId","userId") VALUES($1,$2,\'google\',$3)', [randomUUID(), `g-${randomUUID()}`, id]);
  for (const value of ['', 'not-a-hash', `${hashes.old}x`, hashes.legacy]) {
    await setPassword(value);
    await assert.rejects(unlink(), refusedWith('OIDC_LAST_SIGN_IN_METHOD'), value);
  }
  // Nor an identity of an issuer the app no longer accepts.
  await setPassword(null);
  await auth.withLockedAuth(db, id, (_bound, tx) => linkOidcIdentity(tx, retired));
  const asked: string[] = [];
  await assert.rejects(unlink({ isIssuerUsable: issuer => { asked.push(issuer); return issuer !== normaliseOidcIssuer(retired.issuer); } }), refusedWith('OIDC_LAST_SIGN_IN_METHOD'));
  assert.deepEqual(asked, [normaliseOidcIssuer(retired.issuer)]);
  await pool!.query('DELETE FROM account WHERE "providerId"=$1', [oidcProviderId(retired.issuer)]);
  // A legacy hash is a way in where legacy passwords are accepted.
  await setPassword(hashes.legacy);
  await unlink({ legacyPasswords: true });
  assert.deepEqual(await identitiesOf(id), []);
});

test('an invitation accepted with an identity another account holds is refused before anything is written', { skip }, async () => {
  const holderId = await account_(address('holder'));
  const identity = { issuer: ISSUER, subject: subject() };
  await auth.withLockedAuth(db, holderId, (_bound, tx) => linkOidcIdentity(tx, identity));
  const owner = await account_(address('inviter-2'));
  const invited = address('second-invitee');
  const { token } = await inTransaction(async client => team.inviteMember(client, await workspaceOf(owner), owner, { email: invited, role: 'viewer' }));
  // A caller that commits after the refusal still leaves no account behind.
  const client = await pool!.connect();
  try {
    await client.query('BEGIN');
    await assert.rejects(team.acceptVerifiedOidcInvitation(client as unknown as TeamClient, token, { email: invited, name: 'Second', ...identity }),
      (error: { code?: string; status?: number }) => error.code === 'OIDC_IDENTITY_IN_USE' && error.status === 409);
    await client.query('COMMIT');
  } finally { client.release(); }
  assert.equal(await usersAt(invited), 0);
  assert.deepEqual(await signInOidcUser(db, { iss: ISSUER, sub: identity.subject }, {}), { userId: holderId, created: false });
});

test('completeOidcSession refuses a closed account, or one isAccountUsable refuses, as it refuses an unknown user', { skip }, async () => {
  const closedId = await account_(address('closed-provider'));
  await pool!.query('UPDATE "user" SET closed_at=now() WHERE id=$1', [closedId]);
  const [closed, unknown] = [await providerSignIn(closedId, 'idp'), await providerSignIn(randomUUID(), 'idp')];
  assert.deepEqual([closed.status, await closed.text()], [unknown.status, await unknown.text()]);
  assert.equal(closed.status, 401);
  assert.equal(await sessions(closedId), 0);
  const open = await account_(address('refused-provider'));
  const asked: string[] = [];
  const refusing = authOver(db, { isAccountUsable: account => { asked.push(account.id); return false; } });
  assert.equal((await providerSignIn(open, 'idp', refusing)).status, 401);
  assert.deepEqual(asked, [open]);
  assert.equal(await sessions(open), 0);
  assert.equal((await providerSignIn(open, 'idp')).status, 200);
  // A Drizzle user table that does not map closed_at cannot have usability judged: no session either way.
  const unmappedUser = pgTable('user', {
    id: text('id').primaryKey(), name: text('name').notNull(), email: text('email').notNull(), emailVerified: boolean('emailVerified').notNull(), image: text('image'),
    createdAt: stamp('createdAt').notNull(), updatedAt: stamp('updatedAt').notNull(), twoFactorEnabled: boolean('twoFactorEnabled').notNull(),
  });
  const unmapped = { ...schema, user: unmappedUser };
  const unmappedAuth = createTen98Auth({ database: drizzleAdapter(db, { provider: 'pg', schema: unmapped }), appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test' });
  const other = await account_(address('unmapped'));
  const outcome = await providerSignIn(other, 'idp', unmappedAuth).then(response => response.status, () => 'refused');
  assert.notEqual(outcome, 200);
  assert.equal(await sessions(other), 0);
});

test('better-auth\'s own account routes are off: /unlink-account and /list-accounts answer 404 and change nothing', { skip }, async () => {
  const email = address('routes');
  const id = await account_(email);
  await auth.withLockedAuth(db, id, (_bound, tx) => linkOidcIdentity(tx, { issuer: ISSUER, subject: subject() }));
  const cookie = cookieOf(await signIn(email));
  const rows = async () => (await pool!.query('SELECT id FROM account WHERE "userId"=$1 ORDER BY id', [id])).rows;
  const before = await rows();
  for (const request of [post('/unlink-account', cookie, { providerId: 'credential' }), post('/unlink-account', cookie, { providerId: oidcProviderId(ISSUER) }),
    new Request(`${ORIGIN}/api/auth/list-accounts`, { headers: { cookie, origin: ORIGIN } })]) {
    assert.equal((await auth.handler(request)).status, 404, new URL(request.url).pathname);
  }
  assert.deepEqual(await rows(), before);
});

test('no request can bind, rebind or unbind a session: /update-session refuses oidcProvider', { skip }, async () => {
  const id = await account_(address('pinned'));
  const cookie = cookieOf(await providerSignIn(id, 'pinned'));
  for (const value of [null, 'other', '']) assert.equal((await auth.handler(post('/update-session', cookie, { oidcProvider: value }))).status, 400, String(value));
  assert.equal((await auth.api.getSession({ headers: { cookie } }))!.session.oidcProvider, 'pinned');
});

test('a blank subject or provider key, or a subject with a control character, is refused before any query', { skip }, async () => {
  const id = await account_(address('inputs'));
  for (const bad of [' ', '\t', 'a\u0000b', 'line\nbreak', 'del\u007f']) {
    await assert.rejects(signInOidcUser(db, claimsFor(address('input'), bad), trusted), TypeError, JSON.stringify(bad));
    await assert.rejects(auth.withLockedAuth(db, id, (_bound, tx) => linkOidcIdentity(tx, { issuer: ISSUER, subject: bad })), TypeError, JSON.stringify(bad));
  }
  for (const bad of [' ', '\t\t']) assert.equal((await providerSignIn(id, bad)).status, 400);
  assert.deepEqual(await identitiesOf(id), []);
});

test('a flood the source step refuses never touches the pool: no cookie, a forged cookie or a valid one', { skip }, async () => {
  const email = address('refused-flood'), bystander = address('refused-flood');
  await account_(email);
  await account_(bystander);
  const flood = new pg.Pool({ connectionString: url, max: 10 });
  try {
    const floodDb = drizzle(flood, { schema });
    const floodAuth = authOver(floodDb);
    await floodAuth.assertSchema(floodDb);
    const valid = jar().take(await floodAuth.signInWithPassword(floodDb, { source: SOURCE, email, password: PASSWORD }, allow)).header();
    const forged = jar(); forged.with(`${'A'.repeat(32)}.${'B'.repeat(43)}`);
    let accountAsked = 0;
    const refuseEverySource = { source: () => false, account: () => { accountAsked++; return true; } };
    for (const [name, cookie] of [['no cookie', ''], ['forged', forged.header()], ['valid', valid]] as const) {
      let waiters = 0;
      const sampler = setInterval(() => { waiters = Math.max(waiters, flood.waitingCount); }, 2);
      const until = performance.now() + 1500;
      const statuses = new Set<number>();
      // 200 requests in flight; each yields to the event loop between attempts, as requests arriving over a socket do.
      const workers = Array.from({ length: 200 }, async () => {
        while (performance.now() < until) {
          statuses.add((await floodAuth.signInWithPassword(floodDb, { source: `ip:${randomUUID()}`, email, password: PASSWORD, headers: cookie ? { cookie } : {} }, refuseEverySource)).status);
          await new Promise(resolve => setImmediate(resolve));
        }
      });
      await delay(200);
      const started = performance.now();
      const other = await floodAuth.signInWithPassword(floodDb, { source: `ip:${randomUUID()}`, email: bystander, password: PASSWORD }, allow);
      const waited = performance.now() - started;
      await Promise.all(workers);
      clearInterval(sampler);
      assert.deepEqual([name, [...statuses], waiters, other.status], [name, [429], 0, 200]);
      assert.ok(waited < 2500, `${name}: another user's sign-in took ${waited.toFixed(0)} ms`);
    }
    assert.equal(accountAsked, 0);
  } finally { await flood.end(); }
});

test('the limiter needs both steps; a source refusal asks nothing else and leaves the device claim alone', { skip }, async () => {
  const email = address('steps');
  const id = await account_(email);
  for (const limits of [undefined, () => true, { source: () => true }, { account: () => true }]) {
    await assert.rejects(auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, limits as never), /rate limits: \{ source, account \}/);
  }
  const browser = jar().take(await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow));
  const seen: unknown[] = [];
  const refused = await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { cookie: browser.header() } },
    { source: attempt => { seen.push(attempt); return false; }, account: attempt => { seen.push(attempt); return true; } });
  assert.deepEqual([refused.status, seen, await attempts(id)], [429, [{ email, source: SOURCE }], 0]);
  // The account step refusing gives the claim back; the device then counts as known again.
  const known: boolean[] = [];
  for (let round = 0; round < 2; round++) {
    await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { cookie: browser.header() } }, accountStep(attempt => { known.push(attempt.knownDevice); return false; }));
  }
  assert.deepEqual([known, await attempts(id)], [[true, true], 0]);
});

// A reset request through the handler, as a browser sends it.
const resetRequest = (target: Ten98Auth, path: string, body: unknown) => target.handler(new Request(`${ORIGIN}/api/auth${path}`, {
  method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify(body),
}));
const resetRows = async (userId: string) => (await pool!.query<{ n: number }>("SELECT count(*)::int AS n FROM verification WHERE value=$1 AND identifier LIKE 'reset-password:%'", [userId])).rows[0]!.n;
const storedHash = async (userId: string) => (await pool!.query<{ password: string }>('SELECT password FROM account WHERE "userId"=$1', [userId])).rows[0]!.password;

test('a closed account gets no reset: the request answers as for an unknown email, and an earlier token is refused', { skip }, async () => {
  const sent: string[] = [];
  const resetting = authOver(db, { sendResetPassword: ({ token }) => { sent.push(token); } });
  const email = address('reset-closed');
  const id = await account_(email);
  // A token issued while the account was open, then the account closed.
  assert.equal((await resetRequest(resetting, '/request-password-reset', { email, redirectTo: '/' })).status, 200);
  assert.deepEqual([sent.length, await resetRows(id)], [1, 1]);
  await pool!.query('UPDATE "user" SET closed_at = now() WHERE id = $1', [id]);
  const before = await storedHash(id);
  const unknownToken = await answer(await resetRequest(resetting, '/reset-password', { token: 'x'.repeat(24), newPassword: NEW_PASSWORD }));
  assert.equal(unknownToken.status, 400);
  assert.deepEqual(await answer(await resetRequest(resetting, '/reset-password', { token: sent[0], newPassword: NEW_PASSWORD })), unknownToken);
  assert.equal(await storedHash(id), before);
  // A new request: the same answer as an unknown email, no token stored, nothing sent; a foreign redirect is refused alike.
  const unknown = await answer(await resetRequest(resetting, '/request-password-reset', { email: address('nobody'), redirectTo: '/' }));
  assert.deepEqual(await answer(await resetRequest(resetting, '/request-password-reset', { email: email.toUpperCase(), redirectTo: '/' })), unknown);
  const foreign = await answer(await resetRequest(resetting, '/request-password-reset', { email: address('nobody'), redirectTo: 'https://evil.example/' }));
  assert.notEqual(foreign.status, 200);
  assert.deepEqual(await answer(await resetRequest(resetting, '/request-password-reset', { email, redirectTo: 'https://evil.example/' })), foreign);
  // A stored email the route's schema rejects gets the route's own 400, as an unknown one does.
  const odd = `ü${randomUUID()}@example.com`;
  await pool!.query('UPDATE "user" SET closed_at = now() WHERE id = $1', [await account_(odd)]);
  const oddUnknown = await answer(await resetRequest(resetting, '/request-password-reset', { email: `ü${randomUUID()}@example.com`, redirectTo: '/' }));
  assert.equal(oddUnknown.status, 400);
  assert.deepEqual(await answer(await resetRequest(resetting, '/request-password-reset', { email: odd, redirectTo: '/' })), oddUnknown);
  assert.deepEqual([sent.length, await resetRows(id)], [1, 1]);
  // Negative control: an app that allows the account resets it.
  const lenient = authOver(db, { sendResetPassword: ({ token }) => { sent.push(token); }, isAccountUsable: () => true });
  assert.equal((await resetRequest(lenient, '/request-password-reset', { email, redirectTo: '/' })).status, 200);
  assert.equal(sent.length, 2);
  assert.equal((await resetRequest(lenient, '/reset-password', { token: sent[1], newPassword: NEW_PASSWORD })).status, 200);
  assert.notEqual(await storedHash(id), before);
});

test('the guide closure checklist leaves no session, no known device and no reset', { skip }, async () => {
  const sent: string[] = [];
  const closing = authOver(db, { sendResetPassword: ({ token }) => { sent.push(token); } });
  const email = address('closure');
  const id = await account_(email);
  const browser = jar().take(await closing.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow));
  assert.equal((await resetRequest(closing, '/request-password-reset', { email, redirectTo: '/' })).status, 200);
  const known = async () => {
    let seen: boolean | undefined;
    await closing.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD, headers: { cookie: browser.header() } }, accountStep(attempt => { seen = attempt.knownDevice; return false; }));
    return seen;
  };
  assert.equal(await known(), true);
  // The guide's closure statements, read from the guide and run as written, in one transaction.
  const statements = closureStatements();
  assert.equal(statements.length, 3, statements.join(' | '));
  const client = await pool!.connect();
  try {
    await client.query('BEGIN');
    for (const statement of statements) await client.query(statement, [id]);
    await client.query('COMMIT');
  } finally { client.release(); }
  assert.equal(await closing.api.getSession({ headers: { cookie: browser.header() } }), null);
  assert.equal(await known(), false);
  assert.equal((await resetRequest(closing, '/reset-password', { token: sent[0], newPassword: NEW_PASSWORD })).status, 400);
  assert.equal((await resetRequest(closing, '/request-password-reset', { email, redirectTo: '/' })).status, 200);
  assert.deepEqual([sent.length, await resetRows(id), await sessions(id)], [1, 0, 0]);
});

test('a right password on a closed account is refused before the lock: it never waits on the email lock', { skip }, async () => {
  const closed = address('prelock'), open = address('prelock');
  const id = await account_(closed);
  await account_(open);
  await pool!.query('UPDATE "user" SET closed_at = now() WHERE id = $1', [id]);
  const holder = await pool!.connect();
  try {
    for (const email of [closed, open]) await holder.query('SELECT pg_advisory_lock(109859, hashtext($1))', [email]);
    // Negative control: a usable account's sign-in reaches the lock and waits there.
    let openSettled = false;
    const openSignIn = signIn(open).then(response => { openSettled = true; return response; });
    const started = performance.now();
    const refused = await signIn(closed);
    const waited = performance.now() - started;
    assert.equal(refused.status, 401);
    assert.ok(waited < 3000, `the closed account waited ${waited.toFixed(0)} ms`);
    assert.equal(openSettled, false);
    await holder.query('SELECT pg_advisory_unlock_all()');
    assert.equal((await openSignIn).status, 200);
    assert.equal(await sessions(id), 0);
  } finally { await holder.query('SELECT pg_advisory_unlock_all()'); holder.release(); }
});

// The guide's account-closure statements, from its `sql` block under **Account closure.**
function closureStatements(): string[] {
  const guide = readFileSync(new URL('../docs/FEATURE-ADOPTION.md', import.meta.url), 'utf8');
  const block = /\*\*Account closure\.\*\*[\s\S]*?```sql\n([\s\S]*?)```/.exec(guide);
  assert.ok(block, 'the guide has an Account closure sql block');
  return block[1]!.split(';').map(statement => statement.trim()).filter(Boolean);
}

// The median of a list of numbers.
const median = (values: number[]) => { const sorted = [...values].sort((a, b) => a - b); return sorted[Math.floor(sorted.length / 2)]!; };

test('a reset request costs the same for an unknown email, a closed account and a usable one', { skip }, async () => {
  const resetting = authOver(db, { sendResetPassword: () => {} });
  const usableEmail = address('reset-timing'), closedEmail = address('reset-timing');
  await account_(usableEmail);
  await pool!.query('UPDATE "user" SET closed_at = now() WHERE id = $1', [await account_(closedEmail)]);
  const timed = async (email: string) => {
    const started = performance.now();
    const response = await resetRequest(resetting, '/request-password-reset', { email, redirectTo: '/' });
    await response.text();
    assert.equal(response.status, 200);
    return performance.now() - started;
  };
  for (let warm = 0; warm < 20; warm++) for (const email of [address('nobody'), closedEmail, usableEmail]) await timed(email);
  // 600 samples, interleaved in a fresh random order each round so drift and load fall on every kind alike.
  const closed: number[] = [], usable: number[] = [], unknown: number[] = [];
  for (let round = 0; round < 200; round++) {
    const kinds = ['unknown', 'closed', 'usable'].sort(() => Math.random() - 0.5);
    const took: Record<string, number> = {};
    for (const kind of kinds) took[kind] = await timed(kind === 'unknown' ? address('nobody') : kind === 'closed' ? closedEmail : usableEmail);
    unknown.push(took.unknown!);
    closed.push(took.closed! - took.unknown!);
    usable.push(took.usable! - took.unknown!);
  }
  // The tolerance is a share of an unknown email's median time, so it holds on a fast and a slow machine alike: the joined
  // lookup added 17 to 35% for an existing account. A closed account takes the route's unknown-email path after the
  // preset's read, so that read alone separates it from an unknown email: within 10% is parity. A usable account also
  // stores a token and sends, which better-auth's own route does whether or not the preset reads first; it is reported.
  const base = median(unknown);
  assert.ok(Math.abs(median(closed)) < base * 0.1, `closed minus unknown: median ${median(closed).toFixed(2)} ms of ${base.toFixed(2)} ms (usable: ${median(usable).toFixed(2)} ms)`);
});

// The user table of an app whose Drizzle schema does not map closed_at.
const bareUser = pgTable('user', {
  id: text('id').primaryKey(), name: text('name').notNull(), email: text('email').notNull(), emailVerified: boolean('emailVerified').notNull(), image: text('image'),
  createdAt: stamp('createdAt').notNull(), updatedAt: stamp('updatedAt').notNull(), twoFactorEnabled: boolean('twoFactorEnabled'),
});

test('an adapter whose user model does not map closedAt is refused at start-up, and its resets fail closed', { skip }, async () => {
  const bareSchema = { ...schema, user: bareUser };
  const bareAdapter = (client: unknown) => drizzleAdapter(client as Database, { provider: 'pg', schema: bareSchema });
  const sent: string[] = [];
  const bare = createTen98Auth({ database: bareAdapter(db), transactionDatabase: bareAdapter, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test', sendResetPassword: ({ token }) => { sent.push(token); } });
  await assert.rejects(bare.assertSchema(db), (error: unknown) => error instanceof SchemaMismatchError && /closedAt/.test(error.message));
  const email = address('bare');
  const id = await account_(email);
  await pool!.query('UPDATE "user" SET closed_at = now() WHERE id = $1', [id]);
  const response = await resetRequest(bare, '/request-password-reset', { email, redirectTo: '/' });
  assert.equal(response.status, 500);
  assert.deepEqual([sent.length, await resetRows(id)], [0, 0]);
  // Control: the same app with the runtime's user table passes and refuses the closed account as an unknown email.
  assert.equal(await authOver(db).assertSchema(db), undefined);
});

test('a flood of one valid device cookie that the account step refuses never fills the pool', { skip }, async () => {
  const email = address('claim-flood'), bystander = address('claim-flood');
  await account_(email);
  await account_(bystander);
  const flood = new pg.Pool({ connectionString: url, max: 10 });
  try {
    const floodDb = drizzle(flood, { schema });
    const floodAuth = authOver(floodDb);
    await floodAuth.assertSchema(floodDb);
    const valid = jar().take(await floodAuth.signInWithPassword(floodDb, { source: SOURCE, email, password: PASSWORD }, allow)).header();
    let known = 0;
    const refuseEveryAccount = { source: () => true, account: (attempt: PasswordAttempt) => { if (attempt.knownDevice) known++; return false; } };
    let waiters = 0;
    const sampler = setInterval(() => { waiters = Math.max(waiters, flood.waitingCount); }, 2);
    const until = performance.now() + 1500;
    const workers = Array.from({ length: 200 }, async () => {
      while (performance.now() < until) {
        assert.equal((await floodAuth.signInWithPassword(floodDb, { source: `ip:${randomUUID()}`, email, password: PASSWORD, headers: { cookie: valid } }, refuseEveryAccount)).status, 429);
        await new Promise(resolve => setImmediate(resolve));
      }
    });
    await delay(200);
    const started = performance.now();
    const other = await floodAuth.signInWithPassword(floodDb, { source: `ip:${randomUUID()}`, email: bystander, password: PASSWORD }, allow);
    const waited = performance.now() - started;
    await Promise.all(workers);
    clearInterval(sampler);
    assert.deepEqual([waiters, other.status], [0, 200]);
    assert.ok(waited < 2500, `another user's sign-in took ${waited.toFixed(0)} ms`);
    // The cookie was still recognised while the claims kept within their bound.
    assert.ok(known > 0);
  } finally { await flood.end(); }
});

test('a failed schema check is answered from memory for two seconds, then checked again', { skip }, async () => {
  await pool!.query('CREATE SCHEMA recheck; CREATE TABLE recheck."user" (LIKE public."user" INCLUDING ALL); ALTER TABLE recheck."user" DROP COLUMN closed_at');
  const counted = new pg.Pool({ connectionString: url, max: 2, options: '-c search_path=recheck,public' });
  try {
    let catalogue = 0;
    const query = counted.query.bind(counted) as (...args: unknown[]) => unknown;
    (counted as unknown as { query: (...args: unknown[]) => unknown }).query = (...args: unknown[]) => {
      const text = typeof args[0] === 'string' ? args[0] : (args[0] as { text?: string })?.text;
      if (text?.includes('pg_attribute')) catalogue++;
      return query(...args);
    };
    const countedDb = drizzle(counted, { schema });
    const checked = authOver(countedDb);
    for (let attempt = 0; attempt < 10; attempt++) {
      await assert.rejects(checked.signInWithPassword(countedDb, { source: SOURCE, email: address('recheck'), password: PASSWORD }, allow), SchemaMismatchError);
    }
    assert.equal(catalogue, 1);
    await delay(2100);
    await assert.rejects(checked.assertSchema(countedDb), SchemaMismatchError);
    assert.equal(catalogue, 2);
  } finally { await counted.end(); }
});

test('closedAt can be neither set by a client nor read from a response', { skip }, async () => {
  const email = address('closed-field');
  const id = await account_(email);
  const signedIn = await signIn(email);
  assert.equal(signedIn.status, 200);
  assert.equal('closedAt' in ((await signedIn.clone().json()) as { user: Record<string, unknown> }).user, false);
  const cookie = cookieOf(signedIn);
  const session = await auth.handler(new Request(`${ORIGIN}/api/auth/get-session`, { headers: { cookie } }));
  assert.equal('closedAt' in ((await session.json()) as { user: Record<string, unknown> }).user, false);
  const update = await auth.handler(new Request(`${ORIGIN}/api/auth/update-user`, {
    method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN, cookie }, body: JSON.stringify({ closedAt: new Date().toISOString() }),
  }));
  assert.equal(update.ok, false);
  assert.equal((await pool!.query<{ closed: Date | null }>('SELECT closed_at AS closed FROM "user" WHERE id = $1', [id])).rows[0]!.closed, null);
});

test('every limiter refusal answers 429 with Retry-After: the step\'s own wait, or 60 seconds', { skip }, async () => {
  const email = address('retry-after');
  await account_(email);
  const refusedWith = async (limits: Parameters<Ten98Auth['signInWithPassword']>[2]) => {
    const response = await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, limits);
    return [response.status, response.headers.get('retry-after')];
  };
  assert.deepEqual(await refusedWith({ source: () => ({ retryAfterSeconds: 120 }), account: () => true }), [429, '120']);
  assert.deepEqual(await refusedWith({ source: () => true, account: () => ({ retryAfterSeconds: 30 }) }), [429, '30']);
  assert.deepEqual(await refusedWith({ source: async () => ({ retryAfterSeconds: 86_400 }), account: () => true }), [429, '86400']);
  assert.deepEqual(await refusedWith({ source: () => false, account: () => true }), [429, '60']);
  assert.deepEqual(await refusedWith({ source: () => true, account: () => false }), [429, '60']);
  // Out of range, not an integer or not a number: still refused, with the default wait.
  for (const retryAfterSeconds of [0, 86_401, 1.5, -5, '30', Number.NaN] as unknown as number[]) {
    assert.deepEqual(await refusedWith({ source: () => ({ retryAfterSeconds }), account: () => true }), [429, '60'], String(retryAfterSeconds));
    assert.deepEqual(await refusedWith({ source: () => true, account: () => ({ retryAfterSeconds }) }), [429, '60'], String(retryAfterSeconds));
  }
  assert.equal((await auth.signInWithPassword(db, { source: SOURCE, email, password: PASSWORD }, allow)).status, 200);
});

test('the server calls of the routes the preset turns off throw, naming what to use, on the held and the bound instance', { skip }, async () => {
  const id = await account_(address('off-calls'));
  const calls = (target: { api: unknown }) => target.api as unknown as Record<'unlinkAccount' | 'listUserAccounts', (input?: unknown) => unknown>;
  assert.throws(() => calls(auth).unlinkAccount({ body: { providerId: 'credential' }, headers: {} }), (error: unknown) => error instanceof TypeError && /unlinkOidcIdentity/.test(error.message));
  assert.throws(() => calls(auth).listUserAccounts({ headers: {} }), (error: unknown) => error instanceof TypeError && /account table/.test(error.message));
  await auth.withLockedAuth(db, id, async bound => {
    assert.throws(() => calls(bound).unlinkAccount({ body: { providerId: 'credential' }, headers: {} }), TypeError);
    assert.throws(() => calls(bound).listUserAccounts({ headers: {} }), TypeError);
  });
  assert.equal((await pool!.query('SELECT 1 FROM account WHERE "userId"=$1 AND "providerId"=\'credential\'', [id])).rowCount, 1);
});

test('only a strict true from isAccountUsable or isIssuerUsable counts as usable', { skip }, async () => {
  const user = await account_(address('truthy'));
  for (const answer of [1, 'yes', {}, [], 'true']) {
    const lenient = authOver(db, { isAccountUsable: () => answer as never });
    assert.equal((await providerSignIn(user, 'idp', lenient)).status, 401, JSON.stringify(answer));
  }
  assert.equal(await sessions(user), 0);
  const id = await account_(address('truthy-issuer'), { hash: null });
  const identity = { issuer: ISSUER, subject: subject() }, other = { issuer: 'https://other.example.com', subject: subject() };
  await auth.withLockedAuth(db, id, (_bound, tx) => linkOidcIdentity(tx, identity));
  await auth.withLockedAuth(db, id, (_bound, tx) => linkOidcIdentity(tx, other));
  for (const answer of [1, 'yes', {}, [], 'true']) {
    await assert.rejects(auth.withLockedAuth(db, id, (_bound, tx) => unlinkOidcIdentity(tx, identity, { isIssuerUsable: () => answer as never })), refusedWith('OIDC_LAST_SIGN_IN_METHOD'), JSON.stringify(answer));
  }
  await auth.withLockedAuth(db, id, (_bound, tx) => unlinkOidcIdentity(tx, identity, { isIssuerUsable: () => true }));
  assert.deepEqual((await identitiesOf(id)).length, 1);
});

test('a revocation pass a deadlock keeps aborting is retried a bounded number of times, then the error is thrown', { skip }, async () => {
  const failing = new pg.Pool({ connectionString: url, max: 2 });
  let aborted = 0;
  const connect = failing.connect.bind(failing) as () => Promise<pg.PoolClient>;
  (failing as unknown as { connect: () => Promise<pg.PoolClient> }).connect = async () => {
    const client = await connect();
    const query = client.query.bind(client) as (...args: unknown[]) => unknown;
    (client as unknown as { query: (...args: unknown[]) => unknown }).query = (...args: unknown[]) => {
      const text = typeof args[0] === 'string' ? args[0] : (args[0] as { text?: string })?.text;
      // Every pass aborts as a deadlock victim, up to 20 times; past that a pass would succeed.
      if (text?.includes('WITH bound AS') && aborted < 20) { aborted++; return Promise.reject(Object.assign(new Error('deadlock detected'), { code: '40P01' })); }
      return query(...args);
    };
    return client;
  };
  try {
    await assert.rejects(revokeProviderSessions(drizzle(failing, { schema }), 'deadlocked'), (error: unknown) => [error, (error as { cause?: unknown }).cause].some(item => (item as { code?: string } | null)?.code === '40P01'));
    assert.equal(aborted, 5);
  } finally { await failing.end(); }
});

test('a session with a stale challenge cookie of another account leaves that challenge\'s binding alone', { skip }, async () => {
  // The raw instance routes session-bound verification itself; the guard keeps a challenge cookie from binding it.
  const raw = authOver(db, { allowRawPasswordSignIn: true });
  const factor = await challenged('stale-holder');
  const stale = cookieOf(await providerSignIn(factor.id, 'p-stale'));
  const bindings = async () => (await pool!.query('SELECT 1 FROM verification WHERE starts_with(identifier, \'oidc-challenge:\') AND value=\'p-stale\'')).rowCount;
  assert.equal(await bindings(), 1);
  const email = address('stale-session');
  const id = await account_(email);
  const session = cookieOf(await signIn(email));
  const { totpURI } = await (await raw.handler(post('/two-factor/enable', session, { password: PASSWORD }))).json() as { totpURI: string };
  const enrolled = await raw.handler(post('/two-factor/verify-totp', `${session}; ${stale}`, { code: totp(totpURI) }));
  assert.equal(enrolled.status, 200);
  assert.equal(await bindings(), 1);
  const providers = (await pool!.query<{ provider: string | null }>('SELECT "oidcProvider" AS provider FROM session WHERE "userId"=$1', [id])).rows.map(row => row.provider);
  assert.deepEqual(providers, [null]);
});

test('two concurrent invitation acceptances with one identity: the second waits on the first and is refused', { skip }, async () => {
  // Two workspaces, so the acceptances share no workspace or invitation lock and meet only at the identity insert.
  const invite = async (email: string) => {
    const owner = await account_(address('race-owner'));
    const workspace = await workspaceOf(owner);
    return inTransaction(async client => team.inviteMember(client, workspace, owner, { email, role: 'viewer' }));
  };
  const [first, second] = [address('race-one'), address('race-two')];
  const [one, two] = [await invite(first), await invite(second)];
  const identity = { issuer: ISSUER, subject: subject() };
  const [a, b] = [await pool!.connect(), await pool!.connect()];
  try {
    await a.query('BEGIN');
    await b.query('BEGIN');
    await team.acceptVerifiedOidcInvitation(a as unknown as TeamClient, one.token, { email: first, name: 'One', ...identity });
    // Its pre-check cannot see the first's uncommitted identity, so it reaches the insert and waits there.
    const racing = team.acceptVerifiedOidcInvitation(b as unknown as TeamClient, two.token, { email: second, name: 'Two', ...identity })
      .then(() => 'accepted', (error: { code?: string }) => error.code);
    await delay(200);
    await a.query('COMMIT');
    assert.equal(await racing, 'OIDC_IDENTITY_IN_USE');
    await b.query('ROLLBACK');
  } finally { a.release(); b.release(); }
  assert.deepEqual([await usersAt(first), await usersAt(second)], [1, 0]);
});
