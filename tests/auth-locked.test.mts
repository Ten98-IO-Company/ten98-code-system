import assert from 'node:assert/strict';
import { randomBytes, randomUUID, scryptSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import test from 'node:test';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { hashPassword } from 'better-auth/crypto';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { boolean, integer, pgTable, text, timestamp } from 'drizzle-orm/pg-core';
import pg from 'pg';
import { createTen98Auth, LockedAuthClosedError, LockedAuthTransactionError, LockedAuthUserNotFoundError, tokenStorageUpgradeStatements } from '../auth.mjs';
import type { Ten98Auth, Ten98AuthOptions } from '../auth.mjs';
import { transaction, user } from '../db.mjs';
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

// better-auth's tables for the preset (core plus the two-factor plugin), over workspace-team.sql's user and account.
const stamp = (name: string) => timestamp(name, { withTimezone: true });
const session = pgTable('session', {
  id: text('id').primaryKey(), expiresAt: stamp('expiresAt').notNull(), token: text('token').notNull(), createdAt: stamp('createdAt').notNull(),
  updatedAt: stamp('updatedAt').notNull(), ipAddress: text('ipAddress'), userAgent: text('userAgent'), userId: text('userId').notNull(),
});
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
  CREATE TABLE session (id text PRIMARY KEY, "expiresAt" timestamptz NOT NULL, token text NOT NULL UNIQUE, "createdAt" timestamptz NOT NULL,
    "updatedAt" timestamptz NOT NULL, "ipAddress" text, "userAgent" text, "userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE);
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
let hashes: { old: string; new: string; legacy: string };
const team = createWorkspaceTeam({ hashPassword });
const tenancy = createTenancy({ setting: 'app.workspace_ids', column: 'workspace_id', tables: ['workspace_invitation'] });
const adapterOver = (client: unknown) => drizzleAdapter(client as Database, { provider: 'pg', schema });
const authOver = (target: Database, options: Partial<Ten98AuthOptions> = {}) =>
  createTen98Auth({ database: adapterOver(target), transactionDatabase: adapterOver, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test', ...options });
const allow = () => true;

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
const signIn = (email: string, password = PASSWORD) => auth.handler(new Request(`${ORIGIN}/api/auth/sign-in/email`, {
  method: 'POST', headers: { 'content-type': 'application/json', origin: ORIGIN }, body: JSON.stringify({ email, password }),
}));
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
const oidcSession = (bound: { api: Ten98Auth['api'] }, userId: string) => bound.api.completeOidcSession({ body: { oidcUserId: userId }, headers: {}, asResponse: true });
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
  const oldPassword = auth.signInWithPassword(db, { email, password: PASSWORD }, allow);
  assert.equal(await someoneWaits(), true);
  held.open();
  await reset;
  assert.deepEqual(await answer(await oldPassword), await answer(await auth.signInWithPassword(db, { email: address('unknown'), password: PASSWORD }, allow)));
  assert.equal(await sessions(id), 0);
  const signedIn = await auth.signInWithPassword(db, { email, password: NEW_PASSWORD }, allow);
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
    // Not awaited: it runs after the callback has returned.
    late = delay(50).then(() => oidcSession(bound, id));
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
    assert.equal(await within(auth.signInWithPassword(db, { email, password: PASSWORD }, allow).then(() => 'ran', error => refused(error) ? 'refused' : String(error)), 3000), 'refused');
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
  assert.equal((await auth.signInWithPassword(db, { email, password: PASSWORD }, allow)).status, 200);
});

test('signInWithPassword: limit first, one uniform failure, and a session only for the right password', { skip }, async () => {
  const email = address('password');
  const id = await account_(email);
  const passwordless = address('passwordless');
  await account_(passwordless, { hash: null });
  // The limit runs before the credential read (and so before any hash); refused, nothing is read.
  const order: string[] = [];
  const watched = new Proxy(db, { get(target, key, receiver) { if (key === 'select') order.push('read'); return Reflect.get(target, key, receiver); } });
  const limited = await auth.signInWithPassword(watched, { email, password: PASSWORD }, attempt => { order.push(`limit:${attempt.email}`); return false; });
  assert.deepEqual([limited.status, order], [429, [`limit:${email}`]]);
  assert.equal((await auth.signInWithPassword(watched, { email: ` ${email.toUpperCase()} `, password: 'wrong password guess' }, attempt => { order.push(`limit:${attempt.email}`); return true; })).status, 401);
  assert.deepEqual(order.slice(1), [`limit:${email}`, 'read']);
  // Anything but true refuses: a limiter that forgets to return is not an allowance.
  assert.equal((await auth.signInWithPassword(db, { email, password: PASSWORD }, (() => undefined) as unknown as () => boolean)).status, 429);
  // Unknown email, wrong password and an account without a password answer identically.
  const unknown = await answer(await auth.signInWithPassword(db, { email: address('nobody'), password: PASSWORD }, allow));
  assert.equal(unknown.status, 401);
  assert.deepEqual(await answer(await auth.signInWithPassword(db, { email, password: 'wrong password guess' }, allow)), unknown);
  assert.deepEqual(await answer(await auth.signInWithPassword(db, { email: passwordless, password: PASSWORD }, allow)), unknown);
  assert.equal(await sessions(id), 0);
  const signedIn = await auth.signInWithPassword(db, { email, password: PASSWORD, headers: { 'user-agent': 'fixture-agent' } }, allow);
  assert.equal(signedIn.status, 200);
  assert.equal((await auth.api.getSession({ headers: { cookie: cookieOf(signedIn) } }))?.user.id, id);
  assert.equal((await pool!.query<{ agent: string }>('SELECT "userAgent" AS agent FROM session WHERE "userId"=$1', [id])).rows[0]!.agent, 'fixture-agent');
  assert.equal((await auth.signInWithPassword(db, { email, password: 1 as unknown as string }, allow)).status, 400);
  // A cross-site browser request is refused before the limit counts it; the app's own origin goes ahead.
  let counted = 0;
  const counting = () => { counted++; return true; };
  for (const headers of [{ origin: 'https://evil.example' }, { 'sec-fetch-site': 'cross-site' }, { origin: ORIGIN, 'sec-fetch-site': 'same-site' }] as Record<string, string>[]) {
    assert.equal((await auth.signInWithPassword(db, { email, password: PASSWORD, headers }, counting)).status, 403, JSON.stringify(headers));
  }
  assert.equal(counted, 0);
  assert.equal((await auth.signInWithPassword(db, { email, password: PASSWORD, headers: { origin: ORIGIN, 'sec-fetch-site': 'same-origin' } }, counting)).status, 200);
  // A password over the policy's maximum is wrong for every account: the same 401, without a derivation.
  const started = performance.now();
  assert.deepEqual(await answer(await auth.signInWithPassword(db, { email, password: 'x'.repeat(129) }, allow)), unknown);
  assert.ok(performance.now() - started < 100);
});

test('signInWithPassword costs the same for unknown, current, legacy and passwordless accounts', { skip }, async () => {
  const current = address('timing'), legacy = address('timing'), none = address('timing');
  await account_(current);
  await account_(legacy, { hash: hashes.legacy });
  await account_(none, { hash: null });
  // Wall time and process CPU time (all threads, so both scrypt derivations count): the two run in parallel, so a
  // skipped dummy derivation shows in the work done even where the slower one hides it from the latency.
  const median = async (email: string) => {
    const times: number[] = [], work: number[] = [];
    for (let attempt = 0; attempt < 7; attempt++) {
      const started = performance.now(), cpu = process.cpuUsage();
      assert.equal((await auth.signInWithPassword(db, { email, password: 'wrong password guess' }, allow)).status, 401);
      const used = process.cpuUsage(cpu);
      times.push(performance.now() - started);
      work.push((used.user + used.system) / 1000);
    }
    return [times.sort((a, b) => a - b)[3]!, work.sort((a, b) => a - b)[3]!] as const;
  };
  await median(address('warm'));
  const medians = [await median(address('nobody')), await median(current), await median(legacy), await median(none)];
  const spread = (values: number[]) => Math.max(...values) / Math.min(...values);
  const shown = medians.map(([time, cpu]) => `${time.toFixed(0)} ms, ${cpu.toFixed(0)} ms CPU`).join(' / ');
  assert.ok(spread(medians.map(([time]) => time)) < 1.6, shown);
  assert.ok(spread(medians.map(([, cpu]) => cpu)) < 1.25, shown);
});

test('signInWithPassword answers 503 when the verification bound is reached, never waiting past it', { skip }, async () => {
  const email = address('bound');
  await account_(email);
  const guess = (target: Ten98Auth) => target.signInWithPassword(db, { email, password: 'wrong password guess' }, allow).then(response => response.status);
  const single = authOver(db, { passwordVerification: { concurrency: 1, queue: 0 } });
  assert.deepEqual((await Promise.all([guess(single), guess(single)])).sort(), [401, 503]);
  const brief = authOver(db, { passwordVerification: { concurrency: 1, queue: 1, waitMs: 1 } });
  assert.deepEqual((await Promise.all([guess(brief), guess(brief), guess(brief)])).sort(), [401, 503, 503]);
  const busy = await single.signInWithPassword(db, { email, password: 'x' }, allow);
  assert.equal(busy.status, 401);
});

test('signInWithPassword replaces a legacy hash once, under the lock, however many sign-ins race', { skip }, async () => {
  const email = address('legacy');
  const id = await account_(email, { hash: hashes.legacy });
  const legacyAuth = authOver(db, { legacyPasswords: true });
  const outcomes = await Promise.all(Array.from({ length: 3 }, () => legacyAuth.signInWithPassword(db, { email, password: PASSWORD }, allow).then(response => response.status)));
  assert.deepEqual(outcomes, [200, 200, 200]);
  assert.equal((await pool!.query('SELECT 1 FROM password_writes WHERE user_id=$1', [id])).rowCount, 1);
  assert.equal((await storedPassword(id)).startsWith('scrypt$'), false);
  assert.equal(await sessions(id), 3);
  // Without the option a legacy hash never verifies, on either check.
  const strictEmail = address('strict');
  await account_(strictEmail, { hash: hashes.legacy });
  assert.equal((await auth.signInWithPassword(db, { email: strictEmail, password: PASSWORD }, allow)).status, 401);
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
    const attempts = Array.from({ length: 60 }, () => floodAuth.signInWithPassword(floodDb, { email, password: 'wrong password guess' }, limit)
      .then(response => String(response.status), (error: Error) => `error: ${error.message}`));
    await delay(300);
    const started = performance.now();
    await flood.query('SELECT 1');
    const probe = performance.now() - started;
    const outcomes = await Promise.all(attempts);
    const tally = (value: string) => outcomes.filter(outcome => outcome === value).length;
    assert.deepEqual([tally('401'), tally('429'), outcomes.filter(outcome => outcome.startsWith('error')).length], [50, 10, 0], [...new Set(outcomes)].join(', '));
    assert.ok(probe < 1000, `another request waited ${probe.toFixed(0)} ms for a connection`);
  } finally { await flood.end(); }
});

test('the published upgrade statements end plain sessions and better-auth verification rows only', { skip }, async () => {
  const id = await account_(address('upgrade'));
  await pool!.query('INSERT INTO session(id,"expiresAt",token,"createdAt","updatedAt","userId") VALUES($1,now()+interval \'1 day\',$2,now(),now(),$3)', [randomUUID(), 'plainsessiontoken', id]);
  const identifiers = ['reset-password:abc', 'trust-device-abc', '2fa-abc', '2fa-otp-abc', '2fa-attempts-2fa-abc', 'totp-used:user:digest', 'other-row'];
  for (const identifier of identifiers) await pool!.query('INSERT INTO verification(id,identifier,value,"expiresAt") VALUES($1,$2,$3,now()+interval \'1 hour\')', [randomUUID(), identifier, id]);
  await pool!.query(tokenStorageUpgradeStatements);
  assert.equal((await pool!.query('SELECT 1 FROM session')).rowCount, 0);
  const left = (await pool!.query<{ identifier: string }>('SELECT identifier FROM verification WHERE value=$1 ORDER BY identifier', [id])).rows.map(row => row.identifier);
  assert.deepEqual(left, ['other-row', 'totp-used:user:digest']);
  // The adoption guide publishes exactly these statements.
  assert.ok(readFileSync(new URL('../docs/FEATURE-ADOPTION.md', import.meta.url), 'utf8').includes(tokenStorageUpgradeStatements));
});
