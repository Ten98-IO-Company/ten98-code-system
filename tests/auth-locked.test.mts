import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { hashPassword } from 'better-auth/crypto';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { boolean, integer, pgTable, text, timestamp } from 'drizzle-orm/pg-core';
import pg from 'pg';
import { createTen98Auth, LockedAuthTransactionError, LockedAuthUserNotFoundError, tokenStorageUpgradeStatements } from '../auth.mjs';
import type { Ten98Auth } from '../auth.mjs';
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
  INSERT INTO installation VALUES (1, NULL);`;

type Database = ReturnType<typeof drizzle<typeof schema>>;
let pool: pg.Pool | undefined;
let db: Database;
let auth: Ten98Auth;
let database = '';
let url = '';
let hashes: { old: string; new: string };
const team = createWorkspaceTeam({ hashPassword });
const tenancy = createTenancy({ setting: 'app.workspace_ids', column: 'workspace_id', tables: ['workspace_invitation'] });
const adapterOver = (client: unknown) => drizzleAdapter(client as Database, { provider: 'pg', schema });
const authOver = (target: Database) => createTen98Auth({ database: adapterOver(target), transactionDatabase: adapterOver, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test' });

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
  pool = new pg.Pool({ connectionString: url, max: 6 });
  await pool.query(readFileSync(new URL('../workspace-team.sql', import.meta.url), 'utf8'));
  await pool.query(betterAuthTables);
  db = drizzle(pool, { schema });
  auth = authOver(db);
  hashes = { old: await hashPassword(PASSWORD), new: await hashPassword(NEW_PASSWORD) };
});
test.after(async () => {
  if (!admin || !pool) return;
  await pool.end();
  const root = new pg.Client({ connectionString: admin });
  await root.connect();
  await root.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
  await root.end();
});

async function account_(email: string, { twoFactor: enabled = false } = {}) {
  const id = randomUUID();
  await pool!.query('INSERT INTO "user"(id,name,email,"twoFactorEnabled") VALUES($1,$2,$3,$4)', [id, 'Test', email, enabled]);
  await pool!.query('INSERT INTO account(id,"accountId","providerId","userId",password) VALUES($1,$2,\'credential\',$2,$3)', [randomUUID(), id, hashes.old]);
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
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  return false;
}
async function inTransaction<T>(run: (client: TeamClient) => Promise<T>, held?: Promise<void>): Promise<T> {
  const client = await pool!.connect();
  try {
    await client.query('BEGIN');
    const result = await run(client as unknown as TeamClient);
    await held;
    await client.query('COMMIT');
    return result;
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}
async function workspaceOf(owner: string) {
  const { workspace } = await inTransaction(client => team.createWorkspace(client, owner, { name: 'Acme' }));
  return workspace.id;
}
type ChangePassword = { changePassword(input: { body: Record<string, unknown>; headers: HeadersInit; asResponse: true }): Promise<Response> };

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
  const resetting = createTen98Auth({ database: adapterOver(db), transactionDatabase: adapterOver, appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test', sendResetPassword: ({ token }) => { resets.push(token); } });
  await resetting.withLockedAuthByEmail(db, email, bound => (bound.api as unknown as { requestPasswordReset(input: { body: { email: string; redirectTo: string } }): Promise<unknown> }).requestPasswordReset({ body: { email, redirectTo: '/' } }));
  const identifiers = (await pool!.query<{ identifier: string }>('SELECT identifier FROM verification WHERE value=$1', [id])).rows.map(row => row.identifier);
  assert.deepEqual(identifiers, [resetting.storedVerificationIdentifier(`reset-password:${resets[0]}`)]);
});

test('an old-password sign-in cannot create a session once a CLI reset holds the user', { skip }, async () => {
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
  const oldPassword = auth.withLockedAuthByEmail(db, email, bound => bound.api.signInEmail({ body: { email, password: PASSWORD }, asResponse: true }));
  assert.equal(await someoneWaits(), true);
  held.open();
  await reset;
  assert.equal((await oldPassword).status, 401);
  assert.equal(await sessions(id), 0);
  assert.equal((await signIn(email, NEW_PASSWORD)).status, 200);
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
  const email = address('kill');
  const id = await account_(email);
  await assert.rejects(auth.withLockedAuth(db, id, async (bound, tx) => {
    await setPassword(tx, id);
    assert.equal((await bound.api.signInEmail({ body: { email, password: NEW_PASSWORD }, asResponse: true })).status, 200);
    const { rows } = await tx.execute(sql`SELECT pg_backend_pid() AS pid`) as unknown as { rows: { pid: number }[] };
    await pool!.query('SELECT pg_terminate_backend($1)', [rows[0]!.pid]);
    await tx.execute(sql`SELECT 1`);
  }));
  assert.equal(await storedPassword(id), hashes.old);
  assert.equal(await sessions(id), 0);
  const failure = new Error('the callback failed');
  await assert.rejects(auth.withLockedAuth(db, id, async (bound, tx) => {
    await setPassword(tx, id);
    assert.equal((await bound.api.signInEmail({ body: { email, password: NEW_PASSWORD }, asResponse: true })).status, 200);
    throw failure;
  }), error => error === failure);
  assert.equal(await storedPassword(id), hashes.old);
  assert.equal(await sessions(id), 0);
});

test('tenancy helpers and workspace team operations refuse a locked-auth transaction, and only that one', { skip }, async () => {
  const email = address('refuse');
  const id = await account_(email);
  const workspaceId = await workspaceOf(id);
  // One connection, so the unmarked transactions below run on the connection the locked one used.
  const single = new pg.Pool({ connectionString: url, max: 1 });
  const singleDb = drizzle(single, { schema });
  try {
    const refused = (error: unknown) => error instanceof LockedAuthTransactionError && error.code === 'LOCKED_AUTH_TRANSACTION';
    await auth.withLockedAuth(singleDb, id, async (_bound, tx) => {
      await assert.rejects(tenancy.withWorkspace(tx, id, workspaceId, 'read', async () => 1), refused);
      await assert.rejects(tenancy.withWorkspace(singleDb, id, workspaceId, 'write', async () => 1, tx), refused);
      await assert.rejects(tenancy.withWorkspaces(tx, id, [workspaceId], async () => 1), refused);
      await assert.rejects(tx.transaction(inner => tenancy.withWorkspace(inner, id, workspaceId, 'read', async () => 1)), refused);
      const client = (tx as unknown as { _: { session: { client: TeamClient } } })._.session.client;
      await assert.rejects(team.getTeam(client, workspaceId, id), refused);
      await assert.rejects(team.setTwoFactorRequirement(client, workspaceId, id, { required: false }), refused);
      await assert.rejects(team.acceptInvitation(client, { token: 'x'.repeat(43) }), refused);
      await assert.rejects(team.memberNeedsFactor(client, workspaceId, id), refused);
      // The email lock is the same advisory lock the transaction already holds for sign-in flows.
      await team.lockEmail(client, email);
    });
    assert.equal(await transaction(singleDb, tx => tenancy.withWorkspace(tx, id, workspaceId, 'read', async (_tx, access) => access.role)), 'owner');
    assert.equal(await tenancy.withWorkspace(singleDb, id, workspaceId, 'read', async (_tx, access) => access.role), 'owner');
    const client = await single.connect();
    try {
      await client.query('BEGIN');
      assert.equal((await team.getTeam(client as unknown as TeamClient, workspaceId, id)).role, 'owner');
      await client.query('COMMIT');
    } finally { client.release(); }
  } finally { await single.end(); }
});

test('withLockedAuth refuses a missing user, a transaction and a missing binding; by email it runs without an account', { skip }, async () => {
  await assert.rejects(auth.withLockedAuth(db, randomUUID(), async () => 1), error => error instanceof LockedAuthUserNotFoundError && error.status === 404);
  const id = await account_(address('refusals'));
  await assert.rejects(transaction(db, tx => auth.withLockedAuth(tx as unknown as Database, id, async () => 1)), TypeError);
  const unbound = createTen98Auth({ database: adapterOver(db), appUrl: ORIGIN, secret: SECRET, appName: 'Ten98 Test' });
  await assert.rejects(unbound.withLockedAuth(db, id, async () => 1), /transactionDatabase/);
  const email = address('nobody');
  const result = await auth.withLockedAuthByEmail(db, email, async (bound, _tx, userId) => {
    await bound.revokeAllSessions();
    return { userId, status: (await bound.api.signInEmail({ body: { email, password: PASSWORD }, asResponse: true })).status };
  });
  assert.deepEqual(result, { userId: undefined, status: 401 });
});

test('acceptInvitation and withLockedAuthByEmail on the same email wait for each other in either order', { skip }, async () => {
  const owner = await account_(address('owner'));
  const workspaceId = await workspaceOf(owner);
  const invite = async (email: string) => (await inTransaction(client => team.inviteMember(client, workspaceId, owner, { email, role: 'editor' }))).token;
  // The sign-in holds the email lock and the user row; the acceptance queues on the email lock.
  const first = address('invitee');
  const firstId = await account_(first);
  const firstToken = await invite(first);
  const held = gate(), entered = gate();
  const signedIn = auth.withLockedAuthByEmail(db, first, async bound => {
    const response = await bound.api.signInEmail({ body: { email: first, password: PASSWORD }, asResponse: true });
    entered.open();
    await held.opened;
    return response.status;
  });
  await entered.opened;
  const accepted = inTransaction(client => team.acceptInvitation(client, { token: firstToken }, { id: firstId, email: first }));
  assert.equal(await someoneWaits(), true);
  held.open();
  assert.equal(await signedIn, 200);
  assert.equal((await accepted).joined, true);
  // The acceptance holds workspace, invitation and email locks; the sign-in queues on the email lock.
  const second = address('invitee');
  const secondId = await account_(second);
  const secondToken = await invite(second);
  const release = gate(), locked = gate();
  const acceptedFirst = inTransaction(async client => {
    const result = await team.acceptInvitation(client, { token: secondToken }, { id: secondId, email: second });
    locked.open();
    return result;
  }, release.opened);
  await locked.opened;
  const signedInAfter = auth.withLockedAuthByEmail(db, second, bound => bound.api.signInEmail({ body: { email: second, password: PASSWORD }, asResponse: true }));
  assert.equal(await someoneWaits(), true);
  release.open();
  assert.equal((await acceptedFirst).joined, true);
  assert.equal((await signedInAfter).status, 200);
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
  // The requirement holds the owner's row FOR SHARE; the locked change's first statement queues behind it.
  const release = gate(), locked = gate();
  const requiredFirst = inTransaction(async client => { const result = await team.setTwoFactorRequirement(client, workspaceId, owner, { required: true }); locked.open(); return result; }, release.opened);
  await locked.opened;
  const changeAfter = auth.withLockedAuth(db, owner, async (_bound, tx) => { await setPassword(tx, owner); return 'changed'; });
  assert.equal(await someoneWaits(), true);
  release.open();
  assert.deepEqual(await requiredFirst, { twoFactorRequired: true });
  assert.equal(await changeAfter, 'changed');
});

test('first-user setup (installation row, then the email lock) makes a sign-in by email wait, then succeed', { skip }, async () => {
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
  const signedIn = auth.withLockedAuthByEmail(db, email, async (bound, _tx, found) => ({ found, status: (await bound.api.signInEmail({ body: { email, password: PASSWORD }, asResponse: true })).status }));
  assert.equal(await someoneWaits(), true);
  release.open();
  await setup;
  assert.deepEqual(await signedIn, { found: userId, status: 200 });
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
