import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { eq, sql, type SQL } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { getTableConfig, PgDialect, pgTable, serial, text } from 'drizzle-orm/pg-core';
import pg from 'pg';
import { createPool, teamSchema, transaction } from '../db.mjs';
import { createTenancy, DatabaseRoleError, InvalidWorkspaceIdError, UnlockedScopeError, WorkspaceAccessError, workspaceNotFound } from '../tenancy.mjs';
import * as tenancyTesting from '../tenancy-testing.mjs';

const tenancy = createTenancy({ setting: 'app.workspace_ids', column: 'workspace_id', tables: ['note'] });
const scopeText = "workspace_id = ANY (string_to_array(current_setting('app.workspace_ids', true), ','))";
const note = pgTable('note', { id: serial('id').primaryKey(), workspaceId: text('workspace_id').notNull(), body: text('body').notNull() },
  () => [tenancy.policy('note_scope')]).enableRLS();
const render = (value: SQL | undefined) => new PgDialect().sqlToQuery(value!).sql;

test('policy() scopes every command and role to the configured setting and column, USING and WITH CHECK', () => {
  const [policy] = getTableConfig(note).policies;
  assert.deepEqual([policy!.name, policy!.as, policy!.for, policy!.to, render(policy!.using), render(policy!.withCheck)],
    ['note_scope', 'permissive', 'all', 'public', scopeText, scopeText]);
  assert.equal(getTableConfig(note).enableRLS, true);
  const books = createTenancy({ setting: 'app.company_ids', column: 'company_id', tables: ['company'] });
  assert.equal(render(books.policy('company_scope').using), "company_id = ANY (string_to_array(current_setting('app.company_ids', true), ','))");
});

test('createTenancy refuses names that are not safe lowercase identifiers', () => {
  const valid = { setting: 'app.workspace_ids', column: 'workspace_id', tables: ['note'] };
  for (const setting of ["app.ids', true) OR true --", 'workspace_ids', 'App.ids', 'app.', 'app.ids;', '']) {
    assert.throws(() => createTenancy({ ...valid, setting }), TypeError, setting);
  }
  for (const column of ['workspace_id OR true', 'Workspace_ID', '"workspace_id"', '1column', '']) {
    assert.throws(() => createTenancy({ ...valid, column }), TypeError, column);
  }
  for (const tables of [[], ['note"; DROP TABLE x; --'], ['Note'], ['public.note']]) {
    assert.throws(() => createTenancy({ ...valid, tables }), TypeError, String(tables));
  }
});

test('forceRowLevelSecurity() writes one FORCE statement per table with drizzle-kit breakpoints', () => {
  assert.equal(createTenancy({ setting: 'app.company_ids', column: 'company_id', tables: ['company', 'ledger', 'voucher_line'] }).forceRowLevelSecurity(),
    'ALTER TABLE "company" FORCE ROW LEVEL SECURITY;\n--> statement-breakpoint\nALTER TABLE "ledger" FORCE ROW LEVEL SECURITY;\n--> statement-breakpoint\nALTER TABLE "voucher_line" FORCE ROW LEVEL SECURITY;');
});

// A pool that hands out one scripted connection, so a failing BEGIN or ROLLBACK needs no real server. Drizzle treats a
// client as a pool by its constructor's name, as it does pg's Pool.
// A pg Pool stand-in: `totalCount` is how the runtime recognises a pool, so a minified class name still counts.
class ScriptedPool {
  readonly sent: string[] = [];
  readonly released: unknown[] = [];
  readonly connections: EventEmitter[] = [];
  readonly totalCount = 0;
  readonly fail: Partial<Record<'begin' | 'rollback' | 'commit', Error>>;
  constructor(fail: Partial<Record<'begin' | 'rollback' | 'commit', Error>>) { this.fail = fail; }
  async connect() {
    const connection = Object.assign(new EventEmitter(), {
      query: async (config: string | { text: string }) => {
        const text = typeof config === 'string' ? config : config.text;
        this.sent.push(text.split(/\s/u)[0]!.toLowerCase());
        const failure = this.fail[text as 'begin' | 'rollback' | 'commit'];
        if (failure) throw failure;
        // The membership query, in Drizzle's array row mode: workspace id, name, role.
        return { rows: text.startsWith('select "workspace"') ? [[fakeWorkspace, 'W', 'owner']] : [], fields: [], command: 'SELECT', rowCount: 0 };
      },
      release: (destroy?: unknown) => { this.released.push(destroy); },
    });
    this.connections.push(connection);
    return connection;
  }
}
const fakeWorkspace = '00000000-0000-4000-8000-000000000001';

test('a scoped transaction releases its connection when BEGIN fails, and discards it', async () => {
  const lost = new Error('connection reset during BEGIN');
  for (const call of [
    (db: ReturnType<typeof drizzle>) => tenancy.withWorkspace(db, 'u', fakeWorkspace, 'read', async () => 'unreached'),
    (db: ReturnType<typeof drizzle>) => tenancy.withWorkspaces(db, 'u', [fakeWorkspace], async () => 'unreached'),
  ]) {
    const pool = new ScriptedPool({ begin: lost });
    await assert.rejects(call(drizzle(pool as never)), error => error === lost || (error as { cause?: unknown }).cause === lost);
    // Drizzle 0.45.2 alone leaves the connection checked out here: `released` stays empty.
    assert.deepEqual(pool.released, [true]);
  }
});

test('a failed ROLLBACK neither hides the callback\'s error nor returns the connection to the pool', async () => {
  const original = new Error('the callback failed'), pool = new ScriptedPool({ rollback: new Error('rollback failed') });
  await assert.rejects(tenancy.withWorkspace(drizzle(pool as never), 'u', fakeWorkspace, 'write', async () => { throw original; }), error => error === original);
  assert.deepEqual([pool.sent, pool.released], [['begin', 'select', 'select', 'rollback'], [true]]);
  // A callback error with a working ROLLBACK keeps the connection; so does a commit.
  const kept = new ScriptedPool({});
  await assert.rejects(tenancy.withWorkspace(drizzle(kept as never), 'u', fakeWorkspace, 'write', async () => { throw original; }), error => error === original);
  assert.equal(await tenancy.withWorkspace(drizzle(kept as never), 'u', fakeWorkspace, 'write', async (_tx, access) => access.role), 'owner');
  assert.deepEqual([kept.sent, kept.released], [['begin', 'select', 'select', 'rollback', 'begin', 'select', 'select', 'commit'], [false, false]]);
});

test('read access switches to READ ONLY after the membership check, and the API has no unchecked scope setter', async () => {
  const pool = new ScriptedPool({});
  await tenancy.withWorkspace(drizzle(pool as never), 'u', fakeWorkspace, 'read', async () => undefined);
  await tenancy.withWorkspaces(drizzle(pool as never), 'u', [fakeWorkspace], async () => undefined);
  // begin, membership (with its share lock), SET TRANSACTION READ ONLY, set_config, commit.
  assert.deepEqual(pool.sent, ['begin', 'select', 'set', 'select', 'commit', 'begin', 'select', 'set', 'select', 'commit']);
  assert.equal('setScope' in tenancy, false);
});

test('a workspace id that is not a UUID throws InvalidWorkspaceIdError before any statement, instead of being dropped', async () => {
  const pool = new ScriptedPool({}), db = drizzle(pool as never);
  const invalid = (error: unknown) => error instanceof InvalidWorkspaceIdError && error instanceof TypeError && error.code === 'TENANCY_WORKSPACE_ID_INVALID';
  for (const id of ['not-a-uuid', `${fakeWorkspace},${fakeWorkspace}`, '', 7, undefined]) {
    await assert.rejects(tenancy.withWorkspace(db, 'u', id as string, 'read', async () => 'unreached'), invalid, String(id));
    await assert.rejects(tenancy.withWorkspaces(db, 'u', [fakeWorkspace, id as string], async () => 'unreached'), invalid, String(id));
  }
  await assert.rejects(tenancy.withWorkspaces(db, 'u', fakeWorkspace as never, async () => 'unreached'), TypeError);
  assert.deepEqual([pool.sent, pool.released], [[], []]);
  // Upper case is the same workspace, in its canonical lower-case form.
  assert.equal(await tenancy.withWorkspace(db, 'u', fakeWorkspace.toUpperCase(), 'write', async (_tx, access) => access.workspaceId), fakeWorkspace);
});

test('the exported transaction releases a connection whose BEGIN failed and keeps the callback\'s error', async () => {
  const lost = new Error('connection reset during BEGIN'), failing = new ScriptedPool({ begin: lost });
  await assert.rejects(transaction(drizzle(failing as never), async () => 'unreached'), error => error === lost || (error as { cause?: unknown }).cause === lost);
  assert.deepEqual(failing.released, [true]);
  const original = new Error('the callback failed'), broken = new ScriptedPool({ rollback: new Error('rollback failed') });
  await assert.rejects(transaction(drizzle(broken as never), async () => { throw original; }), error => error === original);
  const working = new ScriptedPool({});
  assert.equal(await transaction(drizzle(working as never), async () => 'done'), 'done');
  assert.deepEqual([broken.released, working.sent, working.released], [[true], ['begin', 'commit'], [false]]);
});

test('the exported transaction keeps the error of a failed COMMIT and discards the connection, even when ROLLBACK would fail too', async () => {
  const lost = new Error('commit failed'), causedBy = (error: unknown) => error === lost || (error as { cause?: unknown }).cause === lost;
  for (const fail of [{ commit: lost }, { commit: lost, rollback: new Error('rollback failed') }]) {
    const pool = new ScriptedPool(fail);
    await assert.rejects(transaction(drizzle(pool as never), async () => 'unreached'), causedBy);
    // The server ended the transaction with the failed COMMIT; the connection is discarded rather than rolled back.
    assert.deepEqual([pool.sent, pool.released], [['begin', 'commit'], [true]]);
  }
});

test('a connection the server terminates mid-transaction fails the transaction instead of crashing the process', async () => {
  const pool = new ScriptedPool({}), terminated = new Error('terminating connection due to administrator command');
  await assert.rejects(transaction(drizzle(pool as never), async tx => {
    // pg emits `error` on a checked-out client whose backend ends; with no listener the emit itself throws.
    pool.connections[0]!.emit('error', terminated);
    await tx.execute(sql`SELECT 1`);
    throw terminated;
  }), error => error === terminated);
  assert.deepEqual([pool.released, pool.connections[0]!.listenerCount('error')], [[true], 0]);
});

test('the exported transaction refuses a database it cannot run safely instead of falling back silently', async () => {
  const refusedDatabase = (error: unknown) => error instanceof TypeError && /node-postgres Drizzle database/u.test(error.message);
  // Neither a pool nor a client, and not a Drizzle database at all.
  await assert.rejects(transaction(drizzle({ connect: async () => undefined } as never), async () => 'unreached'), refusedDatabase);
  await assert.rejects(transaction({ transaction: async () => 'leaked' } as never, async () => 'unreached'), refusedDatabase);
  // A pool whose class name was minified still takes the checked-out path.
  const Minified = class a extends ScriptedPool {}, minified = new Minified({});
  assert.equal(await transaction(drizzle(minified as never), async () => 'done'), 'done');
  assert.deepEqual([minified.sent, minified.released], [['begin', 'commit'], [false]]);
  // A pg Client (a checked-out client is one) is Drizzle's own transaction on that client: nothing to check out or release.
  const sent: string[] = [], query = async (config: string | { text: string }) => { sent.push(typeof config === 'string' ? config : config.text); return { rows: [], fields: [] }; };
  const client = Object.assign(new pg.Client(), { query });
  assert.equal(await transaction(drizzle(client as never), async () => 'done'), 'done');
  assert.deepEqual(sent, ['begin', 'commit']);
  // Wrappers are refused, whatever their shape: statements through them could run on different backends.
  for (const wrapped of [{ query, connect: async () => ({ query, release: () => undefined }) }, { query, release: () => undefined }, { query }]) {
    await assert.rejects(transaction(drizzle(wrapped as never), async () => 'unreached'), refusedDatabase);
  }
  assert.deepEqual(sent, ['begin', 'commit']);
});

test('the exported transaction sends SET TRANSACTION only for a config that sets something', async () => {
  const pool = new ScriptedPool({});
  for (const config of [undefined, {}, { accessMode: undefined }]) assert.equal(await transaction(drizzle(pool as never), async () => 'done', config), 'done');
  assert.deepEqual(pool.sent, ['begin', 'commit', 'begin', 'commit', 'begin', 'commit']);
  const configured = new ScriptedPool({});
  await transaction(drizzle(configured as never), async () => undefined, { accessMode: 'read only' });
  assert.deepEqual(configured.sent, ['begin', 'set', 'commit']);
});

// Integration tests on real PostgreSQL, opt-in: set TEN98_TEST_DATABASE_URL to a disposable server (a superuser URL; each
// run creates and drops its own database and roles). Without it the suite is skipped, like the other opt-in checks.
const admin = process.env.TEN98_TEST_DATABASE_URL;
const skip = admin ? false : 'set TEN98_TEST_DATABASE_URL to a disposable PostgreSQL to run the tenancy integration tests';
const suffix = randomBytes(6).toString('hex');
const database = `ten98_tenancy_${suffix}`;
const roles = { app: `rt_app_${suffix}`, owner: `rt_owner_${suffix}`, bypass: `rt_bypass_${suffix}` };
const password = randomBytes(12).toString('hex');
const schema = { ...teamSchema, note };
let root: pg.Pool | undefined;
const pools: pg.Pool[] = [];
const fixture = { a: '', b: '', c: '', d: '', w1: '', w2: '', w3: '' };

const urlFor = (role?: string) => {
  const url = new URL(admin!);
  url.pathname = `/${database}`;
  if (role) { url.username = role; url.password = password; }
  return url.href;
};
const poolAs = (role: string) => { const pool = createPool(urlFor(role), { max: 2 }); pools.push(pool); return pool; };
const appPool = () => pools[0]!;
const appDb = () => drizzle(appPool(), { schema });
// Drizzle wraps driver errors; the SQLSTATE is on the driver error.
const sqlState = (error: unknown) => (error as { code?: string }).code ?? (error as { cause?: { code?: string } }).cause?.code;
const refused = (error: unknown) => error instanceof WorkspaceAccessError && error.status === 404 && error.message === workspaceNotFound;

test.before(async () => {
  if (!admin) return;
  const server = new pg.Client({ connectionString: admin });
  await server.connect();
  try {
    await server.query(`CREATE DATABASE ${database}`);
    await server.query(`CREATE ROLE ${roles.app} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '${password}'`);
    await server.query(`CREATE ROLE ${roles.owner} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '${password}'`);
    await server.query(`CREATE ROLE ${roles.bypass} LOGIN NOSUPERUSER BYPASSRLS PASSWORD '${password}'`);
  } finally { await server.end(); }
  root = new pg.Pool({ connectionString: urlFor(), max: 2 });
  await root.query(readFileSync(new URL('../workspace-team.sql', import.meta.url), 'utf8'));
  // The scoped tables as an app's migration leaves them: owned by the owner role, the Drizzle policy, ENABLE, and the
  // custom step's FORCE and grants. `unforced` lacks FORCE and `extra` carries a second permissive policy.
  const [policy] = getTableConfig(note).policies;
  const create = (table: string) => `CREATE TABLE ${table} (id serial PRIMARY KEY, workspace_id text NOT NULL REFERENCES workspace(id), body text NOT NULL);
    ALTER TABLE ${table} OWNER TO ${roles.owner};
    CREATE POLICY ${table}_scope ON ${table} AS PERMISSIVE FOR ALL TO public USING (${render(policy!.using)}) WITH CHECK (${render(policy!.withCheck)});
    ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;`;
  await root.query(`${create('note')} ${create('unforced')} ${create('extra')}
    ${tenancy.forceRowLevelSecurity().split('--> statement-breakpoint').join('')}
    ALTER TABLE extra FORCE ROW LEVEL SECURITY;
    CREATE POLICY extra_read ON extra FOR SELECT USING (true);
    GRANT SELECT, INSERT, UPDATE, DELETE ON note, unforced, extra, "user", account, workspace, membership TO ${roles.app};
    GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ${roles.app};`);
  poolAs(roles.app);

  const user = async (name: string) => {
    const id = randomUUID();
    await root!.query('INSERT INTO "user"(id, name, email) VALUES ($1, $2, $3)', [id, name, `${name}-${id}@example.com`]);
    return id;
  };
  fixture.a = await user('a'); fixture.b = await user('b'); fixture.c = await user('c'); fixture.d = await user('d');
  for (const key of ['w1', 'w2', 'w3'] as const) {
    fixture[key] = randomUUID();
    await root.query('INSERT INTO workspace(id, name) VALUES ($1, $2)', [fixture[key], key.toUpperCase()]);
  }
  // A owns W1 and W2; B views W1; D edits W2; C owns W3 only.
  await root.query(`INSERT INTO membership(workspace_id, user_id, role) VALUES ($1, $4, 'owner'), ($2, $4, 'owner'), ($1, $5, 'viewer'),
    ($2, $6, 'editor'), ($3, $7, 'owner')`, [fixture.w1, fixture.w2, fixture.w3, fixture.a, fixture.b, fixture.d, fixture.c]);
  await root.query("INSERT INTO note(workspace_id, body) VALUES ($1, 'one'), ($2, 'two'), ($3, 'three')", [fixture.w1, fixture.w2, fixture.w3]);
});

test.after(async () => {
  if (!admin) return;
  await Promise.all(pools.map(pool => pool.end()));
  await root?.end();
  const server = new pg.Client({ connectionString: admin });
  await server.connect();
  try {
    await server.query(`DROP DATABASE IF EXISTS ${database} WITH (FORCE)`);
    for (const role of Object.values(roles)) await server.query(`DROP ROLE IF EXISTS ${role}`);
  } finally { await server.end(); }
});

test('the team schema matches the tables workspace-team.sql creates', { skip }, async () => {
  const { rows } = await root!.query<{ table_name: string; column_name: string }>(
    "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ANY ($1) ORDER BY 1, 2",
    [Object.values(teamSchema).map(table => getTableConfig(table).name)]);
  const declared = Object.values(teamSchema).flatMap(table => getTableConfig(table).columns.map(column => `${getTableConfig(table).name}.${column.name}`)).sort();
  assert.deepEqual(rows.map(row => `${row.table_name}.${row.column_name}`).sort(), declared);
});

test('the application role passes the boot assertion; the owner and a BYPASSRLS role are refused', { skip }, async () => {
  await tenancy.assertDatabaseRoles(appPool());
  await assert.rejects(tenancy.assertDatabaseRoles(poolAs(roles.owner)),
    (error: unknown) => error instanceof DatabaseRoleError && /it owns or inherits the owner of extra, note, unforced/.test(error.message) && !/superuser|bypasses/.test(error.message));
  await assert.rejects(tenancy.assertDatabaseRoles(poolAs(roles.bypass)),
    (error: unknown) => error instanceof DatabaseRoleError && /it bypasses row-level security/.test(error.message) && !/superuser|owns/.test(error.message));
  await assert.rejects(tenancy.assertDatabaseRoles(root!), /it is a superuser/);
  // A member of the owner role inherits ownership.
  await root!.query(`GRANT ${roles.owner} TO ${roles.bypass}`);
  try { await assert.rejects(tenancy.assertDatabaseRoles(pools.at(-1)!), /owns or inherits the owner of extra, note, unforced/); }
  finally { await root!.query(`REVOKE ${roles.owner} FROM ${roles.bypass}`); }
});

test('the boot assertion requires ENABLE and FORCE and exactly the workspace policy on every scoped table', { skip }, async () => {
  await assert.rejects(tenancy.assertDatabaseRoles(appPool(), ['note', 'unforced']),
    (error: unknown) => error instanceof DatabaseRoleError && /not enabled and forced on unforced\b/.test(error.message) && !/policy/.test(error.message));
  await assert.rejects(tenancy.assertDatabaseRoles(appPool(), ['note', 'extra']),
    (error: unknown) => error instanceof DatabaseRoleError && /workspace policy is missing, altered or accompanied by another policy on extra\./.test(error.message) && !/forced/.test(error.message));
  // A policy for another column or setting is altered, not equivalent.
  const other = createTenancy({ setting: 'app.company_ids', column: 'workspace_id', tables: ['note'] });
  await assert.rejects(other.assertDatabaseRoles(appPool()), /policy is missing, altered or accompanied by another policy on note/);
  await assert.rejects(tenancy.assertDatabaseRoles(appPool(), ['note', 'membership']), /not enabled and forced on membership/);
});

test('withWorkspace admits only its workspace, and WITH CHECK refuses a write for another', { skip }, async () => {
  const db = appDb();
  const read = await tenancy.withWorkspace(db, fixture.a, fixture.w1.toUpperCase(), 'read', async (tx, access) => {
    assert.deepEqual(access, { workspaceId: fixture.w1, name: 'W1', role: 'owner' });
    return tx.select({ body: note.body }).from(note);
  });
  assert.deepEqual(read, [{ body: 'one' }]);
  // A owns W2 as well, so only the transaction's scope can refuse these.
  await tenancy.withWorkspace(db, fixture.a, fixture.w1, 'write', async tx => {
    assert.equal((await tx.update(note).set({ body: 'changed' }).where(eq(note.workspaceId, fixture.w2)).returning()).length, 0);
    assert.equal((await tx.select().from(note).where(eq(note.workspaceId, fixture.w2))).length, 0);
  });
  await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w1, 'write', tx => tx.insert(note).values({ workspaceId: fixture.w2, body: 'intruder' })),
    (error: unknown) => sqlState(error) === '42501');
  await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w1, 'write', tx => tx.update(note).set({ workspaceId: fixture.w2 })),
    (error: unknown) => sqlState(error) === '42501', 'a row cannot be moved out of the scope');
  assert.deepEqual((await root!.query('SELECT workspace_id, body FROM note ORDER BY id')).rows,
    [{ workspace_id: fixture.w1, body: 'one' }, { workspace_id: fixture.w2, body: 'two' }, { workspace_id: fixture.w3, body: 'three' }]);
  // Inside the caller's transaction.
  assert.deepEqual(await db.transaction(outer => tenancy.withWorkspace(db, fixture.d, fixture.w2, 'write', async tx => {
    await tx.update(note).set({ body: 'two edited' });
    return tx.select({ body: note.body }).from(note);
  }, outer)), [{ body: 'two edited' }]);
});

test('without a scope, and after withWorkspace on the same pooled connection, nothing is visible', { skip }, async () => {
  const pool = appPool();
  assert.equal((await pool.query('SELECT * FROM note')).rowCount, 0);
  assert.equal((await pool.query("UPDATE note SET body = 'x'")).rowCount, 0);
  let backend = 0;
  await tenancy.withWorkspace(appDb(), fixture.a, fixture.w1, 'read', async tx => {
    backend = Number((await tx.execute<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid);
    assert.equal((await tx.select().from(note)).length, 1);
  });
  const client = await pool.connect();
  try {
    assert.equal((await client.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid, backend, 'the same pooled connection');
    assert.ok(!(await client.query<{ scope: string | null }>("SELECT current_setting('app.workspace_ids', true) AS scope")).rows[0]!.scope);
    assert.equal((await client.query('SELECT * FROM note')).rowCount, 0);
    await assert.rejects(client.query('ALTER TABLE note NO FORCE ROW LEVEL SECURITY'), (error: unknown) => sqlState(error) === '42501');
  } finally { client.release(); }
});

test('a non-member, a missing workspace and a viewer writing get one indistinguishable refusal before any work', { skip }, async () => {
  const db = appDb();
  let ran = false;
  const attempts = [
    tenancy.withWorkspace(db, fixture.c, fixture.w1, 'read', async () => { ran = true; }),
    tenancy.withWorkspace(db, fixture.c, randomUUID(), 'read', async () => { ran = true; }),
    tenancy.withWorkspace(db, fixture.b, fixture.w1, 'write', async () => { ran = true; }),
  ];
  const errors = await Promise.all(attempts.map(attempt => attempt.then(() => undefined, (error: unknown) => error)));
  for (const error of errors) assert.ok(refused(error), String(error));
  assert.deepEqual(new Set(errors.map(error => JSON.stringify([(error as Error).name, (error as Error).message, (error as WorkspaceAccessError).status]))).size, 1);
  assert.equal(ran, false);
  assert.deepEqual(await tenancy.withWorkspace(db, fixture.b, fixture.w1, 'read', tx => tx.select({ body: note.body }).from(note)), [{ body: 'one' }], 'a viewer reads');
});

test('withWorkspaces reads across the reachable workspaces and leaves the others out silently', { skip }, async () => {
  const db = appDb();
  const ids = [fixture.w3, fixture.w2, fixture.w1, randomUUID()];
  const [access, bodies] = await tenancy.withWorkspaces(db, fixture.a, ids, async (tx, access) =>
    [access.map(item => item.workspaceId), (await tx.select({ body: note.body }).from(note).orderBy(note.id)).map(row => row.body)] as const);
  assert.deepEqual(access, [fixture.w1, fixture.w2], 'in creation order');
  assert.deepEqual(bodies, ['one', 'two edited']);
  assert.deepEqual(await tenancy.withWorkspaces(db, fixture.b, ids, async (tx, access) => [access.length, (await tx.select().from(note)).length]), [1, 1]);
  assert.deepEqual(await tenancy.withWorkspaces(db, randomUUID(), ids, async (tx, access) => [access.length, (await tx.select().from(note)).length]), [0, 0], 'an empty scope admits nothing');
});

test('the test-only scope setter validates ids, is absent from the tenancy entry and the package root, and sends one parameterised statement', async () => {
  assert.deepEqual(Object.keys(tenancyTesting), ['requireScopeForTesting', 'setScopeForTesting', 'unscopedForTesting']);
  const runtime = await import('../index.mjs');
  assert.equal('setScopeForTesting' in tenancy || 'setScopeForTesting' in runtime, false);
  const sent: unknown[][] = [], client = { query: async (text: string, values?: unknown[]) => { sent.push([text, values]); } };
  for (const ids of [['not-a-uuid'], [`${fakeWorkspace},${fakeWorkspace}`], [fakeWorkspace, 7], 'x']) {
    await assert.rejects(tenancyTesting.setScopeForTesting(client, tenancy, ids as never), TypeError);
  }
  await tenancyTesting.setScopeForTesting(client, tenancy, [fakeWorkspace.toUpperCase(), fakeWorkspace]);
  await tenancyTesting.setScopeForTesting(client, tenancy, []);
  assert.deepEqual(sent, [['SELECT set_config($1, $2, true)', ['app.workspace_ids', `${fakeWorkspace},${fakeWorkspace}`]], ['SELECT set_config($1, $2, true)', ['app.workspace_ids', '']]]);
});

test('the test-only scope setter scopes a raw connection as the application role, to any workspaces, for its transaction only', { skip }, async () => {
  const client = await appPool().connect();
  const workspaces = async () => (await client.query<{ workspace_id: string }>('SELECT workspace_id FROM note ORDER BY id')).rows.map(row => row.workspace_id);
  try {
    await client.query('BEGIN');
    // Every workspace, including W3, of which the role's users hold no membership the helpers would check.
    await tenancyTesting.setScopeForTesting(client, tenancy, [fixture.w1, fixture.w2, fixture.w3]);
    assert.deepEqual(await workspaces(), [fixture.w1, fixture.w2, fixture.w3]);
    await tenancyTesting.setScopeForTesting(client, tenancy, []);
    assert.deepEqual(await workspaces(), []);
    await tenancyTesting.setScopeForTesting(client, tenancy, [fixture.w2]);
    await client.query('COMMIT');
    assert.deepEqual(await workspaces(), [], 'the scope ends with the transaction');
  } finally { await client.query('ROLLBACK').catch(() => undefined); client.release(); }
});

test('read access runs READ ONLY; a caller\'s own transaction keeps its access mode', { skip }, async () => {
  const db = appDb(), readOnly = (error: unknown) => sqlState(error) === '25006';
  await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w1, 'read', tx => tx.update(note).set({ body: 'x' })), readOnly);
  await assert.rejects(tenancy.withWorkspaces(db, fixture.a, [fixture.w1], tx => tx.insert(note).values({ workspaceId: fixture.w1, body: 'x' })), readOnly);
  const mode = async (tx: { execute: typeof db.execute }) => (await tx.execute<{ mode: string }>(sql`SELECT current_setting('transaction_read_only') AS mode`)).rows[0]!.mode;
  await db.transaction(async outer => {
    assert.equal(await tenancy.withWorkspace(db, fixture.a, fixture.w1, 'read', tx => mode(tx), outer), 'off');
    assert.equal(await tenancy.withWorkspace(outer, fixture.a, fixture.w1, 'read', tx => mode(tx)), 'off', 'a savepoint');
    assert.equal(await mode(outer), 'off');
  });
  assert.equal(await tenancy.withWorkspace(db, fixture.a, fixture.w1, 'write', tx => mode(tx)), 'off');
});

test('a nested scoped call gives the caller its own scope back, after success and after an error', { skip }, async () => {
  const db = appDb(), inner = new Error('the inner callback failed');
  const visible = async (tx: Pick<typeof db, 'select'>) => (await tx.select({ id: note.workspaceId }).from(note).orderBy(note.id)).map(row => row.id);
  await tenancy.withWorkspace(db, fixture.a, fixture.w1, 'write', async tx => {
    assert.deepEqual(await visible(tx), [fixture.w1]);
    // In a savepoint (a transaction passed as db) and in the caller's transaction (outer).
    assert.deepEqual(await tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', visible), [fixture.w2]);
    assert.deepEqual(await visible(tx), [fixture.w1]);
    assert.deepEqual(await tenancy.withWorkspace(db, fixture.a, fixture.w2, 'write', visible, tx), [fixture.w2]);
    assert.deepEqual(await visible(tx), [fixture.w1]);
    assert.deepEqual(await tenancy.withWorkspaces(tx, fixture.a, [fixture.w1, fixture.w2], visible), [fixture.w1, fixture.w2]);
    assert.deepEqual(await visible(tx), [fixture.w1]);
    await assert.rejects(tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', async () => { throw inner; }), error => error === inner);
    assert.deepEqual(await visible(tx), [fixture.w1]);
    await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w2, 'write', async () => { throw inner; }, tx), error => error === inner);
    assert.deepEqual(await visible(tx), [fixture.w1]);
  });
});

const unlocked = (error: unknown) => error instanceof UnlockedScopeError && error.code === 'TENANCY_SCOPE_UNLOCKED';

test('a scoped call nested in a READ ONLY transaction admits only memberships a helper share-locked, and fails closed otherwise', { skip }, async () => {
  const db = appDb(), readOnly = (error: unknown) => sqlState(error) === '25006';
  const visible = async (tx: Pick<typeof db, 'select'>) => (await tx.select({ id: note.workspaceId }).from(note).orderBy(note.id)).map(row => row.id);
  // The outer read share-locked W1 and W2 before turning READ ONLY; nested calls, savepoints within savepoints included, may use them.
  assert.deepEqual(await tenancy.withWorkspaces(db, fixture.a, [fixture.w1, fixture.w2], async tx => [
    await tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', visible),
    await tenancy.withWorkspaces(tx, fixture.a, [fixture.w1, fixture.w2], visible),
    await tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', inner => tenancy.withWorkspace(inner, fixture.a, fixture.w1, 'read', visible)),
    await tenancy.withWorkspace(db, fixture.a, fixture.w2, 'read', visible, tx),
    await visible(tx),
  ]), [[fixture.w2], [fixture.w1, fixture.w2], [fixture.w1], [fixture.w2], [fixture.w1, fixture.w2]]);
  // A workspace the outer call did not lock is refused, not read unlocked.
  await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w1, 'read', tx => tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', visible)), unlocked);
  await assert.rejects(tenancy.withWorkspaces(db, fixture.a, [fixture.w1], tx => tenancy.withWorkspaces(tx, fixture.a, [fixture.w1, fixture.w2], visible)), unlocked);
  // So is every workspace in a READ ONLY transaction the caller opened itself, as outer or as a savepoint.
  await assert.rejects(db.transaction(outer => tenancy.withWorkspace(db, fixture.a, fixture.w2, 'read', visible, outer), { accessMode: 'read only' }), unlocked);
  await assert.rejects(db.transaction(outer => tenancy.withWorkspaces(outer, fixture.a, [fixture.w2], visible), { accessMode: 'read only' }), unlocked);
  // A non-member still gets the plain refusal, and a write is still refused by PostgreSQL.
  await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w1, 'read', tx => tenancy.withWorkspace(tx, fixture.a, fixture.w3, 'read', visible)), refused);
  await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w1, 'read', tx =>
    tenancy.withWorkspace(tx, fixture.a, fixture.w1, 'write', inner => inner.insert(note).values({ workspaceId: fixture.w1, body: 'x' }))), readOnly);
  // A savepoint rolled back releases the locks taken inside it, so they no longer count.
  const inner = new Error('the inner callback failed');
  await tenancy.withWorkspace(db, fixture.a, fixture.w1, 'write', async tx => {
    await assert.rejects(tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', async () => { throw inner; }), error => error === inner);
    await tx.setTransaction({ accessMode: 'read only' });
    await assert.rejects(tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', visible), unlocked);
    assert.deepEqual(await tenancy.withWorkspace(tx, fixture.a, fixture.w1, 'read', visible), [fixture.w1]);
  });
});

test('a removal waits for a nested read of a locked membership, and cannot commit under an unlocked one', { skip }, async () => {
  const db = appDb(), notLocked = (error: unknown) => sqlState(error) === '55P03';
  const remove = async () => {
    const client = await root!.connect();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL lock_timeout = '300ms'");
      await client.query('DELETE FROM membership WHERE workspace_id = $1 AND user_id = $2', [fixture.w2, fixture.a]);
      await client.query('COMMIT');
    } catch (error) { await client.query('ROLLBACK').catch(() => undefined); throw error; } finally { client.release(); }
  };
  try {
    // Locked by the outer read: the removal times out on the share lock while the nested read runs.
    await tenancy.withWorkspaces(db, fixture.a, [fixture.w1, fixture.w2], tx => tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', async () => {
      await assert.rejects(remove(), notLocked);
    }));
    // Not locked: without the refusal the removal would commit here and the callback would still read W2's rows.
    let ran = false;
    await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w1, 'read', tx => tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', async inner => {
      ran = true;
      await remove();
      return inner.select().from(note);
    })), unlocked);
    assert.equal(ran, false);
  } finally {
    await root!.query("INSERT INTO membership(workspace_id, user_id, role) VALUES ($1, $2, 'owner') ON CONFLICT DO NOTHING", [fixture.w2, fixture.a]);
  }
});

test('one user\'s locked membership never admits another user\'s nested read of the same workspace', { skip }, async () => {
  // A owns W2 and D edits W2. The outer read locks A's membership row only; D's row stays unlocked.
  const db = appDb(), visible = async (tx: Pick<typeof db, 'select'>) => (await tx.select({ id: note.workspaceId }).from(note)).map(row => row.id);
  let removed = false;
  const removeD = async () => {
    await root!.query('DELETE FROM membership WHERE workspace_id = $1 AND user_id = $2', [fixture.w2, fixture.d]);
    removed = true;
  };
  const asD = (tx: Parameters<Parameters<typeof tenancy.withWorkspaces<typeof db, unknown>>[3]>[0]) => [
    // In a savepoint, through withWorkspace and withWorkspaces, and joined as outer.
    () => tenancy.withWorkspace(tx, fixture.d, fixture.w2, 'read', async inner => { await removeD(); return visible(inner); }),
    () => tenancy.withWorkspaces(tx, fixture.d, [fixture.w2], async inner => { await removeD(); return visible(inner); }),
    () => tenancy.withWorkspace(db, fixture.d, fixture.w2, 'read', async inner => { await removeD(); return visible(inner); }, tx),
  ];
  try {
    for (const index of [0, 1, 2]) {
      await assert.rejects(tenancy.withWorkspaces(db, fixture.a, [fixture.w2], tx => asD(tx)[index]!()), unlocked, `nested call ${index}`);
      assert.equal(removed, false, `nested call ${index} ran its callback`);
    }
  } finally {
    await root!.query("INSERT INTO membership(workspace_id, user_id, role) VALUES ($1, $2, 'editor') ON CONFLICT DO NOTHING", [fixture.w2, fixture.d]);
  }
});

test('locks released by a rollback the helper did not make never admit a later nested read', { skip }, async () => {
  const db = appDb(), visible = async (tx: Pick<typeof db, 'select'>) => (await tx.select({ id: note.workspaceId }).from(note)).map(row => row.id);
  const failure = new Error('the inner callback failed');
  // An outer-joined call inside a helper savepoint that then throws: the savepoint's rollback releases W2's lock.
  await tenancy.withWorkspace(db, fixture.a, fixture.w1, 'write', async tx => {
    await assert.rejects(tenancy.withWorkspace(tx, fixture.a, fixture.w1, 'write', async inner => {
      await tenancy.withWorkspace(db, fixture.a, fixture.w2, 'write', async () => undefined, inner);
      throw failure;
    }), error => error === failure);
    await tx.setTransaction({ accessMode: 'read only' });
    await assert.rejects(tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', visible), unlocked);
  });
  // A raw SAVEPOINT and ROLLBACK TO around an outer-joined call.
  await tenancy.withWorkspace(db, fixture.a, fixture.w1, 'write', async tx => {
    await tx.execute(sql`SAVEPOINT caller`);
    await tenancy.withWorkspace(db, fixture.a, fixture.w2, 'write', async () => undefined, tx);
    await tx.execute(sql`ROLLBACK TO SAVEPOINT caller`);
    await tx.setTransaction({ accessMode: 'read only' });
    await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w2, 'read', visible, tx), unlocked);
  });
  // A helper call given the parent inside the caller's own Drizzle savepoint, which then rolls back.
  await tenancy.withWorkspace(db, fixture.a, fixture.w1, 'write', async tx => {
    await assert.rejects(tx.transaction(async () => {
      await tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'write', async () => undefined);
      throw failure;
    }), error => error === failure);
    await tx.setTransaction({ accessMode: 'read only' });
    await assert.rejects(tenancy.withWorkspace(tx, fixture.a, fixture.w2, 'read', visible), unlocked);
    // The top-level lock on W1 still holds and still admits.
    assert.deepEqual(await tenancy.withWorkspace(tx, fixture.a, fixture.w1, 'read', visible), [fixture.w1]);
  });
  // Documented limit, failing closed: the caller's own Drizzle savepoint has no record, though the lock is held.
  await assert.rejects(tenancy.withWorkspaces(db, fixture.a, [fixture.w1], tx => tx.transaction(own => tenancy.withWorkspace(own, fixture.a, fixture.w1, 'read', visible))), unlocked);
});

test('a REPEATABLE READ read-only transaction of the caller never admits a membership its snapshot still shows after removal', { skip }, async () => {
  const db = appDb(), visible = async (tx: Pick<typeof db, 'select'>) => (await tx.select({ id: note.workspaceId }).from(note)).map(row => row.id);
  try {
    await db.transaction(async outer => {
      await outer.execute(sql`SELECT 1`); // takes the snapshot, in which A is still a member of W2
      await root!.query('DELETE FROM membership WHERE workspace_id = $1 AND user_id = $2', [fixture.w2, fixture.a]);
      await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w2, 'read', visible, outer), unlocked);
      await assert.rejects(tenancy.withWorkspaces(outer, fixture.a, [fixture.w2], visible), unlocked);
    }, { isolationLevel: 'repeatable read', accessMode: 'read only' });
  } finally {
    await root!.query("INSERT INTO membership(workspace_id, user_id, role) VALUES ($1, $2, 'owner') ON CONFLICT DO NOTHING", [fixture.w2, fixture.a]);
  }
});

test('a lock record never outlives its transaction: a stale transaction object inside a later READ ONLY transaction is refused', { skip }, async () => {
  // One connection, so the stale object's statements land in the later transaction on that same connection.
  const single = createPool(urlFor(roles.app), { max: 1 });
  pools.push(single);
  const db = drizzle(single, { schema }), visible = async (tx: Pick<typeof db, 'select'>) => (await tx.select({ id: note.workspaceId }).from(note)).map(row => row.id);
  type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];
  let stale: Tx | undefined;
  const failure = new Error('the callback failed');
  // Reused after the helper's transaction committed, and after it rolled back.
  for (const end of ['commit', 'rollback'] as const) {
    const finished = tenancy.withWorkspaces(db, fixture.a, [fixture.w1, fixture.w2], async tx => { stale = tx as Tx; if (end === 'rollback') throw failure; });
    if (end === 'rollback') await assert.rejects(finished, error => error === failure); else await finished;
    await db.transaction(async () => {
      await assert.rejects(tenancy.withWorkspace(stale!, fixture.a, fixture.w1, 'read', visible), unlocked, `${end}: as db`);
      await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w1, 'read', visible, stale), unlocked, `${end}: as outer`);
      await assert.rejects(tenancy.withWorkspaces(stale!, fixture.a, [fixture.w1], visible), unlocked, `${end}: withWorkspaces`);
    }, { accessMode: 'read only' });
  }
  // A caller's own ROLLBACK and BEGIN READ ONLY inside a live helper transaction starts a transaction the record does not cover.
  await tenancy.withWorkspaces(db, fixture.a, [fixture.w1, fixture.w2], async tx => {
    await tx.execute(sql`ROLLBACK`);
    await tx.execute(sql`BEGIN READ ONLY`);
    await assert.rejects(tenancy.withWorkspace(tx, fixture.a, fixture.w1, 'read', visible), unlocked, 'after ROLLBACK and BEGIN');
    await assert.rejects(tenancy.withWorkspace(db, fixture.a, fixture.w1, 'read', visible, tx), unlocked, 'as outer, after ROLLBACK and BEGIN');
  });
  // The live record still admits within its own transaction.
  assert.deepEqual(await tenancy.withWorkspaces(db, fixture.a, [fixture.w1, fixture.w2], tx => tenancy.withWorkspace(tx, fixture.a, fixture.w1, 'read', visible)), [fixture.w1]);
});

test('a session time zone change inside a helper read never refuses a correctly locked nested read (#128)', { skip }, async () => {
  const db = appDb(), visible = async (tx: Pick<typeof db, 'select'>) => (await tx.select({ id: note.workspaceId }).from(note)).map(row => row.id);
  assert.deepEqual(await tenancy.withWorkspaces(db, fixture.a, [fixture.w1, fixture.w2], async tx => {
    await tx.execute(sql`SET LOCAL TIME ZONE 'Pacific/Kiritimati'`);
    return tenancy.withWorkspace(tx, fixture.a, fixture.w1, 'read', visible);
  }), [fixture.w1]);
});

// Last: this changes D's membership.
test('a demotion waits for an in-flight workspace write; then the viewer cannot write', { skip }, async () => {
  const db = appDb();
  let demotion: Promise<unknown> | undefined;
  let settled = false;
  await tenancy.withWorkspace(db, fixture.d, fixture.w2, 'write', async tx => {
    demotion = root!.query("UPDATE membership SET role = 'viewer' WHERE workspace_id = $1 AND user_id = $2", [fixture.w2, fixture.d]).finally(() => { settled = true; });
    await new Promise(resolve => setTimeout(resolve, 500));
    assert.equal(settled, false, 'the demotion cannot commit while the write that checked the old role is open');
    await tx.update(note).set({ body: 'last edit' });
  });
  await demotion;
  await assert.rejects(tenancy.withWorkspace(db, fixture.d, fixture.w2, 'write', async () => undefined), refused);
});
