import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { eq, type SQL } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { getTableConfig, PgDialect, pgTable, serial, text } from 'drizzle-orm/pg-core';
import pg from 'pg';
import { createPool, teamSchema } from '../db.mjs';
import { createTenancy, DatabaseRoleError, WorkspaceAccessError, workspaceNotFound } from '../tenancy.mjs';

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
    tenancy.withWorkspace(db, fixture.c, 'not-a-uuid', 'write', async () => { ran = true; }),
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
  const ids = [fixture.w3, fixture.w2, fixture.w1, randomUUID(), 'not-a-uuid'];
  const [access, bodies] = await tenancy.withWorkspaces(db, fixture.a, ids, async (tx, access) =>
    [access.map(item => item.workspaceId), (await tx.select({ body: note.body }).from(note).orderBy(note.id)).map(row => row.body)] as const);
  assert.deepEqual(access, [fixture.w1, fixture.w2], 'in creation order');
  assert.deepEqual(bodies, ['one', 'two edited']);
  assert.deepEqual(await tenancy.withWorkspaces(db, fixture.b, ids, async (tx, access) => [access.length, (await tx.select().from(note)).length]), [1, 1]);
  assert.deepEqual(await tenancy.withWorkspaces(db, randomUUID(), ids, async (tx, access) => [access.length, (await tx.select().from(note)).length]), [0, 0], 'an empty scope admits nothing');
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
