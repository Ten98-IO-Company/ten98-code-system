// Workspace tenancy by forced row-level security, promoted from Books src/server/tenancy.ts. Every table that holds
// workspace data carries one policy admitting the workspaces listed in a transaction-local setting, and is read and
// written only inside `withWorkspace` (or, for reads across the caller's own workspaces, `withWorkspaces`). The app
// configures the setting, column and tables once with `createTenancy` and keeps its routes, roles and how a refusal
// becomes its response. drizzle-orm and pg are exact, optional peer dependencies.
//
// Drizzle declares the policy (`policy`) and ENABLE ROW LEVEL SECURITY (`pgTable(...).enableRLS()`). FORCE, the roles
// and their grants are SQL in the app's custom migration step; `forceRowLevelSecurity` writes the FORCE part.
import { and, eq, inArray, sql } from 'drizzle-orm';
import { pgPolicy, PgTransaction, type PgPolicy } from 'drizzle-orm/pg-core';
import type pg from 'pg';
import type { WorkspaceRole } from './browser.mjs';
import { membership, transaction, workspace, type AnyDatabase, type ScopedTransaction } from './db.mjs';

export type { ScopedTransaction } from './db.mjs';

export type WorkspaceMode = 'read' | 'write';
type Caller = { scope: string; readOnly: boolean };
/** The authorized workspace with its name and the caller's role in it. */
export type WorkspaceAccess = { workspaceId: string; name: string; role: WorkspaceRole };
// A pg pool, pool client or client.
type Queryable = { query<R extends pg.QueryResultRow>(text: string, values?: unknown[]): Promise<pg.QueryResult<R>> };

/** One answer for a missing workspace and for a workspace the user may not reach (or not write), so ids reveal nothing. */
export const workspaceNotFound = 'Workspace not found or unavailable.';
export class WorkspaceAccessError extends Error {
  readonly status = 404 as const;
  constructor() { super(workspaceNotFound); this.name = 'WorkspaceAccessError'; }
}

/** Operator-safe refusal: names the failed checks, never connection details. */
export class DatabaseRoleError extends Error {
  constructor(problems: readonly string[]) {
    super(`The application database role is unsafe for workspace data: ${problems.join('; ')}. Connect web and worker with the non-owner application role.`);
    this.name = 'DatabaseRoleError';
  }
}

export interface TenancyOptions<TTable extends string> {
  /** The custom setting that lists the admitted workspace ids, such as `app.workspace_ids`. */
  setting: string;
  /** The workspace id column every scoped table carries, such as `workspace_id`. */
  column: string;
  /** Every table that holds workspace data. */
  tables: readonly TTable[];
}

/**
 * A scoped call nested in a READ ONLY transaction named a membership that this transaction does not hold share-locked,
 * so a removal could commit while its callback still read the workspace. Thrown instead of reading it unlocked.
 */
export class UnlockedScopeError extends Error {
  readonly code = 'TENANCY_SCOPE_UNLOCKED' as const;
  constructor() {
    super('A scoped call nested in a READ ONLY transaction may admit only memberships the transaction\'s own helper call share-locked. Open the outer call for the same user over those workspaces (withWorkspaces), or make it a write call.');
    this.name = 'UnlockedScopeError';
  }
}

const writers: readonly WorkspaceRole[] = ['owner', 'admin', 'editor'];
/**
 * The memberships, as user and workspace pairs, that a helper share-locked at the top level of a transaction it opened
 * itself. That check is the transaction's first statement, so no savepoint precedes it and nothing short of the
 * transaction's end releases those locks. Locks taken by nested calls are never recorded: a savepoint or a caller's
 * ROLLBACK TO can release them unseen. Keyed by the transaction objects the helpers hand out, the top-level one and the
 * savepoints helpers open inside it; any other transaction object has no record, so nesting there fails closed.
 */
const held = new WeakMap<object, ReadonlySet<string>>();
const pair = (userId: string, workspaceId: string) => `${userId}\u0000${workspaceId}`;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Lowercase names only: they go into SQL text unquoted, and PostgreSQL's stored policy then matches them verbatim.
const identifier = /^[a-z_][a-z0-9_]*$/;
const settingName = /^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$/;
// Removes PostgreSQL's deparse formatting (whitespace, parentheses, `::text` casts) from a stored policy, never the expression.
const deparseNoise = String.raw`[\s()]|::text(\[\])?`;

export function createTenancy<TTable extends string>({ setting, column, tables }: TenancyOptions<TTable>) {
  if (typeof setting !== 'string' || !settingName.test(setting)) throw new TypeError('The tenancy setting must be a lowercase custom setting name such as app.workspace_ids.');
  if (typeof column !== 'string' || !identifier.test(column)) throw new TypeError('The tenancy column must be a lowercase SQL identifier.');
  if (!Array.isArray(tables) || !tables.length || !tables.every(table => typeof table === 'string' && identifier.test(table))) throw new TypeError('The tenancy tables must be lowercase SQL identifiers.');
  // Raw by necessity: a policy is DDL, which takes no bind parameters. Only the two names checked above are interpolated.
  const scope = sql.raw(`${column} = ANY (string_to_array(current_setting('${setting}', true), ','))`);
  // The scope as PostgreSQL stores it in pg_policies once `deparseNoise` is removed.
  const storedScope = `${column}=ANYstring_to_arraycurrent_setting'${setting}',true,','`;

  // Parameterised `sql` statements by necessity: Drizzle has no builder for set_config or current_setting.
  const setScope = (tx: AnyDatabase, value: string) => tx.execute(sql`SELECT set_config(${setting}, ${value}, true)`);
  // What a nested call must respect: the caller's scope, to put back, and whether its transaction is READ ONLY.
  const readCaller = async (tx: AnyDatabase): Promise<Caller> => {
    const { rows } = (await tx.execute(sql`SELECT current_setting(${setting}, true) AS scope, current_setting('transaction_read_only') AS read_only`)) as unknown as { rows: { scope: string | null; read_only: string }[] };
    return { scope: rows[0]?.scope ?? '', readOnly: rows[0]?.read_only === 'on' };
  };

  /**
   * Runs `run` with row-level security admitting `workspaceIds`. In a transaction of its own the scope lasts to its end.
   * A nested call (`caller`: a caller's transaction or a savepoint, which may already hold a scope) puts the caller's
   * scope back when `run` settles, so the caller never goes on in the inner workspace. After an error the transaction
   * may be aborted and refuse the restore; the caller's ROLLBACK, or the savepoint's, then undoes the inner scope.
   * Nested calls on one transaction must be awaited in turn: run at once, their scopes and restores interleave.
   */
  async function inScope<T>(tx: AnyDatabase, workspaceIds: readonly string[], caller: Caller | undefined, run: () => Promise<T>): Promise<T> {
    await setScope(tx, workspaceIds.join(','));
    if (!caller) return run();
    let result: T;
    try { result = await run(); } catch (error) { await setScope(tx, caller.scope).catch(() => undefined); throw error; }
    await setScope(tx, caller.scope);
    return result;
  }

  /**
   * The caller's memberships among `workspaceIds`, taken inside the transaction. Each membership row is share-locked
   * until commit (the team controller's caller-membership convention), so a removal or demotion waits for an in-flight
   * workspace transaction and cannot commit between this check and its writes. The workspace row is not locked: team
   * changes lock it first, and tenant transactions must not queue behind them or hold them up.
   *
   * A READ ONLY transaction refuses the lock, so there the check fails closed: it admits only this user's memberships
   * that the transaction's own top-level helper call share-locked (`held`), which a removal must still wait for. Any
   * other membership, another user's, or any in a READ ONLY transaction the caller opened itself, throws
   * UnlockedScopeError rather than being read unlocked, where a removal could commit while the callback still reads.
   */
  async function memberships(tx: AnyDatabase, userId: string, workspaceIds: readonly string[], caller: Caller | undefined,
    record: Set<string> | undefined, locked: ReadonlySet<string> | undefined): Promise<WorkspaceAccess[]> {
    const ids = workspaceIds.filter(id => typeof id === 'string' && uuid.test(id)).map(id => id.toLowerCase());
    if (!ids.length || typeof userId !== 'string') return [];
    const query = tx.select({ workspaceId: workspace.id, name: workspace.name, role: membership.role })
      .from(membership).innerJoin(workspace, eq(workspace.id, membership.workspaceId))
      .where(and(eq(membership.userId, userId), inArray(membership.workspaceId, ids)))
      .orderBy(workspace.createdAt, workspace.id);
    if (!caller?.readOnly) {
      const access = await query.for('share', { of: membership });
      if (record) for (const item of access) record.add(pair(userId, item.workspaceId));
      return access;
    }
    const access = await query;
    if (access.some(item => !locked?.has(pair(userId, item.workspaceId)))) throw new UnlockedScopeError();
    return access;
  }

  /**
   * Runs `body` in the transaction a helper call uses. A transaction of its own starts a fresh record of the
   * memberships its top-level check locks (`record`). A nested call (the caller's `outer`, or a savepoint when `db` is a
   * transaction) gets the caller's state and only reads the record; a savepoint a helper opens shares it.
   */
  async function scopedTransaction<TDatabase extends AnyDatabase, T>(db: TDatabase, outer: ScopedTransaction<TDatabase> | undefined,
    body: (tx: ScopedTransaction<TDatabase>, caller: Caller | undefined, record: Set<string> | undefined, locked: ReadonlySet<string> | undefined) => Promise<T>): Promise<T> {
    if (outer) return body(outer, await readCaller(outer), undefined, held.get(outer));
    if (!(db instanceof PgTransaction)) {
      return transaction(db, tx => { const record = new Set<string>(); held.set(tx, record); return body(tx, undefined, record, record); });
    }
    const locked = held.get(db);
    return transaction(db, async tx => { if (locked) held.set(tx, locked); return body(tx, await readCaller(tx), undefined, locked); });
  }

  return {
    setting, column, tables,
    /** The policy for a scoped table's Drizzle callback: every command, every role, USING and WITH CHECK the scope. */
    policy(name: string): PgPolicy {
      return pgPolicy(name, { as: 'permissive', for: 'all', to: 'public', using: scope, withCheck: scope });
    },
    /**
     * The custom migration step's FORCE statements, separated as drizzle-kit separates statements. Returned as text for
     * the migration file, never executed here; the table names are the identifiers checked by `createTenancy`.
     */
    forceRowLevelSecurity(): string {
      return tables.map(table => `ALTER TABLE "${table}" FORCE ROW LEVEL SECURITY;`).join('\n--> statement-breakpoint\n');
    },
    /**
     * Authorizes `userId` as a member of `workspaceId` (viewers read; editors, admins and owners write) and runs `run` in
     * one transaction whose row-level security admits that workspace only. `read` makes that transaction READ ONLY once
     * the membership is checked (its share lock cannot be taken in a read-only transaction). `outer` joins a transaction
     * the caller already holds (workspace creation inserts the workspace first), and `db` may itself be a transaction (a
     * savepoint): the caller then owns commit, rollback and access mode, and gets its own scope back afterwards. Nested in
     * a READ ONLY transaction it admits only this user's memberships that the transaction's top-level helper call locked.
     */
    async withWorkspace<TDatabase extends AnyDatabase, T>(db: TDatabase, userId: string, workspaceId: string, mode: WorkspaceMode,
      run: (tx: ScopedTransaction<TDatabase>, access: WorkspaceAccess) => Promise<T>, outer?: ScopedTransaction<TDatabase>): Promise<T> {
      return scopedTransaction(db, outer, async (tx, caller, record, locked) => {
        const [access] = await memberships(tx, userId, [workspaceId], caller, record, locked);
        if (!access || (mode !== 'read' && !writers.includes(access.role))) throw new WorkspaceAccessError();
        if (mode === 'read' && !caller) await tx.setTransaction({ accessMode: 'read only' });
        return inScope(tx, [access.workspaceId], caller, () => run(tx, access));
      });
    },
    /**
     * For reads: runs `run` in one READ ONLY transaction scoped to those of `workspaceIds` the user is a member of. Ids
     * the user cannot reach are left out silently; `run` receives the ones admitted. Given a transaction as `db` it runs in
     * a savepoint, as `withWorkspace` does, and restores the caller's scope.
     */
    withWorkspaces<TDatabase extends AnyDatabase, T>(db: TDatabase, userId: string, workspaceIds: readonly string[],
      run: (tx: ScopedTransaction<TDatabase>, access: WorkspaceAccess[]) => Promise<T>): Promise<T> {
      return scopedTransaction(db, undefined, async (tx, caller, record, locked) => {
        const access = await memberships(tx, userId, workspaceIds, caller, record, locked);
        if (!caller) await tx.setTransaction({ accessMode: 'read only' });
        return inScope(tx, access.map(item => item.workspaceId), caller, () => run(tx, access));
      });
    },
    /**
     * Boot and test assertion: the connected role is not a superuser, cannot bypass row-level security, neither owns nor
     * is a member of the owner of any public table, and every scoped table (`checked`, by default all of them) forces
     * row-level security with exactly one policy, the workspace policy, for every command and role (USING and WITH
     * CHECK). Without this the policies are silently inert or could be widened by an extra permissive policy.
     */
    async assertDatabaseRoles(pool: Queryable, checked: readonly string[] = tables): Promise<void> {
      // A raw, parameterised statement by necessity: it reads the system catalogues, which have no Drizzle schema, and
      // takes a pg pool so it can run at boot before any Drizzle database exists.
      const { rows } = await pool.query<{ rolsuper: boolean; rolbypassrls: boolean; owned: string[]; unforced: string[]; unpolicied: string[] }>(
        `SELECT r.rolsuper, r.rolbypassrls,
           ARRAY(SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND pg_has_role(current_user, c.relowner, 'MEMBER') ORDER BY 1) AS owned,
           ARRAY(SELECT t FROM unnest($1::text[]) t WHERE NOT EXISTS (
                   SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = 'public' AND c.relname = t AND c.relkind = 'r' AND c.relrowsecurity AND c.relforcerowsecurity) ORDER BY 1) AS unforced,
           ARRAY(SELECT t FROM unnest($1::text[]) t WHERE NOT (
                   (SELECT count(*) FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = t) = 1
                   AND EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = t
                     AND p.cmd = 'ALL' AND p.permissive = 'PERMISSIVE' AND p.roles = '{public}'::name[]
                     AND regexp_replace(p.qual, $2, '', 'g') = $3 AND regexp_replace(p.with_check, $2, '', 'g') = $3)) ORDER BY 1) AS unpolicied
         FROM pg_roles r WHERE r.rolname = current_user`, [checked, deparseNoise, storedScope],
      );
      const role = rows[0];
      const problems = !role ? ['the connected role was not found'] : [
        ...role.rolsuper ? ['it is a superuser'] : [],
        ...role.rolbypassrls ? ['it bypasses row-level security'] : [],
        ...role.owned.length ? [`it owns or inherits the owner of ${role.owned.join(', ')}`] : [],
        ...role.unforced.length ? [`row-level security is not enabled and forced on ${role.unforced.join(', ')}`] : [],
        ...role.unpolicied.length ? [`the workspace policy is missing, altered or accompanied by another policy on ${role.unpolicied.join(', ')}`] : [],
      ];
      if (problems.length) throw new DatabaseRoleError(problems);
    },
  };
}

export type Tenancy<TTable extends string = string> = ReturnType<typeof createTenancy<TTable>>;
