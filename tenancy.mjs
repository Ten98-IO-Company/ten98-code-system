// Workspace tenancy by forced row-level security, promoted from Books src/server/tenancy.ts. Every table that holds
// workspace data carries one policy admitting the workspaces listed in a transaction-local setting, and is read and
// written only inside `withWorkspace` (or, for reads across the caller's own workspaces, `withWorkspaces`). The app
// configures the setting, column and tables once with `createTenancy` and keeps its routes, roles and how a refusal
// becomes its response. drizzle-orm and pg are exact, optional peer dependencies.
//
// Drizzle declares the policy (`policy`) and ENABLE ROW LEVEL SECURITY (`pgTable(...).enableRLS()`). FORCE, the roles
// and their grants are SQL in the app's custom migration step; `forceRowLevelSecurity` writes the FORCE part.
import { and, eq, inArray, sql } from 'drizzle-orm';
import { pgPolicy, PgTransaction } from 'drizzle-orm/pg-core';
import { membership, transaction, workspace } from './db.mjs';
/** One answer for a missing workspace and for a workspace the user may not reach (or not write), so ids reveal nothing. */
export const workspaceNotFound = 'Workspace not found or unavailable.';
export class WorkspaceAccessError extends Error {
    status = 404;
    constructor() { super(workspaceNotFound); this.name = 'WorkspaceAccessError'; }
}
/** Operator-safe refusal: names the failed checks, never connection details. */
export class DatabaseRoleError extends Error {
    constructor(problems) {
        super(`The application database role is unsafe for workspace data: ${problems.join('; ')}. Connect web and worker with the non-owner application role.`);
        this.name = 'DatabaseRoleError';
    }
}
const writers = ['owner', 'admin', 'editor'];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Lowercase names only: they go into SQL text unquoted, and PostgreSQL's stored policy then matches them verbatim.
const identifier = /^[a-z_][a-z0-9_]*$/;
const settingName = /^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$/;
// Removes PostgreSQL's deparse formatting (whitespace, parentheses, `::text` casts) from a stored policy, never the expression.
const deparseNoise = String.raw `[\s()]|::text(\[\])?`;
export function createTenancy({ setting, column, tables }) {
    if (typeof setting !== 'string' || !settingName.test(setting))
        throw new TypeError('The tenancy setting must be a lowercase custom setting name such as app.workspace_ids.');
    if (typeof column !== 'string' || !identifier.test(column))
        throw new TypeError('The tenancy column must be a lowercase SQL identifier.');
    if (!Array.isArray(tables) || !tables.length || !tables.every(table => typeof table === 'string' && identifier.test(table)))
        throw new TypeError('The tenancy tables must be lowercase SQL identifiers.');
    // Raw by necessity: a policy is DDL, which takes no bind parameters. Only the two names checked above are interpolated.
    const scope = sql.raw(`${column} = ANY (string_to_array(current_setting('${setting}', true), ','))`);
    // The scope as PostgreSQL stores it in pg_policies once `deparseNoise` is removed.
    const storedScope = `${column}=ANYstring_to_arraycurrent_setting'${setting}',true,','`;
    // Parameterised `sql` statements by necessity: Drizzle has no builder for set_config or current_setting.
    const setScope = (tx, value) => tx.execute(sql `SELECT set_config(${setting}, ${value}, true)`);
    // What a nested call must respect: the caller's scope, to put back, and whether its transaction is READ ONLY.
    const readCaller = async (tx) => {
        const { rows } = (await tx.execute(sql `SELECT current_setting(${setting}, true) AS scope, current_setting('transaction_read_only') AS read_only`));
        return { scope: rows[0]?.scope ?? '', readOnly: rows[0]?.read_only === 'on' };
    };
    /**
     * Runs `run` with row-level security admitting `workspaceIds`. In a transaction of its own the scope lasts to its end.
     * A nested call (`caller`: a caller's transaction or a savepoint, which may already hold a scope) puts the caller's
     * scope back when `run` settles, so the caller never goes on in the inner workspace. After an error the transaction
     * may be aborted and refuse the restore; the caller's ROLLBACK, or the savepoint's, then undoes the inner scope.
     * Nested calls on one transaction must be awaited in turn: run at once, their scopes and restores interleave.
     */
    async function inScope(tx, workspaceIds, caller, run) {
        await setScope(tx, workspaceIds.join(','));
        if (!caller)
            return run();
        let result;
        try {
            result = await run();
        }
        catch (error) {
            await setScope(tx, caller.scope).catch(() => undefined);
            throw error;
        }
        await setScope(tx, caller.scope);
        return result;
    }
    /**
     * The caller's memberships among `workspaceIds`, taken inside the transaction. Each membership row is share-locked
     * until commit (the team controller's caller-membership convention), so a removal or demotion waits for an in-flight
     * workspace transaction and cannot commit between this check and its writes. The workspace row is not locked: team
     * changes lock it first, and tenant transactions must not queue behind them or hold them up. A READ ONLY transaction
     * refuses the lock and makes no writes for it to protect, so there the check runs without it.
     */
    async function memberships(tx, userId, workspaceIds, readOnly = false) {
        const ids = workspaceIds.filter(id => typeof id === 'string' && uuid.test(id)).map(id => id.toLowerCase());
        if (!ids.length || typeof userId !== 'string')
            return [];
        const query = tx.select({ workspaceId: workspace.id, name: workspace.name, role: membership.role })
            .from(membership).innerJoin(workspace, eq(workspace.id, membership.workspaceId))
            .where(and(eq(membership.userId, userId), inArray(membership.workspaceId, ids)))
            .orderBy(workspace.createdAt, workspace.id);
        return readOnly ? query : query.for('share', { of: membership });
    }
    return {
        setting, column, tables,
        /** The policy for a scoped table's Drizzle callback: every command, every role, USING and WITH CHECK the scope. */
        policy(name) {
            return pgPolicy(name, { as: 'permissive', for: 'all', to: 'public', using: scope, withCheck: scope });
        },
        /**
         * The custom migration step's FORCE statements, separated as drizzle-kit separates statements. Returned as text for
         * the migration file, never executed here; the table names are the identifiers checked by `createTenancy`.
         */
        forceRowLevelSecurity() {
            return tables.map(table => `ALTER TABLE "${table}" FORCE ROW LEVEL SECURITY;`).join('\n--> statement-breakpoint\n');
        },
        /**
         * Authorizes `userId` as a member of `workspaceId` (viewers read; editors, admins and owners write) and runs `run` in
         * one transaction whose row-level security admits that workspace only. `read` makes that transaction READ ONLY once
         * the membership is checked (its share lock cannot be taken in a read-only transaction). `outer` joins a transaction
         * the caller already holds (workspace creation inserts the workspace first), and `db` may itself be a transaction (a
         * savepoint): the caller then owns commit, rollback and access mode, and gets its own scope back afterwards.
         */
        async withWorkspace(db, userId, workspaceId, mode, run, outer) {
            const nested = outer !== undefined || db instanceof PgTransaction;
            const scoped = async (tx) => {
                const caller = nested ? await readCaller(tx) : undefined;
                const [access] = await memberships(tx, userId, [workspaceId], caller?.readOnly);
                if (!access || (mode !== 'read' && !writers.includes(access.role)))
                    throw new WorkspaceAccessError();
                if (mode === 'read' && !nested)
                    await tx.setTransaction({ accessMode: 'read only' });
                return inScope(tx, [access.workspaceId], caller, () => run(tx, access));
            };
            return outer ? scoped(outer) : transaction(db, scoped);
        },
        /**
         * For reads: runs `run` in one READ ONLY transaction scoped to those of `workspaceIds` the user is a member of. Ids
         * the user cannot reach are left out silently; `run` receives the ones admitted. Given a transaction as `db` it runs in
         * a savepoint, as `withWorkspace` does, and restores the caller's scope.
         */
        withWorkspaces(db, userId, workspaceIds, run) {
            const nested = db instanceof PgTransaction;
            return transaction(db, async (tx) => {
                const caller = nested ? await readCaller(tx) : undefined;
                const access = await memberships(tx, userId, workspaceIds, caller?.readOnly);
                if (!nested)
                    await tx.setTransaction({ accessMode: 'read only' });
                return inScope(tx, access.map(item => item.workspaceId), caller, () => run(tx, access));
            });
        },
        /**
         * Boot and test assertion: the connected role is not a superuser, cannot bypass row-level security, neither owns nor
         * is a member of the owner of any public table, and every scoped table (`checked`, by default all of them) forces
         * row-level security with exactly one policy, the workspace policy, for every command and role (USING and WITH
         * CHECK). Without this the policies are silently inert or could be widened by an extra permissive policy.
         */
        async assertDatabaseRoles(pool, checked = tables) {
            // A raw, parameterised statement by necessity: it reads the system catalogues, which have no Drizzle schema, and
            // takes a pg pool so it can run at boot before any Drizzle database exists.
            const { rows } = await pool.query(`SELECT r.rolsuper, r.rolbypassrls,
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
         FROM pg_roles r WHERE r.rolname = current_user`, [checked, deparseNoise, storedScope]);
            const role = rows[0];
            const problems = !role ? ['the connected role was not found'] : [
                ...role.rolsuper ? ['it is a superuser'] : [],
                ...role.rolbypassrls ? ['it bypasses row-level security'] : [],
                ...role.owned.length ? [`it owns or inherits the owner of ${role.owned.join(', ')}`] : [],
                ...role.unforced.length ? [`row-level security is not enabled and forced on ${role.unforced.join(', ')}`] : [],
                ...role.unpolicied.length ? [`the workspace policy is missing, altered or accompanied by another policy on ${role.unpolicied.join(', ')}`] : [],
            ];
            if (problems.length)
                throw new DatabaseRoleError(problems);
        },
    };
}
