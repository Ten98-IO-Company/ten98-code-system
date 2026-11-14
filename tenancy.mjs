// Workspace tenancy by forced row-level security, promoted from Books src/server/tenancy.ts. Every table that holds
// workspace data carries one policy admitting the workspaces listed in a transaction-local setting, and is read and
// written only inside `withWorkspace` (or, for reads across the caller's own workspaces, `withWorkspaces`). The app
// configures the setting, column and tables once with `createTenancy` and keeps its routes, roles and how a refusal
// becomes its response. drizzle-orm and pg are exact, optional peer dependencies.
//
// Drizzle declares the policy (`policy`) and ENABLE ROW LEVEL SECURITY (`pgTable(...).enableRLS()`). FORCE, the roles
// and their grants are SQL in the app's custom migration step; `forceRowLevelSecurity` writes the FORCE part.
import { and, eq, inArray, sql } from 'drizzle-orm';
import { pgPolicy } from 'drizzle-orm/pg-core';
import { membership, workspace } from './db.mjs';
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
    const scope = sql.raw(`${column} = ANY (string_to_array(current_setting('${setting}', true), ','))`);
    // The scope as PostgreSQL stores it in pg_policies once `deparseNoise` is removed.
    const storedScope = `${column}=ANYstring_to_arraycurrent_setting'${setting}',true,','`;
    /** Sets, for the rest of the current transaction only, the workspaces row-level security admits. */
    async function setScope(tx, workspaceIds) {
        await tx.execute(sql `SELECT set_config(${setting}, ${workspaceIds.join(',')}, true)`);
    }
    /**
     * The caller's memberships among `workspaceIds`, taken inside the transaction. Each membership row is share-locked
     * until commit (the team controller's caller-membership convention), so a removal or demotion waits for an in-flight
     * workspace transaction and cannot commit between this check and its writes. The workspace row is not locked: team
     * changes lock it first, and tenant transactions must not queue behind them or hold them up.
     */
    async function memberships(tx, userId, workspaceIds) {
        const ids = workspaceIds.filter(id => typeof id === 'string' && uuid.test(id)).map(id => id.toLowerCase());
        if (!ids.length || typeof userId !== 'string')
            return [];
        return tx.select({ workspaceId: workspace.id, name: workspace.name, role: membership.role })
            .from(membership).innerJoin(workspace, eq(workspace.id, membership.workspaceId))
            .where(and(eq(membership.userId, userId), inArray(membership.workspaceId, ids)))
            .orderBy(workspace.createdAt, workspace.id)
            .for('share', { of: membership });
    }
    return {
        setting, column, tables,
        /** The policy for a scoped table's Drizzle callback: every command, every role, USING and WITH CHECK the scope. */
        policy(name) {
            return pgPolicy(name, { as: 'permissive', for: 'all', to: 'public', using: scope, withCheck: scope });
        },
        /** The custom migration step's FORCE statements, separated as drizzle-kit separates statements. */
        forceRowLevelSecurity() {
            return tables.map(table => `ALTER TABLE "${table}" FORCE ROW LEVEL SECURITY;`).join('\n--> statement-breakpoint\n');
        },
        setScope,
        /**
         * Authorizes `userId` as a member of `workspaceId` (viewers read; editors, admins and owners write) and runs `run` in
         * one transaction whose row-level security admits that workspace only. `outer` joins a transaction the caller already
         * holds (workspace creation inserts the workspace first); the caller then owns commit and rollback.
         */
        async withWorkspace(db, userId, workspaceId, mode, run, outer) {
            const scoped = async (tx) => {
                const [access] = await memberships(tx, userId, [workspaceId]);
                if (!access || (mode !== 'read' && !writers.includes(access.role)))
                    throw new WorkspaceAccessError();
                await setScope(tx, [access.workspaceId]);
                return run(tx, access);
            };
            return outer ? scoped(outer) : db.transaction(tx => scoped(tx));
        },
        /**
         * For reads: runs `run` in one transaction scoped to those of `workspaceIds` the user is a member of. Ids the user
         * cannot reach are left out silently; `run` receives the ones admitted.
         */
        withWorkspaces(db, userId, workspaceIds, run) {
            return db.transaction(async (tx) => {
                const access = await memberships(tx, userId, workspaceIds);
                await setScope(tx, access.map(item => item.workspaceId));
                return run(tx, access);
            });
        },
        /**
         * Boot and test assertion: the connected role is not a superuser, cannot bypass row-level security, neither owns nor
         * is a member of the owner of any public table, and every scoped table (`checked`, by default all of them) forces
         * row-level security with exactly one policy, the workspace policy, for every command and role (USING and WITH
         * CHECK). Without this the policies are silently inert or could be widened by an extra permissive policy.
         */
        async assertDatabaseRoles(pool, checked = tables) {
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
