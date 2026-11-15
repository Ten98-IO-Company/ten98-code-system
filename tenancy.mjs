// Workspace tenancy by forced row-level security, promoted from Books src/server/tenancy.ts. Every table that holds
// workspace data carries one policy admitting the workspaces listed in a transaction-local setting, and is read and
// written only inside `withWorkspace` (or, for reads across the caller's own workspaces, `withWorkspaces`). The app
// configures the setting, column and tables once with `createTenancy` and keeps its routes, roles and how a refusal
// becomes its response. drizzle-orm and pg are exact, optional peer dependencies. Work with no user (jobs, webhooks,
// verified credentials) uses the separate @ten98/runtime/tenancy/system entry over the same tenancy.
//
// Drizzle declares the policy (`policy`) and ENABLE ROW LEVEL SECURITY (`pgTable(...).enableRLS()`). FORCE, the roles
// and their grants are SQL in the app's custom migration step; `forceRowLevelSecurity` writes the FORCE part and
// `resolverFunctions` the declared resolvers.
import { and, eq, inArray, sql } from 'drizzle-orm';
import { pgPolicy } from 'drizzle-orm/pg-core';
import { membership, workspace } from './db.mjs';
import { mechanics, scopeMechanics, workspaceIdOf } from './tenancy-scope.mjs';
export { InvalidWorkspaceIdError, ScopeNestingError } from './tenancy-scope.mjs';
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
/**
 * A scoped call nested in a READ ONLY transaction named a membership that this transaction does not hold share-locked,
 * so a removal could commit while its callback still read the workspace. Thrown instead of reading it unlocked.
 */
export class UnlockedScopeError extends Error {
    code = 'TENANCY_SCOPE_UNLOCKED';
    constructor() {
        super('A scoped call nested in a READ ONLY transaction may admit only memberships the transaction\'s own helper call share-locked. Open the outer call for the same user over those workspaces (withWorkspaces), or make it a write call.');
        this.name = 'UnlockedScopeError';
    }
}
const writers = ['owner', 'admin', 'editor'];
const pair = (userId, workspaceId) => `${userId}\u0000${workspaceId}`;
// Lowercase names only: they go into SQL text unquoted, and PostgreSQL's stored policy then matches them verbatim.
const identifier = /^[a-z_][a-z0-9_]*$/;
const settingName = /^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$/;
// Removes PostgreSQL's deparse formatting (whitespace, parentheses, `::text` casts) from a stored policy, never the expression.
const deparseNoise = String.raw `[\s()]|::text(\[\])?`;
const name = (value) => typeof value === 'string' && identifier.test(value);
// The one search_path every resolver fixes, as pg_proc.proconfig stores it.
const resolverSearchPath = 'search_path=pg_catalog, pg_temp';
function checkResolvers(column, owner, resolvers) {
    if (resolvers === undefined)
        return;
    const fail = (message) => { throw new TypeError(`Tenancy resolvers: ${message}`); };
    if (!resolvers || typeof resolvers !== 'object' || Array.isArray(resolvers))
        fail('declare them as an object keyed by function name.');
    if (!name(owner))
        fail('resolverOwner must be a lowercase SQL identifier.');
    for (const [key, resolver] of Object.entries(resolvers)) {
        const { parameter, table, match, workspace: ws = column, principal, touch } = (resolver ?? {});
        if (!name(key))
            fail(`${key} is not a lowercase SQL identifier.`);
        if (!parameter || !name(parameter.name) || (parameter.type !== 'text' && parameter.type !== 'uuid'))
            fail(`${key} needs a parameter with a lowercase name and type text or uuid.`);
        if (!name(table) || !name(match) || !name(ws))
            fail(`${key} needs lowercase table, match and workspace column names.`);
        if (principal !== undefined && (!principal || !name(principal.kind) || !name(principal.id)))
            fail(`${key} needs a principal with a lowercase kind and id column.`);
        if (touch !== undefined && (!Array.isArray(touch) || !touch.length || !touch.every(name) || !principal))
            fail(`${key} touches lowercase columns of its principal's row only.`);
    }
}
/**
 * The resolver's DDL. The body is one parameterised statement on one table, its argument bound as `$1`, returning at
 * most one row of the declared columns. With `touch` it is an UPDATE of the principal's row (VOLATILE), so recording use
 * happens inside the resolver, before any read-only scope begins.
 */
function resolverStatements(key, resolver, column, owner, applicationRole) {
    const { parameter, table, match, workspace: ws = column, principal, touch } = resolver;
    const signature = `public."${key}"(${parameter.type})`, from = `public."${table}"`;
    const returned = [`"${ws}"::uuid`, ...principal ? [`'${principal.kind}'::text`, `"${principal.id}"::text`] : []].join(', ');
    const lookup = principal && touch
        ? `UPDATE ${from} SET ${touch.map(item => `"${item}" = now()`).join(', ')} WHERE "${principal.id}" = (SELECT "${principal.id}" FROM ${from} WHERE "${match}" = $1 LIMIT 1) RETURNING ${returned}`
        : `SELECT ${returned} FROM ${from} WHERE "${match}" = $1 LIMIT 1`;
    const shape = principal ? `"${parameter.name}" ${parameter.type}, OUT workspace_id uuid, OUT principal_kind text, OUT principal_id text)`
        : `"${parameter.name}" ${parameter.type}) RETURNS uuid`;
    return [
        `CREATE OR REPLACE FUNCTION public."${key}"(${shape} LANGUAGE sql ${touch ? 'VOLATILE' : 'STABLE'} SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $resolver$${lookup}$resolver$;`,
        `ALTER FUNCTION ${signature} OWNER TO "${owner}";`,
        `REVOKE ALL ON FUNCTION ${signature} FROM PUBLIC;`,
        `GRANT EXECUTE ON FUNCTION ${signature} TO "${applicationRole}";`,
    ];
}
export function createTenancy({ setting, column, tables, resolverOwner, resolvers }) {
    if (typeof setting !== 'string' || !settingName.test(setting))
        throw new TypeError('The tenancy setting must be a lowercase custom setting name such as app.workspace_ids.');
    if (!name(column))
        throw new TypeError('The tenancy column must be a lowercase SQL identifier.');
    if (!Array.isArray(tables) || !tables.length || !tables.every(name))
        throw new TypeError('The tenancy tables must be lowercase SQL identifiers.');
    checkResolvers(column, resolverOwner, resolvers);
    const declared = { ...resolvers };
    // Raw by necessity: a policy is DDL, which takes no bind parameters. Only the two names checked above are interpolated.
    const scope = sql.raw(`${column} = ANY (string_to_array(current_setting('${setting}', true), ','))`);
    // The scope as PostgreSQL stores it in pg_policies once `deparseNoise` is removed.
    const storedScope = `${column}=ANYstring_to_arraycurrent_setting'${setting}',true,','`;
    const scoped = scopeMechanics(setting);
    const { inScope, scopedTransaction } = scoped;
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
    async function memberships(tx, userId, ids, caller, record, locked) {
        if (!ids.length || typeof userId !== 'string')
            return [];
        const query = tx.select({ workspaceId: workspace.id, name: workspace.name, role: membership.role, started: sql `extract(epoch from transaction_timestamp())::text` })
            .from(membership).innerJoin(workspace, eq(workspace.id, membership.workspaceId))
            .where(and(eq(membership.userId, userId), inArray(membership.workspaceId, ids)))
            .orderBy(workspace.createdAt, workspace.id);
        const rows = caller?.readOnly ? await query : await query.for('share', { of: membership });
        if (!caller?.readOnly) {
            if (record) {
                record.started = rows[0]?.started;
                for (const item of rows)
                    record.pairs.add(pair(userId, item.workspaceId));
            }
        }
        else if (rows.length && (!locked?.open || locked.kind !== 'user' || rows[0].started !== locked.started || rows.some(item => !locked.pairs.has(pair(userId, item.workspaceId))))) {
            throw new UnlockedScopeError();
        }
        return rows.map(({ workspaceId, name, role }) => ({ workspaceId, name, role }));
    }
    const tenancy = {
        setting, column, tables,
        /** The transaction-local settings a system scope records its reason and verified principal in, for triggers and audit. */
        reasonSetting: scoped.reasonSetting, principalSetting: scoped.principalSetting,
        /** The declared resolvers, as given to `createTenancy`. */
        resolvers: declared,
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
         * The custom migration step's statements for every declared resolver: the function, SECURITY DEFINER with a fixed
         * search_path, owned by `resolverOwner`, EXECUTE revoked from PUBLIC and granted to `applicationRole` only. Returned
         * as text with drizzle-kit breakpoints, never executed here. The owner role, its BYPASSRLS and its SELECT (and, for
         * `touch`, UPDATE) grants on the looked-up tables stay in the app's custom step.
         */
        resolverFunctions(applicationRole) {
            if (!name(applicationRole) || applicationRole === resolverOwner)
                throw new TypeError('resolverFunctions needs the application role, a lowercase SQL identifier other than the resolver owner.');
            return Object.entries(declared).flatMap(([key, resolver]) => resolverStatements(key, resolver, column, resolverOwner, applicationRole)).join('\n--> statement-breakpoint\n');
        },
        /**
         * Authorizes `userId` as a member of `workspaceId` (viewers read; editors, admins and owners write) and runs `run` in
         * one transaction whose row-level security admits that workspace only. `read` makes that transaction READ ONLY once
         * the membership is checked (its share lock cannot be taken in a read-only transaction). `outer` joins a transaction
         * the caller already holds (workspace creation inserts the workspace first), and `db` may itself be a transaction (a
         * savepoint): the caller then owns commit, rollback and access mode, and gets its own scope back afterwards. Nested in
         * a READ ONLY transaction it admits only this user's memberships that the transaction's top-level helper call locked.
         * A workspace id that is not a UUID throws InvalidWorkspaceIdError before any statement; nested in a system scope it
         * throws ScopeNestingError.
         */
        async withWorkspace(db, userId, workspaceId, mode, run, outer) {
            const id = workspaceIdOf(workspaceId);
            return scopedTransaction(db, outer, 'user', async (tx, caller, record, locked) => {
                const [access] = await memberships(tx, userId, [id], caller, record, locked);
                if (!access || (mode !== 'read' && !writers.includes(access.role)))
                    throw new WorkspaceAccessError();
                if (mode === 'read' && !caller)
                    await tx.setTransaction({ accessMode: 'read only' });
                return inScope(tx, 'user', [access.workspaceId, '', ''], caller, () => run(tx, access));
            });
        },
        /**
         * For reads: runs `run` in one READ ONLY transaction scoped to those of `workspaceIds` the user is a member of. Ids
         * the user is not a member of are left out silently; `run` receives the ones admitted. An id that is not a UUID
         * throws InvalidWorkspaceIdError before any statement. Given a transaction as `db` it runs in a savepoint, as
         * `withWorkspace` does, and restores the caller's scope.
         */
        withWorkspaces(db, userId, workspaceIds, run) {
            if (!Array.isArray(workspaceIds))
                return Promise.reject(new TypeError('withWorkspaces needs an array of workspace ids.'));
            let ids;
            try {
                ids = workspaceIds.map(workspaceIdOf);
            }
            catch (error) {
                return Promise.reject(error);
            }
            return scopedTransaction(db, undefined, 'user', async (tx, caller, record, locked) => {
                const access = await memberships(tx, userId, ids, caller, record, locked);
                if (!caller)
                    await tx.setTransaction({ accessMode: 'read only' });
                return inScope(tx, 'user', [access.map(item => item.workspaceId).join(','), '', ''], caller, () => run(tx, access));
            });
        },
        /**
         * Boot and test assertion: the connected role is not a superuser, cannot bypass row-level security, neither owns nor
         * is a member of the owner of any public table, and every scoped table (`checked`, by default all of them) forces
         * row-level security with exactly one policy, the workspace policy, for every command and role (USING and WITH
         * CHECK). Without this the policies are silently inert or could be widened by an extra permissive policy.
         *
         * With resolvers declared it also checks each one's shape (SECURITY DEFINER, LANGUAGE sql, the fixed search_path,
         * the declared argument and return, no overload, EXECUTE for this role and not for PUBLIC, owned by `resolverOwner`),
         * the owner role (NOLOGIN, not a superuser, BYPASSRLS, owning no relation, not a role this one is a member of), and
         * that the owner owns no function that is not declared. It does not read function bodies; review those by hand.
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
            if (resolverOwner !== undefined)
                problems.push(...await resolverProblems(pool));
            if (problems.length)
                throw new DatabaseRoleError(problems);
        },
    };
    // The declared resolvers against the catalogue, and every function their owner owns.
    async function resolverProblems(pool) {
        // A raw, parameterised statement by necessity, as above: it reads pg_proc, pg_roles and pg_class.
        const { rows } = await pool.query(`SELECT COALESCE((SELECT json_agg(json_build_object('name', p.proname, 'schema', n.nspname, 'kind', p.prokind, 'definer', p.prosecdef,
           'set', p.proretset, 'language', l.lanname, 'config', p.proconfig, 'arguments', pg_get_function_arguments(p.oid),
           'result', pg_get_function_result(p.oid), 'owner', o.rolname, 'executable', has_function_privilege(current_user, p.oid, 'EXECUTE'),
           'publicExecute', p.proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'))
           ORDER BY n.nspname, p.proname, p.oid)
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang JOIN pg_roles o ON o.oid = p.proowner
         WHERE (n.nspname = 'public' AND p.proname = ANY ($1::text[])) OR o.rolname = $2), '[]'::json) AS functions,
         (SELECT json_build_object('canlogin', r.rolcanlogin, 'superuser', r.rolsuper, 'bypass', r.rolbypassrls,
           'member', pg_has_role(current_user, r.oid, 'MEMBER'),
           'owned', ARRAY(SELECT c.relname::text FROM pg_class c WHERE c.relowner = r.oid ORDER BY 1))
          FROM pg_roles r WHERE r.rolname = $2) AS owner`, [Object.keys(declared), resolverOwner]);
        const { functions, owner } = rows[0];
        const problems = [];
        if (!owner)
            problems.push(`the resolver owner ${resolverOwner} was not found`);
        else {
            const wrong = [...owner.canlogin ? ['can log in'] : [], ...owner.superuser ? ['is a superuser'] : [], ...!owner.bypass ? ['lacks BYPASSRLS'] : [],
                ...owner.member ? ['is a role the application role is a member of'] : [], ...owner.owned.length ? [`owns ${owner.owned.join(', ')}`] : []];
            if (wrong.length)
                problems.push(`the resolver owner ${resolverOwner} ${wrong.join(', ')}`);
        }
        for (const [key, resolver] of Object.entries(declared)) {
            const found = functions.filter(item => item.schema === 'public' && item.name === key);
            if (found.length !== 1) {
                problems.push(found.length ? `resolver ${key} is overloaded` : `resolver ${key} is missing`);
                continue;
            }
            const fn = found[0], expected = resolverShape(resolver);
            const wrong = [...fn.kind !== 'f' || fn.set || fn.arguments !== expected.arguments || fn.result !== expected.result ? ['has another signature or return'] : [],
                ...!fn.definer ? ['is not SECURITY DEFINER'] : [], ...fn.language !== 'sql' ? ['is not LANGUAGE sql'] : [],
                ...fn.config?.length !== 1 || fn.config[0] !== resolverSearchPath ? [`does not fix ${resolverSearchPath} alone`] : [],
                ...fn.owner !== resolverOwner ? [`is not owned by ${resolverOwner}`] : [], ...!fn.executable ? ['is not executable by this role'] : [],
                ...fn.publicExecute ? ['is executable by PUBLIC'] : []];
            if (wrong.length)
                problems.push(`resolver ${key} ${wrong.join(', ')}`);
        }
        const undeclared = functions.filter(item => item.owner === resolverOwner && !(item.schema === 'public' && Object.hasOwn(declared, item.name)));
        if (undeclared.length)
            problems.push(`the resolver owner ${resolverOwner} owns undeclared functions ${undeclared.map(item => `${item.schema}.${item.name}(${item.arguments})`).join(', ')}`);
        return problems;
    }
    mechanics.set(tenancy, scoped);
    return tenancy;
}
// How pg_get_function_arguments and pg_get_function_result print a declared resolver.
function resolverShape({ parameter, principal }) {
    return principal ? { arguments: `${parameter.name} ${parameter.type}, OUT workspace_id uuid, OUT principal_kind text, OUT principal_id text`, result: 'record' }
        : { arguments: `${parameter.name} ${parameter.type}`, result: 'uuid' };
}
