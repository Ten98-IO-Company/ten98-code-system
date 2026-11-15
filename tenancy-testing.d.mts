import type { Tenancy } from './tenancy.mjs';
type Queryable = {
    query(text: string, values?: unknown[]): Promise<unknown>;
};
/** What the scope setting holds, in a database prepared by `requireScopeForTesting`, while no scope is set. */
export declare const unscopedForTesting = "ten98:unscoped";
/**
 * For the rest of the caller's open transaction (`set_config(…, true)`), row-level security admits exactly
 * `workspaceIds`; an empty list admits none. Every id must be a UUID, so nothing but workspace ids reaches the
 * comma-separated setting. Outside a transaction the setting lasts only for this statement and admits nothing after.
 */
export declare function setScopeForTesting(client: Queryable, tenancy: Pick<Tenancy, 'setting'>, workspaceIds: readonly string[]): Promise<void>;
/**
 * Test databases only. A query on a scoped table with no scope set returns no rows rather than failing; after this, it
 * raises "No tenancy scope is set" as soon as it reaches a row, so a missed scope fails the test (an insert with no
 * scope already fails the workspace policy's check). Seed the tables the test reads. An empty scope that a helper set on
 * purpose (`withWorkspaces` with no membership) still admits nothing quietly. Run it on the test database as its owner
 * or a superuser, before the application role connects: it makes `unscopedForTesting` the database's default for the
 * setting, which only new connections read. It also adds a RESTRICTIVE policy, `<table>_requires_scope`, to every scoped
 * table, so `assertDatabaseRoles` refuses that database: run the role assertion against a database without it.
 * Production policies are unchanged.
 */
export declare function requireScopeForTesting(client: Queryable, tenancy: Pick<Tenancy, 'setting' | 'tables'>): Promise<void>;
export {};
