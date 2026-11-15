// Test-only: sets the row-level security scope on a connection the test owns, so database guard tests can act as the
// application role with any scope (several workspaces, or ones the role has no membership in) without the membership
// check, and makes a missing scope fail loudly in a test database. Applications never import this: the scope is set
// only by the tenancy helpers. It is a separate entry point, absent from @ten98/runtime/tenancy, so an application
// import shows in review.
import type { Tenancy } from './tenancy.mjs';

type Queryable = { query(text: string, values?: unknown[]): Promise<unknown> };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const identifier = /^[a-z_][a-z0-9_]*$/;
const settingName = /^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)+$/;

/** What the scope setting holds, in a database prepared by `requireScopeForTesting`, while no scope is set. */
export const unscopedForTesting = 'ten98:unscoped';

/**
 * For the rest of the caller's open transaction (`set_config(…, true)`), row-level security admits exactly
 * `workspaceIds`; an empty list admits none. Every id must be a UUID, so nothing but workspace ids reaches the
 * comma-separated setting. Outside a transaction the setting lasts only for this statement and admits nothing after.
 */
export async function setScopeForTesting(client: Queryable, tenancy: Pick<Tenancy, 'setting'>, workspaceIds: readonly string[]): Promise<void> {
  if (!Array.isArray(workspaceIds) || !workspaceIds.every(id => typeof id === 'string' && uuid.test(id))) {
    throw new TypeError('setScopeForTesting needs workspace ids that are UUIDs.');
  }
  // A raw, parameterised statement by necessity: it takes a pg connection, and Drizzle has no builder for set_config.
  await client.query('SELECT set_config($1, $2, true)', [tenancy.setting, workspaceIds.map(id => id.toLowerCase()).join(',')]);
}

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
export async function requireScopeForTesting(client: Queryable, tenancy: Pick<Tenancy, 'setting' | 'tables'>): Promise<void> {
  const { setting, tables } = tenancy;
  if (typeof setting !== 'string' || !settingName.test(setting) || !Array.isArray(tables) || !tables.length || !tables.every(table => typeof table === 'string' && identifier.test(table))) {
    throw new TypeError('requireScopeForTesting needs a tenancy from createTenancy.');
  }
  const check = `public.ten98_require_scope('${setting}')`;
  // Raw by necessity: DDL takes no bind parameters. Only the setting and table names checked above are interpolated.
  // The tiny COST makes the planner evaluate this check before the workspace policy, which would otherwise reject each
  // row first and never reach it.
  await client.query(`CREATE OR REPLACE FUNCTION public.ten98_require_scope(setting text) RETURNS boolean LANGUAGE plpgsql STABLE COST 0.0001 AS $require$
    BEGIN
      IF current_setting(setting, true) IS NOT DISTINCT FROM '${unscopedForTesting}' THEN
        RAISE EXCEPTION 'No tenancy scope is set for %', setting USING HINT = 'Run the query inside withWorkspace, withWorkspaces or a system scope.';
      END IF;
      RETURN true;
    END $require$;
    DO $default$ BEGIN EXECUTE format('ALTER DATABASE %I SET ${setting} = %L', current_database(), '${unscopedForTesting}'); END $default$;
    ${tables.map(table => `DROP POLICY IF EXISTS "${table}_requires_scope" ON "${table}";
    CREATE POLICY "${table}_requires_scope" ON "${table}" AS RESTRICTIVE FOR ALL TO public USING (${check}) WITH CHECK (${check});`).join('\n    ')}`);
}
