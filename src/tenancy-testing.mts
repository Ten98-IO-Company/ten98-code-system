// Test-only: sets the row-level security scope on a connection the test owns, so database guard tests can act as the
// application role with any scope (several workspaces, or ones the role has no membership in) without the membership
// check. Applications never import this: the scope is set only by withWorkspace and withWorkspaces, after that check.
// It is a separate entry point, absent from @ten98/runtime/tenancy, so an application import shows in review.
import type { Tenancy } from './tenancy.mjs';

type Queryable = { query(text: string, values?: unknown[]): Promise<unknown> };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
