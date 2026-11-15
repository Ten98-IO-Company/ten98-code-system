const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/**
 * For the rest of the caller's open transaction (`set_config(…, true)`), row-level security admits exactly
 * `workspaceIds`; an empty list admits none. Every id must be a UUID, so nothing but workspace ids reaches the
 * comma-separated setting. Outside a transaction the setting lasts only for this statement and admits nothing after.
 */
export async function setScopeForTesting(client, tenancy, workspaceIds) {
    if (!Array.isArray(workspaceIds) || !workspaceIds.every(id => typeof id === 'string' && uuid.test(id))) {
        throw new TypeError('setScopeForTesting needs workspace ids that are UUIDs.');
    }
    // A raw, parameterised statement by necessity: it takes a pg connection, and Drizzle has no builder for set_config.
    await client.query('SELECT set_config($1, $2, true)', [tenancy.setting, workspaceIds.map(id => id.toLowerCase()).join(',')]);
}
