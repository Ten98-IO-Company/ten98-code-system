import type { Tenancy } from './tenancy.mjs';
type Queryable = {
    query(text: string, values?: unknown[]): Promise<unknown>;
};
/**
 * For the rest of the caller's open transaction (`set_config(…, true)`), row-level security admits exactly
 * `workspaceIds`; an empty list admits none. Every id must be a UUID, so nothing but workspace ids reaches the
 * comma-separated setting. Outside a transaction the setting lasts only for this statement and admits nothing after.
 */
export declare function setScopeForTesting(client: Queryable, tenancy: Pick<Tenancy, 'setting'>, workspaceIds: readonly string[]): Promise<void>;
export {};
