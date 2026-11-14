/**
 * Inspect canonical declarations only; this does not discover or migrate databases. `exceptions` and `transitions` are
 * the declaration's general lists; entries for rule `database.engine` name the engine in `items`.
 */
export declare function inspectDatabasePolicy(policy: unknown, profiles: unknown, exceptions?: unknown, transitions?: unknown): string[];
