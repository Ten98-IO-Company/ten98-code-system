import { type AnyDatabase, type ScopedTransaction } from './db.mjs';
import { type Tenancy } from './tenancy.mjs';
export type { ScopedTransaction } from './db.mjs';
export { InvalidWorkspaceIdError, ScopeNestingError } from './tenancy-scope.mjs';
export { UnlockedScopeError, WorkspaceAccessError } from './tenancy.mjs';
export type SystemMode = 'read' | 'write';
/** The workspace a system scope admits and the reason it was opened. */
export type SystemAccess = {
    workspaceId: string;
    reason: string;
};
/** The principal a verified resolver returned, such as `{ kind: 'api_key', id: '…' }`. */
export type VerifiedPrincipal = {
    kind: string;
    id: string;
};
export type VerifiedAccess = SystemAccess & {
    principal: VerifiedPrincipal;
};
export interface SystemScopeOptions {
    /**
     * Caches verified resolutions in this process for `seconds` (1 to 60). A revoked credential then keeps resolving for
     * up to that long unless the app calls `invalidate(credential)` when it revokes it. Without it every call resolves.
     */
    cache?: {
        seconds: number;
    };
}
/**
 * The system scopes over `tenancy`, which must come from `createTenancy`. They share its lock record, so a system scope
 * and a user scope refuse to nest in each other (ScopeNestingError), and a nested system scope must stay in its
 * caller's workspace. The reason and the verified principal (`kind:id`) are set transaction-locally in
 * `tenancy.reasonSetting` and `tenancy.principalSetting`, for triggers and audit.
 */
export declare function createSystemScope<TResolver extends string>(tenancy: Tenancy<string, TResolver>, { cache }?: SystemScopeOptions): {
    /**
     * Runs `run` in one read-write transaction whose row-level security admits `workspaceId` only, with no membership
     * check, for a job, scheduler, webhook or operator tool. The workspace row is share-locked first, so a missing or
     * deleted workspace is refused with WorkspaceAccessError and a deletion waits for the transaction. `reason` is
     * required and recorded. Given a transaction as `db` it runs in a savepoint and restores the caller's scope.
     */
    withSystemWorkspace<TDatabase extends AnyDatabase, T>(db: TDatabase, { workspaceId, reason }: {
        workspaceId: string;
        reason: string;
    }, run: (tx: ScopedTransaction<TDatabase>, access: SystemAccess) => Promise<T>): Promise<T>;
    /**
     * Resolves `credential` with the declared verified `resolver` and runs `run` in one transaction admitting the
     * workspace it names, with the principal it verified recorded. An unresolved credential, an unusable one and a
     * deleted workspace all get WorkspaceAccessError before any scoped statement. `mode` is `read` by default: the
     * workspace row is share-locked before the transaction turns READ ONLY. `write` needs a `"write": true` entry for
     * the calling file in system-scope.json. Use is recorded by the resolver itself (`touch`), never in the scope.
     */
    withVerifiedWorkspace<TDatabase extends AnyDatabase, T>(db: TDatabase, { resolver, credential, reason, mode }: {
        resolver: TResolver;
        credential: string;
        reason: string;
        mode?: SystemMode;
    }, run: (tx: ScopedTransaction<TDatabase>, access: VerifiedAccess) => Promise<T>): Promise<T>;
    /**
     * The workspace id a declared workspace `resolver` (one without a principal) returns for `credential`, or undefined.
     * The only cross-tenant read: run it outside any scope, then open `withSystemWorkspace` on the id.
     */
    resolveWorkspace(db: AnyDatabase, resolver: TResolver, credential: string): Promise<string | undefined>;
    /** Drops every cached resolution of `credential` at once; call it when the app revokes that credential. */
    invalidate(credential: string): void;
};
export type SystemScope<TResolver extends string = string> = ReturnType<typeof createSystemScope<TResolver>>;
