import { type PgDatabase, type PgPolicy, type PgQueryResultHKT, type PgTransaction } from 'drizzle-orm/pg-core';
import type pg from 'pg';
import type { WorkspaceRole } from './browser.mjs';
export type WorkspaceMode = 'read' | 'write';
/** The authorized workspace with its name and the caller's role in it. */
export type WorkspaceAccess = {
    workspaceId: string;
    name: string;
    role: WorkspaceRole;
};
type AnyDatabase = PgDatabase<PgQueryResultHKT, any, any>;
export type ScopedTransaction<TDatabase extends AnyDatabase> = TDatabase extends PgDatabase<infer H, infer F, infer S> ? PgTransaction<H, F, S> : never;
type Queryable = {
    query<R extends pg.QueryResultRow>(text: string, values?: unknown[]): Promise<pg.QueryResult<R>>;
};
/** One answer for a missing workspace and for a workspace the user may not reach (or not write), so ids reveal nothing. */
export declare const workspaceNotFound = "Workspace not found or unavailable.";
export declare class WorkspaceAccessError extends Error {
    readonly status: 404;
    constructor();
}
/** Operator-safe refusal: names the failed checks, never connection details. */
export declare class DatabaseRoleError extends Error {
    constructor(problems: readonly string[]);
}
export interface TenancyOptions<TTable extends string> {
    /** The custom setting that lists the admitted workspace ids, such as `app.workspace_ids`. */
    setting: string;
    /** The workspace id column every scoped table carries, such as `workspace_id`. */
    column: string;
    /** Every table that holds workspace data. */
    tables: readonly TTable[];
}
export declare function createTenancy<TTable extends string>({ setting, column, tables }: TenancyOptions<TTable>): {
    setting: string;
    column: string;
    tables: any[];
    /** The policy for a scoped table's Drizzle callback: every command, every role, USING and WITH CHECK the scope. */
    policy(name: string): PgPolicy;
    /** The custom migration step's FORCE statements, separated as drizzle-kit separates statements. */
    forceRowLevelSecurity(): string;
    setScope: (tx: Pick<AnyDatabase, 'execute'>, workspaceIds: readonly string[]) => Promise<void>;
    /**
     * Authorizes `userId` as a member of `workspaceId` (viewers read; editors, admins and owners write) and runs `run` in
     * one transaction whose row-level security admits that workspace only. `outer` joins a transaction the caller already
     * holds (workspace creation inserts the workspace first); the caller then owns commit and rollback.
     */
    withWorkspace<TDatabase extends AnyDatabase, T>(db: TDatabase, userId: string, workspaceId: string, mode: WorkspaceMode, run: (tx: ScopedTransaction<TDatabase>, access: WorkspaceAccess) => Promise<T>, outer?: ScopedTransaction<TDatabase>): Promise<T>;
    /**
     * For reads: runs `run` in one transaction scoped to those of `workspaceIds` the user is a member of. Ids the user
     * cannot reach are left out silently; `run` receives the ones admitted.
     */
    withWorkspaces<TDatabase extends AnyDatabase, T>(db: TDatabase, userId: string, workspaceIds: readonly string[], run: (tx: ScopedTransaction<TDatabase>, access: WorkspaceAccess[]) => Promise<T>): Promise<T>;
    /**
     * Boot and test assertion: the connected role is not a superuser, cannot bypass row-level security, neither owns nor
     * is a member of the owner of any public table, and every scoped table (`checked`, by default all of them) forces
     * row-level security with exactly one policy, the workspace policy, for every command and role (USING and WITH
     * CHECK). Without this the policies are silently inert or could be widened by an extra permissive policy.
     */
    assertDatabaseRoles(pool: Queryable, checked?: readonly string[]): Promise<void>;
};
export type Tenancy<TTable extends string = string> = ReturnType<typeof createTenancy<TTable>>;
export {};
