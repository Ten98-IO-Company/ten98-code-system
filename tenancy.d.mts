import { type PgPolicy } from 'drizzle-orm/pg-core';
import type pg from 'pg';
import type { WorkspaceRole } from './browser.mjs';
import { type AnyDatabase, type ScopedTransaction } from './db.mjs';
export type { ScopedTransaction } from './db.mjs';
export { InvalidWorkspaceIdError, ScopeNestingError } from './tenancy-scope.mjs';
export type WorkspaceMode = 'read' | 'write';
/** The authorized workspace with its name and the caller's role in it. */
export type WorkspaceAccess = {
    workspaceId: string;
    name: string;
    role: WorkspaceRole;
};
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
/**
 * A narrow SECURITY DEFINER lookup, the only cross-tenant read: one parameterised `SELECT … WHERE … LIMIT 1` on one
 * table, returning a workspace id, or for a verified resolver the workspace id and the principal it verified.
 */
export interface ResolverDeclaration {
    /** The one argument, such as `{ name: 'token_hash', type: 'text' }`. */
    parameter: {
        name: string;
        type: 'text' | 'uuid';
    };
    /** The table the credential is looked up in, which the resolver owner role reads. */
    table: string;
    /** The column the argument is matched against, such as `token_hash`. */
    match: string;
    /** The table's workspace id column; the tenancy column by default. */
    workspace?: string;
    /** For `withVerifiedWorkspace`: the principal's kind, a constant such as `api_key`, and its id column. */
    principal?: {
        kind: string;
        id: string;
    };
    /** Timestamp columns of the principal's row set to now() each time it resolves, such as `last_used_at`. Needs `principal`. */
    touch?: readonly string[];
}
export interface TenancyOptions<TTable extends string, TResolver extends string = string> {
    /** The custom setting that lists the admitted workspace ids, such as `app.workspace_ids`. */
    setting: string;
    /** The workspace id column every scoped table carries, such as `workspace_id`. */
    column: string;
    /** Every table that holds workspace data. */
    tables: readonly TTable[];
    /** The NOLOGIN, BYPASSRLS role that owns the resolvers and nothing else. Required with `resolvers`. */
    resolverOwner?: string;
    /** Every SECURITY DEFINER resolver function, by name. `assertDatabaseRoles` refuses any other function the owner owns. */
    resolvers?: Readonly<Record<TResolver, ResolverDeclaration>>;
}
/**
 * A scoped call nested in a READ ONLY transaction named a membership that this transaction does not hold share-locked,
 * so a removal could commit while its callback still read the workspace. Thrown instead of reading it unlocked.
 */
export declare class UnlockedScopeError extends Error {
    readonly code: 'TENANCY_SCOPE_UNLOCKED';
    constructor();
}
export declare function createTenancy<TTable extends string, TResolver extends string = never>({ setting, column, tables, resolverOwner, resolvers }: TenancyOptions<TTable, TResolver>): {
    setting: string;
    column: string;
    tables: string[];
    /** The transaction-local settings a system scope records its reason and verified principal in, for triggers and audit. */
    reasonSetting: string;
    principalSetting: string;
    /** The declared resolvers, as given to `createTenancy`. */
    resolvers: Readonly<Record<TResolver, ResolverDeclaration>>;
    /** The policy for a scoped table's Drizzle callback: every command, every role, USING and WITH CHECK the scope. */
    policy(name: string): PgPolicy;
    /**
     * The custom migration step's FORCE statements, separated as drizzle-kit separates statements. Returned as text for
     * the migration file, never executed here; the table names are the identifiers checked by `createTenancy`.
     */
    forceRowLevelSecurity(): string;
    /**
     * The custom migration step's statements for every declared resolver: the function, SECURITY DEFINER with a fixed
     * search_path, owned by `resolverOwner`, EXECUTE revoked from PUBLIC and granted to `applicationRole` only. Returned
     * as text with drizzle-kit breakpoints, never executed here. The owner role, its BYPASSRLS and its SELECT (and, for
     * `touch`, UPDATE) grants on the looked-up tables stay in the app's custom step.
     */
    resolverFunctions(applicationRole: string): string;
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
    withWorkspace<TDatabase extends AnyDatabase, T>(db: TDatabase, userId: string, workspaceId: string, mode: WorkspaceMode, run: (tx: ScopedTransaction<TDatabase>, access: WorkspaceAccess) => Promise<T>, outer?: ScopedTransaction<TDatabase>): Promise<T>;
    /**
     * For reads: runs `run` in one READ ONLY transaction scoped to those of `workspaceIds` the user is a member of. Ids
     * the user is not a member of are left out silently; `run` receives the ones admitted. An id that is not a UUID
     * throws InvalidWorkspaceIdError before any statement. Given a transaction as `db` it runs in a savepoint, as
     * `withWorkspace` does, and restores the caller's scope.
     */
    withWorkspaces<TDatabase extends AnyDatabase, T>(db: TDatabase, userId: string, workspaceIds: readonly string[], run: (tx: ScopedTransaction<TDatabase>, access: WorkspaceAccess[]) => Promise<T>): Promise<T>;
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
    assertDatabaseRoles(pool: Queryable, checked?: readonly string[]): Promise<void>;
};
export type Tenancy<TTable extends string = string, TResolver extends string = string> = ReturnType<typeof createTenancy<TTable, TResolver>>;
