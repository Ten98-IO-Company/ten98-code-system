import { type AnyDatabase, type ScopedTransaction } from './db.mjs';
/** A user scope (membership checked) or a system scope (no user: a job, a webhook, a verified credential). */
export type ScopeKind = 'user' | 'system';
/** What a nested call must respect: the caller's scope settings, to put back, and whether its transaction is READ ONLY. */
export type Caller = {
    scope: string;
    reason: string;
    principal: string;
    readOnly: boolean;
};
/** The three transaction-local settings a scope sets: the admitted workspace ids, and for a system scope its reason and principal. */
export type ScopeValues = readonly [scope: string, reason: string, principal: string];
/**
 * The rows a helper share-locked at the top level of a transaction it opened itself: membership rows as user and
 * workspace pairs for a user scope, the workspace row for a system scope. That check is the transaction's first
 * locking statement, so no savepoint precedes it and nothing short of the transaction's end releases those locks.
 * Locks taken by nested calls are never recorded: a savepoint or a caller's ROLLBACK TO can release them unseen. Keyed
 * by the transaction objects the helpers hand out, the top-level one and the savepoints helpers open inside it; any
 * other transaction object has no record, so nesting there fails closed.
 *
 * A record is valid only for the transaction that made it: `open` turns false when that transaction ends, however it
 * ends, so a transaction object used afterwards (an un-awaited nested call, say) is refused. `started` is that
 * transaction's `transaction_timestamp()`, so a caller's own ROLLBACK and BEGIN inside it, which would start a new
 * transaction on the same connection under the same objects, is refused too.
 */
export type LockRecord = {
    readonly kind: ScopeKind;
    readonly pairs: Set<string>;
    started: string | undefined;
    open: boolean;
};
export declare const held: WeakMap<object, LockRecord>;
export declare const uuid: RegExp;
/** A workspace id that is not a UUID. Thrown before any statement, instead of being dropped or reported as not found. */
export declare class InvalidWorkspaceIdError extends TypeError {
    readonly code: 'TENANCY_WORKSPACE_ID_INVALID';
    constructor();
}
/** A user scope nested in a system scope, a system scope nested in a user scope, or a system scope widened to another workspace. */
export declare class ScopeNestingError extends Error {
    readonly code: 'TENANCY_SCOPE_NESTED';
    constructor();
}
/** The canonical lower-case form of a workspace id, or InvalidWorkspaceIdError. */
export declare function workspaceIdOf(value: unknown): string;
/** The mechanics for one tenancy setting; `createTenancy` builds them and registers them in `mechanics`. */
export declare function scopeMechanics(setting: string): {
    setting: string;
    reasonSetting: string;
    principalSetting: string;
    inScope: <T>(tx: AnyDatabase, kind: ScopeKind, values: ScopeValues, caller: Caller | undefined, run: () => Promise<T>) => Promise<T>;
    scopedTransaction: <TDatabase extends AnyDatabase, T>(db: TDatabase, outer: ScopedTransaction<TDatabase> | undefined, kind: ScopeKind, body: (tx: ScopedTransaction<TDatabase>, caller: Caller | undefined, record: LockRecord | undefined, locked: LockRecord | undefined) => Promise<T>) => Promise<T>;
};
export type ScopeMechanics = ReturnType<typeof scopeMechanics>;
/** Each tenancy `createTenancy` returned, with its mechanics, so only a real tenancy opens a system scope. */
export declare const mechanics: WeakMap<object, {
    setting: string;
    reasonSetting: string;
    principalSetting: string;
    inScope: <T>(tx: AnyDatabase, kind: ScopeKind, values: ScopeValues, caller: Caller | undefined, run: () => Promise<T>) => Promise<T>;
    scopedTransaction: <TDatabase extends AnyDatabase, T>(db: TDatabase, outer: ScopedTransaction<TDatabase> | undefined, kind: ScopeKind, body: (tx: ScopedTransaction<TDatabase>, caller: Caller | undefined, record: LockRecord | undefined, locked: LockRecord | undefined) => Promise<T>) => Promise<T>;
}>;
