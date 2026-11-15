// The mark on the transactions `withLockedAuth` and `withLockedAuthByEmail` open (@ten98/runtime/auth), read by the
// tenancy helpers and the workspace-level team operations, which refuse a marked transaction. A locked-auth transaction
// holds a user row and must never wait on a workspace, membership or invitation lock, so no lock cycle can form between
// it and a team or tenancy transaction. Internal: imported by auth, tenancy and workspace-team, not re-exported by index.
//
// The set lives on globalThis, so separate copies of these modules (bundlers load more than one) share it. It holds the
// Drizzle transaction and its pg connection only while the callback runs; a transaction nobody marked is never refused.
const key = Symbol.for('ten98.runtime.locked-auth-transactions');
const slot = globalThis;
const marked = slot[key] ??= new WeakSet();
/** A tenancy helper or a workspace-level team operation was called inside a `withLockedAuth` transaction. */
export class LockedAuthTransactionError extends Error {
    code = 'LOCKED_AUTH_TRANSACTION';
    constructor(operation) {
        super(`${operation} cannot run inside a withLockedAuth transaction: it holds a user row and must not wait on workspace, membership or invitation locks. Run it in its own transaction.`);
        this.name = 'LockedAuthTransactionError';
    }
}
// A Drizzle database or transaction reaches its pg connection through its session; a pg client is itself the connection.
const connectionOf = (value) => value._?.session?.client;
const objects = (value) => {
    if (value === null || typeof value !== 'object')
        return [];
    const connection = connectionOf(value);
    return connection !== null && typeof connection === 'object' ? [value, connection] : [value];
};
/** Marks a transaction and its connection until the returned function is called. */
export function markLockedAuth(transaction) {
    const held = objects(transaction);
    for (const item of held)
        marked.add(item);
    return () => { for (const item of held)
        marked.delete(item); };
}
/** Throws LockedAuthTransactionError when `client` is, or runs on the connection of, a marked transaction. */
export function refuseLockedAuth(client, operation) {
    if (objects(client).some(item => marked.has(item)))
        throw new LockedAuthTransactionError(operation);
}
