const key = Symbol.for('ten98.runtime.locked-auth-transactions.v2');
const slot = globalThis;
const marked = slot[key] ??= new WeakMap();
/** A tenancy helper, a team operation or a lock was called inside a `withLockedAuth` transaction that cannot take it. */
export class LockedAuthTransactionError extends Error {
    code = 'LOCKED_AUTH_TRANSACTION';
    constructor(operation) {
        super(`${operation} cannot run inside a withLockedAuth transaction: it holds a user row, so it must not wait on a workspace, membership, invitation or other email lock. Run it in its own transaction.`);
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
const holdOf = (value) => objects(value).map(item => marked.get(item)).find(hold => hold !== undefined);
/** Marks the given transactions and connections until the returned function is called. */
export function markLockedAuth(hold, ...targets) {
    const held = targets.flatMap(objects);
    for (const item of held)
        marked.set(item, hold);
    return () => { for (const item of held)
        marked.delete(item); };
}
/**
 * The user row a by-id `withLockedAuth` transaction locked: undefined outside one, and for `withLockedAuthByEmail`,
 * whose account is the one behind an email being signed in to, not a signed-in user.
 */
export function lockedAuthUser(client) {
    const hold = holdOf(client);
    return hold?.email === undefined ? hold?.userId : undefined;
}
/** Throws LockedAuthTransactionError when `client` is, or runs on the connection of, a marked transaction. */
export function refuseLockedAuth(client, operation) {
    if (holdOf(client))
        throw new LockedAuthTransactionError(operation);
}
/**
 * The email lock is allowed in a marked transaction only for the email it already holds (taken first, by
 * `withLockedAuthByEmail`), where taking it again changes nothing. After a user row (`withLockedAuth`), or for another
 * email, it would reverse the global lock order and can deadlock against a sign-in by email.
 */
export function refuseLockedEmail(client, email) {
    const hold = holdOf(client);
    if (hold && hold.email !== email)
        throw new LockedAuthTransactionError('lockEmail');
}
