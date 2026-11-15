/** What a marked transaction already holds: `email` is the normalised email whose advisory lock it took first, if any. */
export type LockedAuthHold = {
    readonly email: string | undefined;
};
/** A tenancy helper, a team operation or a lock was called inside a `withLockedAuth` transaction that cannot take it. */
export declare class LockedAuthTransactionError extends Error {
    readonly code: 'LOCKED_AUTH_TRANSACTION';
    constructor(operation: string);
}
/** Marks the given transactions and connections until the returned function is called. */
export declare function markLockedAuth(hold: LockedAuthHold, ...targets: object[]): () => void;
/** Throws LockedAuthTransactionError when `client` is, or runs on the connection of, a marked transaction. */
export declare function refuseLockedAuth(client: unknown, operation: string): void;
/**
 * The email lock is allowed in a marked transaction only for the email it already holds (taken first, by
 * `withLockedAuthByEmail`), where taking it again changes nothing. After a user row (`withLockedAuth`), or for another
 * email, it would reverse the global lock order and can deadlock against a sign-in by email.
 */
export declare function refuseLockedEmail(client: unknown, email: string): void;
