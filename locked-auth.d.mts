/** A tenancy helper or a workspace-level team operation was called inside a `withLockedAuth` transaction. */
export declare class LockedAuthTransactionError extends Error {
    readonly code: 'LOCKED_AUTH_TRANSACTION';
    constructor(operation: string);
}
/** Marks a transaction and its connection until the returned function is called. */
export declare function markLockedAuth(transaction: object): () => void;
/** Throws LockedAuthTransactionError when `client` is, or runs on the connection of, a marked transaction. */
export declare function refuseLockedAuth(client: unknown, operation: string): void;
