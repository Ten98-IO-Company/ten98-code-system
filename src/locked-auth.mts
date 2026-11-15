// The mark on the transactions `withLockedAuth` and `withLockedAuthByEmail` open (@ten98/runtime/auth), read by the
// tenancy helpers and the team controller. A locked-auth transaction holds a user row and must never wait on a
// workspace, membership, invitation or email lock taken after it, so no lock cycle can form between it and a team,
// tenancy or sign-in transaction. Internal: imported by auth, tenancy and workspace-team, not re-exported by index.
//
// The map lives on globalThis, so separate copies of these modules (bundlers load more than one) share it. It holds the
// Drizzle transaction and its pg connection only while the callback runs; a transaction nobody marked is never refused.
/** What a marked transaction already holds: `email` is the normalised email whose advisory lock it took first, if any. */
export type LockedAuthHold = { readonly email: string | undefined };
const key = Symbol.for('ten98.runtime.locked-auth-transactions.v2');
const slot = globalThis as unknown as Record<symbol, WeakMap<object, LockedAuthHold> | undefined>;
const marked = slot[key] ??= new WeakMap<object, LockedAuthHold>();

/** A tenancy helper, a team operation or a lock was called inside a `withLockedAuth` transaction that cannot take it. */
export class LockedAuthTransactionError extends Error {
  readonly code = 'LOCKED_AUTH_TRANSACTION' as const;
  constructor(operation: string) {
    super(`${operation} cannot run inside a withLockedAuth transaction: it holds a user row, so it must not wait on a workspace, membership, invitation or other email lock. Run it in its own transaction.`);
    this.name = 'LockedAuthTransactionError';
  }
}

// A Drizzle database or transaction reaches its pg connection through its session; a pg client is itself the connection.
const connectionOf = (value: object): unknown => (value as { _?: { session?: { client?: unknown } } })._?.session?.client;
const objects = (value: unknown): object[] => {
  if (value === null || typeof value !== 'object') return [];
  const connection = connectionOf(value);
  return connection !== null && typeof connection === 'object' ? [value, connection] : [value];
};
const holdOf = (value: unknown): LockedAuthHold | undefined => objects(value).map(item => marked.get(item)).find(hold => hold !== undefined);

/** Marks the given transactions and connections until the returned function is called. */
export function markLockedAuth(hold: LockedAuthHold, ...targets: object[]): () => void {
  const held = targets.flatMap(objects);
  for (const item of held) marked.set(item, hold);
  return () => { for (const item of held) marked.delete(item); };
}

/** Throws LockedAuthTransactionError when `client` is, or runs on the connection of, a marked transaction. */
export function refuseLockedAuth(client: unknown, operation: string): void {
  if (holdOf(client)) throw new LockedAuthTransactionError(operation);
}

/**
 * The email lock is allowed in a marked transaction only for the email it already holds (taken first, by
 * `withLockedAuthByEmail`), where taking it again changes nothing. After a user row (`withLockedAuth`), or for another
 * email, it would reverse the global lock order and can deadlock against a sign-in by email.
 */
export function refuseLockedEmail(client: unknown, email: string): void {
  const hold = holdOf(client);
  if (hold && hold.email !== email) throw new LockedAuthTransactionError('lockEmail');
}
