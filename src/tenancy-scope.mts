// Internal: the scope mechanics that ./tenancy (user scopes) and ./tenancy/system (system and verified scopes) share,
// so the two entries keep one lock record and refuse to nest in each other. Not a package export.
import { sql } from 'drizzle-orm';
import { PgTransaction } from 'drizzle-orm/pg-core';
import { transaction, type AnyDatabase, type ScopedTransaction } from './db.mjs';

/** A user scope (membership checked) or a system scope (no user: a job, a webhook, a verified credential). */
export type ScopeKind = 'user' | 'system';
/** What a nested call must respect: the caller's scope settings, to put back, and whether its transaction is READ ONLY. */
export type Caller = { scope: string; reason: string; principal: string; readOnly: boolean };
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
export type LockRecord = { readonly kind: ScopeKind; readonly pairs: Set<string>; started: string | undefined; open: boolean };
export const held = new WeakMap<object, LockRecord>();
// The kind of scope whose callback a transaction object was handed to, while that callback runs.
const running = new WeakMap<object, ScopeKind>();

export const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A workspace id that is not a UUID. Thrown before any statement, instead of being dropped or reported as not found. */
export class InvalidWorkspaceIdError extends TypeError {
  readonly code = 'TENANCY_WORKSPACE_ID_INVALID' as const;
  constructor() { super('Workspace ids must be UUIDs.'); this.name = 'InvalidWorkspaceIdError'; }
}

/** A user scope nested in a system scope, a system scope nested in a user scope, or a system scope widened to another workspace. */
export class ScopeNestingError extends Error {
  readonly code = 'TENANCY_SCOPE_NESTED' as const;
  constructor() {
    super('A user scope and a system scope cannot be nested in each other, and a nested system scope must stay in its caller\'s workspace. Open a separate transaction.');
    this.name = 'ScopeNestingError';
  }
}

/** The canonical lower-case form of a workspace id, or InvalidWorkspaceIdError. */
export function workspaceIdOf(value: unknown): string {
  if (typeof value !== 'string' || !uuid.test(value)) throw new InvalidWorkspaceIdError();
  return value.toLowerCase();
}

// A caller with no running record shows its kind in its settings: a reason marks a system scope, a list of workspace
// ids with no reason a user scope. Anything else (unset, empty, a test database's unscoped marker) is no scope.
const kindOf = (caller: Caller): ScopeKind | undefined =>
  caller.reason ? 'system' : caller.scope && caller.scope.split(',').every(id => uuid.test(id)) ? 'user' : undefined;

/** The mechanics for one tenancy setting; `createTenancy` builds them and registers them in `mechanics`. */
export function scopeMechanics(setting: string) {
  const reasonSetting = `${setting}_reason`, principalSetting = `${setting}_principal`;
  // Parameterised `sql` statements by necessity: Drizzle has no builder for set_config or current_setting.
  const setScope = (tx: AnyDatabase, [scope, reason, principal]: ScopeValues) =>
    tx.execute(sql`SELECT set_config(${setting}, ${scope}, true), set_config(${reasonSetting}, ${reason}, true), set_config(${principalSetting}, ${principal}, true)`);
  const readCaller = async (tx: AnyDatabase): Promise<Caller> => {
    const { rows } = (await tx.execute(sql`SELECT current_setting(${setting}, true) AS scope, current_setting(${reasonSetting}, true) AS reason,
      current_setting(${principalSetting}, true) AS principal, current_setting('transaction_read_only') AS read_only`)) as unknown as
      { rows: { scope: string | null; reason: string | null; principal: string | null; read_only: string }[] };
    const row = rows[0];
    return { scope: row?.scope ?? '', reason: row?.reason ?? '', principal: row?.principal ?? '', readOnly: row?.read_only === 'on' };
  };

  /**
   * Runs `run` with row-level security admitting `values`. In a transaction of its own the scope lasts to its end. A
   * nested call (`caller`: a caller's transaction or a savepoint, which may already hold a scope) puts the caller's
   * settings back when `run` settles, so the caller never goes on in the inner scope. After an error the transaction may
   * be aborted and refuse the restore; the caller's ROLLBACK, or the savepoint's, then undoes the inner scope. Nested
   * calls on one transaction must be awaited in turn: run at once, their scopes and restores interleave.
   */
  async function inScope<T>(tx: AnyDatabase, kind: ScopeKind, values: ScopeValues, caller: Caller | undefined, run: () => Promise<T>): Promise<T> {
    await setScope(tx, values);
    const before = running.get(tx);
    running.set(tx, kind);
    try {
      if (!caller) return await run();
      let result: T;
      try { result = await run(); } catch (error) { await setScope(tx, [caller.scope, caller.reason, caller.principal]).catch(() => undefined); throw error; }
      await setScope(tx, [caller.scope, caller.reason, caller.principal]);
      return result;
    } finally { if (before) running.set(tx, before); else running.delete(tx); }
  }

  /**
   * Runs `body` in the transaction a helper call uses. A transaction of its own starts a fresh record of the rows its
   * top-level check locks (`record`). A nested call (the caller's `outer`, or a savepoint when `db` is a transaction)
   * gets the caller's state and only reads the record; a savepoint a helper opens shares it. A nested call of the other
   * kind of scope is refused with ScopeNestingError before `body` runs.
   */
  async function scopedTransaction<TDatabase extends AnyDatabase, T>(db: TDatabase, outer: ScopedTransaction<TDatabase> | undefined, kind: ScopeKind,
    body: (tx: ScopedTransaction<TDatabase>, caller: Caller | undefined, record: LockRecord | undefined, locked: LockRecord | undefined) => Promise<T>): Promise<T> {
    const nested = (given: object, caller: Caller) => {
      const other = running.get(given) ?? kindOf(caller);
      if (other && other !== kind) throw new ScopeNestingError();
      return caller;
    };
    if (outer) return body(outer, nested(outer, await readCaller(outer)), undefined, held.get(outer));
    if (!(db instanceof PgTransaction)) {
      const record: LockRecord = { kind, pairs: new Set(), started: undefined, open: true };
      try {
        return await transaction(db, tx => { held.set(tx, record); return body(tx, undefined, record, record); });
      } finally { record.open = false; }
    }
    const locked = held.get(db);
    return transaction(db, async tx => {
      if (locked) held.set(tx, locked);
      return body(tx, nested(db, await readCaller(tx)), undefined, locked);
    });
  }

  return { setting, reasonSetting, principalSetting, inScope, scopedTransaction };
}

export type ScopeMechanics = ReturnType<typeof scopeMechanics>;
/** Each tenancy `createTenancy` returned, with its mechanics, so only a real tenancy opens a system scope. */
export const mechanics = new WeakMap<object, ScopeMechanics>();
