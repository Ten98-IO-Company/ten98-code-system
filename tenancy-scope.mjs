// Internal: the scope mechanics that ./tenancy (user scopes) and ./tenancy/system (system and verified scopes) share,
// so the two entries keep one lock record and refuse to nest in each other. Not a package export.
import { sql } from 'drizzle-orm';
import { PgTransaction } from 'drizzle-orm/pg-core';
import { transaction } from './db.mjs';
export const held = new WeakMap();
// The kind of scope whose callback a transaction object was handed to, while that callback runs.
const running = new WeakMap();
export const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** A workspace id that is not a UUID. Thrown before any statement, instead of being dropped or reported as not found. */
export class InvalidWorkspaceIdError extends TypeError {
    code = 'TENANCY_WORKSPACE_ID_INVALID';
    constructor() { super('Workspace ids must be UUIDs.'); this.name = 'InvalidWorkspaceIdError'; }
}
/** A user scope nested in a system scope, a system scope nested in a user scope, or a system scope widened to another workspace. */
export class ScopeNestingError extends Error {
    code = 'TENANCY_SCOPE_NESTED';
    constructor() {
        super('A user scope and a system scope cannot be nested in each other, and a nested system scope must stay in its caller\'s workspace. Open a separate transaction.');
        this.name = 'ScopeNestingError';
    }
}
/** The canonical lower-case form of a workspace id, or InvalidWorkspaceIdError. */
export function workspaceIdOf(value) {
    if (typeof value !== 'string' || !uuid.test(value))
        throw new InvalidWorkspaceIdError();
    return value.toLowerCase();
}
// A caller with no running record shows its kind in its settings: a reason marks a system scope, a list of workspace
// ids with no reason a user scope. Anything else (unset, empty, a test database's unscoped marker) is no scope.
const kindOf = (caller) => caller.reason ? 'system' : caller.scope && caller.scope.split(',').every(id => uuid.test(id)) ? 'user' : undefined;
/** The mechanics for one tenancy setting; `createTenancy` builds them and registers them in `mechanics`. */
export function scopeMechanics(setting) {
    const reasonSetting = `${setting}_reason`, principalSetting = `${setting}_principal`;
    // Parameterised `sql` statements by necessity: Drizzle has no builder for set_config or current_setting.
    const setScope = (tx, [scope, reason, principal]) => tx.execute(sql `SELECT set_config(${setting}, ${scope}, true), set_config(${reasonSetting}, ${reason}, true), set_config(${principalSetting}, ${principal}, true)`);
    const readCaller = async (tx) => {
        const { rows } = (await tx.execute(sql `SELECT current_setting(${setting}, true) AS scope, current_setting(${reasonSetting}, true) AS reason,
      current_setting(${principalSetting}, true) AS principal, current_setting('transaction_read_only') AS read_only`));
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
    async function inScope(tx, kind, values, caller, run) {
        await setScope(tx, values);
        const before = running.get(tx);
        running.set(tx, kind);
        try {
            if (!caller)
                return await run();
            let result;
            try {
                result = await run();
            }
            catch (error) {
                await setScope(tx, [caller.scope, caller.reason, caller.principal]).catch(() => undefined);
                throw error;
            }
            await setScope(tx, [caller.scope, caller.reason, caller.principal]);
            return result;
        }
        finally {
            if (before)
                running.set(tx, before);
            else
                running.delete(tx);
        }
    }
    /**
     * Runs `body` in the transaction a helper call uses. A transaction of its own starts a fresh record of the rows its
     * top-level check locks (`record`). A nested call (the caller's `outer`, or a savepoint when `db` is a transaction)
     * gets the caller's state and only reads the record; a savepoint a helper opens shares it. A nested call of the other
     * kind of scope is refused with ScopeNestingError before `body` runs.
     */
    async function scopedTransaction(db, outer, kind, body) {
        const nested = (given, caller) => {
            const other = running.get(given) ?? kindOf(caller);
            if (other && other !== kind)
                throw new ScopeNestingError();
            return caller;
        };
        if (outer)
            return body(outer, nested(outer, await readCaller(outer)), undefined, held.get(outer));
        if (!(db instanceof PgTransaction)) {
            const record = { kind, pairs: new Set(), started: undefined, open: true };
            try {
                return await transaction(db, tx => { held.set(tx, record); return body(tx, undefined, record, record); });
            }
            finally {
                record.open = false;
            }
        }
        const locked = held.get(db);
        return transaction(db, async (tx) => {
            if (locked)
                held.set(tx, locked);
            return body(tx, nested(db, await readCaller(tx)), undefined, locked);
        });
    }
    return { setting, reasonSetting, principalSetting, inScope, scopedTransaction };
}
/** Each tenancy `createTenancy` returned, with its mechanics, so only a real tenancy opens a system scope. */
export const mechanics = new WeakMap();
