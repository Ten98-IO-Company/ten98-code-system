// The Ten98 PostgreSQL connection preset on node-postgres and Drizzle, promoted from Books src/server/db.ts and
// src/server/schema.ts. It fixes the type parsing, pool defaults and per-process pool slot, and declares the common team
// tables of workspace-team.sql for typed queries. Each app keeps its own connection URLs, migrations, schema for its own
// tables and resource-cleanup registration. drizzle-orm and pg are exact, optional peer dependencies.
import { sql } from 'drizzle-orm';
import { drizzle, NodePgSession, NodePgTransaction } from 'drizzle-orm/node-postgres';
import { bigint, boolean, check, foreignKey, index, pgTable, primaryKey, text, timestamp, unique, uniqueIndex, uuid, PgTransaction } from 'drizzle-orm/pg-core';
import pg from 'pg';
import { workspaceRoles } from './browser.mjs';
/**
 * PostgreSQL int8 (BIGINT, money in minor units) reads as `bigint`, never as a lossy number or a string. DATE is a
 * calendar date and stays its YYYY-MM-DD text, never a time-zone-shifted Date. Scoped to the pools that pass it, so
 * libraries with their own connections (pg-boss) keep their own parsing.
 */
export const pgTypes = {
    getTypeParser: ((oid, format) => format === 'binary' ? pg.types.getTypeParser(oid, format)
        : oid === pg.types.builtins.INT8 ? (value) => BigInt(value)
            : oid === pg.types.builtins.DATE ? (value) => value
                : pg.types.getTypeParser(oid, 'text')),
};
/** A pool with bounded waits (connect 5 s, idle 10 s, statements 10 s) and `pgTypes`; `options` override any of them. */
export function createPool(connectionString, options = {}) {
    const pool = new pg.Pool({ connectionString, max: 10, connectionTimeoutMillis: 5000, idleTimeoutMillis: 10000, statement_timeout: 10000, types: pgTypes, ...options });
    // An idle client's error would otherwise crash the process; the message never carries connection details.
    pool.on('error', () => console.error('Database connection failed; check database availability.'));
    return pool;
}
/**
 * One pool per process, kept on globalThis. Bundlers can load separate copies of an app module (Nitro's entry and
 * TanStack Start's SSR routes), and every copy that names the same key shares this slot instead of opening its own pool.
 */
export function sharedDatabase(options) {
    if (typeof options.key !== 'string' || !options.key)
        throw new TypeError('A shared database needs a key.');
    const key = Symbol.for(options.key);
    const shared = globalThis;
    return {
        get() {
            let database = shared[key];
            if (!database) {
                const url = typeof options.connectionString === 'function' ? options.connectionString() : options.connectionString;
                const pool = createPool(url, options.pool);
                database = shared[key] = { pool, db: drizzle(pool, { schema: options.schema }) };
                options.onOpen?.(database);
            }
            return database;
        },
        async close() {
            // Release the slot before ending, so a concurrent close from another bundle never ends the same pool twice.
            const database = shared[key];
            shared[key] = undefined;
            if (database)
                await database.pool.end();
        },
    };
}
const isPool = (client) => client instanceof pg.Pool
    || (client instanceof Object && typeof client.connect === 'function' && typeof client.totalCount === 'number');
// A single connection is a pg Client from this copy of pg; a pool's checked-out client is one. No object shape can prove
// that its statements share one backend (a wrapper with `query` and `release` around a pool does not), so anything
// else is refused rather than given a transaction that is not one.
const isClient = (client) => client instanceof pg.Client;
// Drizzle writes `SET TRANSACTION` with nothing after it for a config that sets nothing, which PostgreSQL refuses.
const setsSomething = (config) => config !== undefined && Object.values(config).some(value => value !== undefined);
/**
 * COMMIT ended in a rollback: a statement failed inside the transaction (an error the callback caught, say), so nothing
 * it did persisted. `transaction` throws this instead of returning the callback's result.
 */
export class TransactionRolledBackError extends Error {
    code = 'TRANSACTION_ROLLED_BACK';
    constructor() { super('The transaction was rolled back: a statement in it failed, so nothing it did persisted.'); this.name = 'TransactionRolledBackError'; }
}
/**
 * `db.transaction` without drizzle-orm 0.45.2's connection leak. Its node-postgres transaction sends BEGIN before its
 * `try`, so a failed BEGIN never releases the pooled connection, and a failed ROLLBACK replaces the error that caused
 * it. Over a pool this checks the connection out and runs BEGIN, COMMIT and ROLLBACK itself. It always releases the
 * connection, and discards it when BEGIN, COMMIT or ROLLBACK failed or the server ended it (its state is then
 * unknown; a COMMIT refused for a constraint or serialisation failure also discards a usable connection, which costs
 * only a reconnect). It throws the callback's own error, or a failed COMMIT's, or TransactionRolledBackError when COMMIT
 * ended in a rollback because a statement failed and the callback caught it. While the connection is checked out it has an
 * `error` listener, so a backend the server terminates fails the transaction instead of crashing the process.
 *
 * Given a transaction (a savepoint) or a database on a single client, it uses Drizzle's own `transaction`. Any other
 * database is refused with a TypeError rather than silently taking the leaking path: a second copy of drizzle-orm or
 * pg, or a driver other than node-postgres. `config` is Drizzle's, such as `{ accessMode: 'read only' }`; a
 * savepoint ignores it.
 */
export async function transaction(db, run, config) {
    const pooled = db, session = pooled._?.session;
    const nodePg = session instanceof NodePgSession, pool = nodePg && isPool(pooled.$client);
    if (db instanceof PgTransaction || (nodePg && !pool && isClient(pooled.$client)))
        return db.transaction(tx => run(tx), config);
    if (!pool)
        throw new TypeError('transaction() needs a node-postgres Drizzle database from this copy of drizzle-orm, on a pg Pool or Client, or one of its transactions.');
    const connection = await pooled.$client.connect();
    let broken = false;
    const ended = () => { broken = true; };
    connection.on('error', ended);
    try {
        const { schema, options } = session;
        const tx = new NodePgTransaction(pooled.dialect, new NodePgSession(connection, pooled.dialect, schema, options), schema);
        try {
            await tx.execute(sql `begin`);
            if (setsSomething(config))
                await tx.setTransaction(config);
        }
        catch (error) {
            broken = true;
            throw error;
        }
        let result;
        try {
            result = await run(tx);
        }
        catch (error) {
            await tx.execute(sql `rollback`).catch(ended);
            throw error;
        }
        // A failed COMMIT has already ended the transaction; the discarded connection needs no ROLLBACK.
        let committed;
        try {
            committed = await tx.execute(sql `commit`);
        }
        catch (error) {
            broken = true;
            throw error;
        }
        // A transaction a failed statement aborted answers COMMIT with ROLLBACK and no error: report it, never the result.
        if (committed.command !== 'COMMIT')
            throw new TransactionRolledBackError();
        return result;
    }
    finally {
        connection.off('error', ended);
        connection.release(broken);
    }
}
// The common team tables exactly as workspace-team.sql creates them, constraint names included, so Drizzle queries are
// typed and a drizzle-kit diff against that schema finds nothing to change. workspace-team.sql stays the definition.
export const user = pgTable('user', {
    id: text('id').primaryKey(), name: text('name').notNull(), email: text('email').notNull().unique('user_email_key'),
    emailVerified: boolean('emailVerified').notNull().default(false), image: text('image'),
    createdAt: timestamp('createdAt', { withTimezone: true }).notNull().defaultNow(), updatedAt: timestamp('updatedAt', { withTimezone: true }).notNull().defaultNow(),
    twoFactorEnabled: boolean('twoFactorEnabled').notNull().default(false), closedAt: timestamp('closed_at', { withTimezone: true }),
}, table => [uniqueIndex('user_email_normalized_idx').on(sql `lower(${table.email})`), check('user_email_lowercase', sql `${table.email} = lower(${table.email})`)]);
// better-auth's session table. `token` holds the preset's keyed handle (#131); `oidcProvider` is the app's provider key
// for a session that began with a provider sign-in, NULL otherwise, and survives the handle because it is its own column.
export const session = pgTable('session', {
    id: text('id').primaryKey(), expiresAt: timestamp('expiresAt', { withTimezone: true }).notNull(), token: text('token').notNull().unique('session_token_key'),
    createdAt: timestamp('createdAt', { withTimezone: true }).notNull().defaultNow(), updatedAt: timestamp('updatedAt', { withTimezone: true }).notNull().defaultNow(),
    ipAddress: text('ipAddress'), userAgent: text('userAgent'), userId: text('userId').notNull(), oidcProvider: text('oidcProvider'),
}, table => [
    foreignKey({ name: 'session_userId_fkey', columns: [table.userId], foreignColumns: [user.id] }).onDelete('cascade'),
    index('session_user_idx').on(table.userId),
]);
export const account = pgTable('account', {
    id: text('id').primaryKey(), accountId: text('accountId').notNull(), providerId: text('providerId').notNull(), userId: text('userId').notNull(),
    password: text('password'),
    createdAt: timestamp('createdAt', { withTimezone: true }).notNull().defaultNow(), updatedAt: timestamp('updatedAt', { withTimezone: true }).notNull().defaultNow(),
}, table => [
    foreignKey({ name: 'account_userId_fkey', columns: [table.userId], foreignColumns: [user.id] }).onDelete('cascade'),
    unique('account_providerId_accountId_key').on(table.providerId, table.accountId),
    index('account_user_idx').on(table.userId),
]);
export const workspace = pgTable('workspace', {
    id: text('id').primaryKey(), name: text('name').notNull(), createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
export const membership = pgTable('membership', {
    workspaceId: text('workspace_id').notNull(), userId: text('user_id').notNull(), role: text('role', { enum: workspaceRoles }).notNull(),
}, table => [
    primaryKey({ name: 'membership_pkey', columns: [table.workspaceId, table.userId] }),
    foreignKey({ name: 'membership_workspace_id_fkey', columns: [table.workspaceId], foreignColumns: [workspace.id] }).onDelete('cascade'),
    foreignKey({ name: 'membership_user_id_fkey', columns: [table.userId], foreignColumns: [user.id] }).onDelete('cascade'),
    check('membership_role_check', sql `${table.role} IN ('owner','admin','editor','viewer')`),
    index('membership_user_idx').on(table.userId),
]);
export const workspaceInvitation = pgTable('workspace_invitation', {
    id: uuid('id').primaryKey(), workspaceId: text('workspace_id').notNull(), inviterId: text('inviter_id').notNull(), email: text('email').notNull(),
    role: text('role', { enum: ['admin', 'editor', 'viewer'] }).notNull(), tokenHash: text('token_hash').notNull().unique('workspace_invitation_token_hash_key'),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(), createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, table => [
    foreignKey({ name: 'workspace_invitation_workspace_id_fkey', columns: [table.workspaceId], foreignColumns: [workspace.id] }).onDelete('cascade'),
    foreignKey({ name: 'workspace_invitation_inviter_id_fkey', columns: [table.inviterId], foreignColumns: [user.id] }).onDelete('cascade'),
    check('workspace_invitation_email_check', sql `${table.email} = lower(${table.email})`),
    check('workspace_invitation_role_check', sql `${table.role} IN ('admin', 'editor', 'viewer')`),
    check('workspace_invitation_token_hash_check', sql `length(${table.tokenHash}) = 64`),
    unique('workspace_invitation_workspace_id_email_key').on(table.workspaceId, table.email),
]);
export const workspaceTwoFactorRequirement = pgTable('workspace_two_factor_requirement', {
    workspaceId: text('workspace_id').primaryKey(),
}, table => [foreignKey({ name: 'workspace_two_factor_requirement_workspace_id_fkey', columns: [table.workspaceId], foreignColumns: [workspace.id] }).onDelete('cascade')]);
export const instanceOperator = pgTable('instance_operator', {
    userId: text('user_id').primaryKey(), source: text('source', { enum: ['bootstrap', 'host'] }).notNull(),
    grantedAt: timestamp('granted_at', { withTimezone: true }).notNull().defaultNow(),
}, table => [
    foreignKey({ name: 'instance_operator_user_id_fkey', columns: [table.userId], foreignColumns: [user.id] }).onDelete('cascade'),
    check('instance_operator_source_check', sql `${table.source} IN ('bootstrap','host')`),
]);
export const instanceOperatorAudit = pgTable('instance_operator_audit', {
    id: bigint('id', { mode: 'bigint' }).primaryKey().generatedAlwaysAsIdentity(), userId: text('user_id').notNull(),
    action: text('action', { enum: ['bootstrap', 'grant', 'revoke', 'paid_work_export', 'email_suppression_clear'] }).notNull(), scope: text('scope'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, table => [
    check('instance_operator_audit_action_check', sql `${table.action} IN ('bootstrap','grant','revoke','paid_work_export','email_suppression_clear')`),
    check('instance_operator_audit_scope_check', sql `(${table.action} = 'paid_work_export') = (${table.scope} IS NOT NULL)
    AND (${table.scope} IS NULL OR ${table.scope} ~ '^workspace:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(/website:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?$')`),
]);
/** The team tables as one object, to spread into an app's Drizzle schema. */
export const teamSchema = { user, session, account, workspace, membership, workspaceInvitation, workspaceTwoFactorRequirement, instanceOperator, instanceOperatorAudit };
