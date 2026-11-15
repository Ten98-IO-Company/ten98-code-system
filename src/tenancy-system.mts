// System scopes: work with no user, under the same row-level security policies as a user request. A separate entry
// point, absent from @ten98/runtime/tenancy and the root, so a request handler cannot reach it by accident; the
// architecture check allows imports of it only from files the app lists, with a reason, in its system-scope.json.
//
// - `withSystemWorkspace` is for jobs, schedulers, provider webhooks and operator tools that already know the workspace
//   (a job's row, or `resolveWorkspace` on a webhook's credential). It records a required `reason`.
// - `withVerifiedWorkspace` is for request paths that enter one workspace on the strength of a credential the app
//   verifies (an API key, a share link, a site key) through a declared SECURITY DEFINER resolver, read-only by default.
//
// Neither checks a membership. Each share-locks the workspace row instead, so a concurrent deletion waits and a deleted
// workspace is refused. drizzle-orm and pg are exact, optional peer dependencies.
import { eq, sql } from 'drizzle-orm';
import { workspace, type AnyDatabase, type ScopedTransaction } from './db.mjs';
import { UnlockedScopeError, WorkspaceAccessError, type Tenancy } from './tenancy.mjs';
import { mechanics, ScopeNestingError, uuid, workspaceIdOf } from './tenancy-scope.mjs';

export type { ScopedTransaction } from './db.mjs';
export { InvalidWorkspaceIdError, ScopeNestingError } from './tenancy-scope.mjs';
export { UnlockedScopeError, WorkspaceAccessError } from './tenancy.mjs';

export type SystemMode = 'read' | 'write';
/** The workspace a system scope admits and the reason it was opened. */
export type SystemAccess = { workspaceId: string; reason: string };
/** The principal a verified resolver returned, such as `{ kind: 'api_key', id: '…' }`. */
export type VerifiedPrincipal = { kind: string; id: string };
export type VerifiedAccess = SystemAccess & { principal: VerifiedPrincipal };
export interface SystemScopeOptions {
  /**
   * Caches verified resolutions in this process for `seconds` (1 to 60). A revoked credential then keeps resolving for
   * up to that long unless the app calls `invalidate(credential)` when it revokes it. Without it every call resolves.
   */
  cache?: { seconds: number };
}

/** Reasons are printable ASCII, 1 to 200 characters, with no space at either end: a job, webhook or tool name. */
const reasonText = /^[\x21-\x7e](?:[\x20-\x7e]{0,198}[\x21-\x7e])?$/u;
const maximumCacheSeconds = 60, maximumCacheEntries = 10_000, maximumCredentialLength = 1024;
type Located = { workspaceId: string; principal?: VerifiedPrincipal };

function reasonOf(reason: unknown): string {
  if (typeof reason !== 'string' || !reasonText.test(reason)) {
    throw new TypeError('A system scope needs a reason: a job, webhook or tool name of 1 to 200 printable ASCII characters with no space at either end.');
  }
  return reason;
}

/**
 * The system scopes over `tenancy`, which must come from `createTenancy`. They share its lock record, so a system scope
 * and a user scope refuse to nest in each other (ScopeNestingError), and a nested system scope must stay in its
 * caller's workspace. The reason and the verified principal (`kind:id`) are set transaction-locally in
 * `tenancy.reasonSetting` and `tenancy.principalSetting`, for triggers and audit.
 */
export function createSystemScope<TResolver extends string>(tenancy: Tenancy<string, TResolver>, { cache }: SystemScopeOptions = {}) {
  const scoped = mechanics.get(tenancy);
  if (!scoped) throw new TypeError('createSystemScope needs a tenancy from createTenancy.');
  if (cache !== undefined && (!cache || !Number.isInteger(cache.seconds) || cache.seconds < 1 || cache.seconds > maximumCacheSeconds)) {
    throw new TypeError(`The resolution cache lifetime must be a whole number of seconds from 1 to ${maximumCacheSeconds}.`);
  }
  const lifetime = (cache?.seconds ?? 0) * 1000;
  const resolutions = new Map<string, { expires: number; located: Located }>();
  const cacheKey = (resolver: string, credential: string) => `${resolver}\u0000${credential}`;

  const resolverOf = (resolver: unknown, verified: boolean) => {
    const declared = typeof resolver === 'string' && Object.hasOwn(tenancy.resolvers, resolver) ? tenancy.resolvers[resolver as TResolver] : undefined;
    if (!declared || Boolean(declared.principal) !== verified) {
      throw new TypeError(`${String(resolver)} is not a declared ${verified ? 'verified resolver (with a principal)' : 'workspace resolver (without a principal)'}.`);
    }
    return declared;
  };
  // A credential the resolver could not take gets the same refusal as one it does not know.
  const credentialOf = (credential: unknown, type: 'text' | 'uuid'): string => {
    if (typeof credential !== 'string' || !credential || credential.length > maximumCredentialLength || (type === 'uuid' && !uuid.test(credential))) throw new WorkspaceAccessError();
    return credential;
  };
  // Parameterised by necessity: the resolver is a function call, which Drizzle has no builder for. Its name is a declared
  // identifier, and the cast picks the declared signature only.
  const call = (resolver: string, credential: string, type: 'text' | 'uuid') =>
    sql`public.${sql.identifier(resolver)}(${type === 'uuid' ? sql`${credential}::uuid` : sql`${credential}::text`})`;

  /**
   * One system-scoped transaction. `locate` runs first (a verified resolver, which may record use); then the workspace
   * row is share-locked, the transaction turns READ ONLY for `read`, and the scope is set. Nested in a READ ONLY
   * transaction, only a workspace the transaction's own top-level system call locked is admitted.
   */
  function enter<TDatabase extends AnyDatabase, TAccess extends SystemAccess, T>(db: TDatabase, mode: SystemMode, locate: (tx: AnyDatabase) => Promise<TAccess>,
    run: (tx: ScopedTransaction<TDatabase>, access: TAccess) => Promise<T>): Promise<T> {
    return scoped!.scopedTransaction(db, undefined, 'system', async (tx, caller, record, locked) => {
      const access = await locate(tx);
      if (caller?.reason && caller.scope !== access.workspaceId) throw new ScopeNestingError();
      const query = tx.select({ id: workspace.id, started: sql<string>`extract(epoch from transaction_timestamp())::text` })
        .from(workspace).where(eq(workspace.id, access.workspaceId));
      const [row] = caller?.readOnly ? await query : await query.for('share');
      if (!row) throw new WorkspaceAccessError();
      if (!caller?.readOnly) {
        if (record) { record.started = row.started; record.pairs.add(row.id); }
      } else if (!locked?.open || locked.kind !== 'system' || row.started !== locked.started || !locked.pairs.has(row.id)) {
        throw new UnlockedScopeError();
      }
      if (mode === 'read' && !caller) await tx.setTransaction({ accessMode: 'read only' });
      const { principal } = access as Partial<VerifiedAccess>;
      return scoped!.inScope(tx, 'system', [row.id, access.reason, principal ? `${principal.kind}:${principal.id}` : ''], caller, () => run(tx, access));
    });
  }

  return {
    /**
     * Runs `run` in one read-write transaction whose row-level security admits `workspaceId` only, with no membership
     * check, for a job, scheduler, webhook or operator tool. The workspace row is share-locked first, so a missing or
     * deleted workspace is refused with WorkspaceAccessError and a deletion waits for the transaction. `reason` is
     * required and recorded. Given a transaction as `db` it runs in a savepoint and restores the caller's scope.
     */
    withSystemWorkspace<TDatabase extends AnyDatabase, T>(db: TDatabase, { workspaceId, reason }: { workspaceId: string; reason: string },
      run: (tx: ScopedTransaction<TDatabase>, access: SystemAccess) => Promise<T>): Promise<T> {
      let access: SystemAccess;
      try { access = { workspaceId: workspaceIdOf(workspaceId), reason: reasonOf(reason) }; } catch (error) { return Promise.reject(error); }
      return enter(db, 'write', async () => access, run);
    },
    /**
     * Resolves `credential` with the declared verified `resolver` and runs `run` in one transaction admitting the
     * workspace it names, with the principal it verified recorded. An unresolved credential, an unusable one and a
     * deleted workspace all get WorkspaceAccessError before any scoped statement. `mode` is `read` by default: the
     * workspace row is share-locked before the transaction turns READ ONLY. `write` needs a `"write": true` entry for
     * the calling file in system-scope.json. Use is recorded by the resolver itself (`touch`), never in the scope.
     */
    withVerifiedWorkspace<TDatabase extends AnyDatabase, T>(db: TDatabase,
      { resolver, credential, reason, mode = 'read' }: { resolver: TResolver; credential: string; reason: string; mode?: SystemMode },
      run: (tx: ScopedTransaction<TDatabase>, access: VerifiedAccess) => Promise<T>): Promise<T> {
      let declared, checkedReason: string;
      try {
        declared = resolverOf(resolver, true);
        checkedReason = reasonOf(reason);
        if (mode !== 'read' && mode !== 'write') throw new TypeError('A verified scope\'s mode is read or write.');
      } catch (error) { return Promise.reject(error); }
      return enter(db, mode, async tx => {
        const value = credentialOf(credential, declared.parameter.type), key = cacheKey(resolver, value);
        const hit = resolutions.get(key);
        // A copy, so a callback that changes its access object never changes the cached resolution.
        if (hit && hit.expires > Date.now()) return { workspaceId: hit.located.workspaceId, principal: { ...hit.located.principal! }, reason: checkedReason };
        if (hit) resolutions.delete(key);
        const { rows } = (await tx.execute(sql`SELECT workspace_id, principal_kind, principal_id FROM ${call(resolver, value, declared.parameter.type)}`)) as unknown as
          { rows: { workspace_id: string | null; principal_kind: string | null; principal_id: string | null }[] };
        const row = rows[0];
        if (!row?.workspace_id || !row.principal_kind || !row.principal_id) throw new WorkspaceAccessError();
        const located = { workspaceId: workspaceIdOf(row.workspace_id), principal: { kind: row.principal_kind, id: row.principal_id } };
        if (lifetime) {
          if (resolutions.size >= maximumCacheEntries) resolutions.delete(resolutions.keys().next().value!);
          resolutions.set(key, { expires: Date.now() + lifetime, located: { workspaceId: located.workspaceId, principal: { ...located.principal } } });
        }
        return { ...located, reason: checkedReason };
      }, run);
    },
    /**
     * The workspace id a declared workspace `resolver` (one without a principal) returns for `credential`, or undefined.
     * The only cross-tenant read: run it outside any scope, then open `withSystemWorkspace` on the id.
     */
    async resolveWorkspace(db: AnyDatabase, resolver: TResolver, credential: string): Promise<string | undefined> {
      const declared = resolverOf(resolver, false);
      let value: string;
      try { value = credentialOf(credential, declared.parameter.type); } catch { return undefined; }
      const { rows } = (await db.execute(sql`SELECT ${call(resolver, value, declared.parameter.type)} AS workspace_id`)) as unknown as { rows: { workspace_id: string | null }[] };
      const id = rows[0]?.workspace_id;
      return id ? workspaceIdOf(id) : undefined;
    },
    /** Drops every cached resolution of `credential` at once; call it when the app revokes that credential. */
    invalidate(credential: string): void {
      for (const key of resolutions.keys()) if (key.slice(key.indexOf('\u0000') + 1) === credential) resolutions.delete(key);
    },
  };
}

export type SystemScope<TResolver extends string = string> = ReturnType<typeof createSystemScope<TResolver>>;
