# Adopt a complete feature

Start with [the feature catalogue](../features/catalog.json) and the canonical `databasePolicy` in [architecture.json](../architecture.json). New stateful Node applications default to PostgreSQL with Drizzle and checked TypeScript; stateless packages need no database. Discover supplies the default framework, identity and feature source on PostgreSQL, Drizzle and pg-boss. Campaign also runs PostgreSQL and Drizzle; its retained identity and routing adapters have separate adoption gaps. Native Cloudflare D1 is an explicit platform exception; other nondefault engines require a recorded purpose and review. Connect is not built yet.

The catalogue retains `defaultAuthenticatedNodeStack` as its framework-source selector for compatibility; database choice comes from the canonical policy. The engine in an existing app is not the default for a new application.

Each catalogue `sources` entry names the app's current release tag. Check out that tag in a fresh working folder, install through its lockfile with Node 24 and the app's own package manager, and run its listed checks before adopting anything. It is a complete reference to adopt into the same stack, not a drop-in package:

```sh
git clone --depth 1 --branch v0.7.4 https://github.com/Ten98-IO-Company/ten98-discover.git work/ten98-feature-reference
```

Entry-point paths in the catalogue are navigation aids, not a list of independently copyable files. A tag carries the complete source closure: routes, UI, controllers, schema and migrations, jobs, public configuration examples, lockfiles, pinned runtime and UI archives, tests, licences and notices. The 2026-10-20 source bundles are archived history and predate Campaign on PostgreSQL, Amazon SES and account closure.

Use imports for `@ten98/runtime` primitives and `@ten98/ui` presentation. A URL validator is not OIDC sign-in; a transport wrapper is not a paid-work lifecycle; a grant predicate is not transactional tenant authorization. Follow the catalogue's full source reference when adopting those features.

Runtime 0.22.0 provides the Shopify crawler-access mechanism: `parseShopifyCrawlerAccess`, `shopifyCrawlerHeadersFor` and `verifyShopifyCrawlerAccess`. Import those functions instead of copying signature parsing, expiry or header selection into an app. The helper performs no key lookup or network request: the owning app supplies a public verification key and retains domain proof, encrypted credentials, current authorization, revision binding, request recovery, scheduling and safe crawl transport. Selecting headers is not authorization to crawl. Recheck a selected credential after waits and before native dispatch; expired, revoked or unreadable selected access must stop its request. The pinned upstream MIT attribution is in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Track complete consumer adoption and remaining live-provider/release checks in [issue102](https://github.com/Ten98-IO-Company/ten98-code-system/issues/102).

Runtime 0.22.0 also promotes Discover's `addressKey` and `publicNetworkAddress` policy, plus `pinnedNetworkPeer` and bounded, cancellable dual-family `resolveNetworkHost`. Import these mechanisms without creating another app-local address policy. DNS results are evidence, not admission: reject the whole set if any target is nonpublic, pin an admitted address and verify the connected peer before forwarding. Applications still own URL scope, authority and transport. `normalizeLighthouseReport` consumes the pinned local Lighthouse 13.6.0 navigation report, binds its requested URL, and projects bounded scores, lab measurements and audit details with explicit missing/error/truncation evidence. It performs no browser or provider work. Track actual imports, removal of duplicates, real isolated-browser acceptance and remaining release work in [issue 103](https://github.com/Ten98-IO-Company/ten98-code-system/issues/103); package tests alone do not establish a working renderer.

For stack-bound features, first run the unmodified reference with its own documented setup and tests. Then trace the caller through route admission, session/token identity, authorization, validation, transaction, provider boundary, receipt and rendered outcome. Adopt the complete flow into the same supported stack or make a controlled adaptation with explicit migrations and compatibility tests. Copying one handler while omitting its schema, lock, worker or authority recheck is incomplete.

Record the source repository and tag, the commit, the source path and the reason for adaptation beside copied code or in the consuming change. Retain copyright and notices. Link the owning code-system GitHub issue and identify who will port later fixes. Prefer improving the maintained canonical implementation and adopting that version together; do not establish independently evolving auth/provider frameworks.

Verification must include the feature's listed tests and actual UI/API/persistence path, plus relevant negative cases: wrong tenant/role, revocation after a wait, expired/reused capability, malformed/incomplete response, failed transaction, stale draft, unmount/navigation, keyboard/narrow layout and uncertain provider outcome. Run network/provider scenarios only in approved isolated fixtures. Synthetic checks are evidence for their fixture scope; they establish no live-provider certification or production deployment.

Before claiming adoption complete, preserve existing accounts/data and error contracts, pass the consumer's architecture/type/test/build gates, obtain independent review, and record the exact source tag and commit, commands, results, skips and remaining gaps in GitHub. The catalogue's issue statuses are a snapshot: consult issues [#4](https://github.com/Ten98-IO-Company/ten98-code-system/issues/4) through [#8](https://github.com/Ten98-IO-Company/ten98-code-system/issues/8) before choosing a reference. Current static dependency checks do not prove complete feature adoption.

## Entry-point checklists

Each framework entry point takes its libraries as exact optional peers, so the app lists each one in its own `dependencies` with its lockfile entry. pnpm does not install optional peers. The sections below hold the details. Release notes are on [GitHub Releases](https://github.com/Ten98-IO-Company/ten98-code-system/releases). Record each consumer's imports and checks in its adoption issue.

**`@ten98/runtime/db`** (0.27.0; peers `drizzle-orm` 0.45.2 and `pg` 8.23.0)
- Open the pool once per process with `sharedDatabase({ key, connectionString, schema })`, keyed by app (for example `ten98-books.database`), so bundler copies of a module share it.
- Replace `db.transaction` with `transaction(db, run)` everywhere. Pass a pool-backed database or a single `pg.Client` from the same copy of pg; anything else is refused.
- Use `teamSchema` and the shipped `workspace-team.sql` for the team tables rather than redeclaring them.
- Commit `raw-statements.json`, with a reason for every entry, and lower it as raw statements become typed queries.

**`@ten98/runtime/tenancy`** (0.27.0; same peers)
- Call `createTenancy({ setting, column, tables })` once, add `policy(name)` to each scoped table's Drizzle callback, and put `forceRowLevelSecurity()`, the roles and every `GRANT` in a custom migration step.
- Connect as a non-owner role without BYPASSRLS, and call `assertDatabaseRoles(pool)` at start-up and in a database test.
- Reach scoped tables only through `withWorkspace` and `withWorkspaces`. Await nested calls on one transaction in turn.
- Map `WorkspaceAccessError` to a not-found response and `UnlockedScopeError` to a bare 500. A `DatabaseRoleError` stops start-up.
- Map `InvalidWorkspaceIdError` (`code: 'TENANCY_WORKSPACE_ID_INVALID'`, a TypeError) to invalid input. From the release after 0.29.0 the helpers throw it for a workspace id that is not a UUID instead of refusing it as not found (`withWorkspace`) or dropping it (`withWorkspaces`). Map `ScopeNestingError` to a bare 500.
- Before adopting read-only reads, check that no read callback writes.

**`@ten98/runtime/tenancy/testing`** (0.27.1; peer `pg`)
- Import `setScopeForTesting(client, tenancy, workspaceIds)` only from tests outside the app's data roots; the architecture check refuses it inside them.
- Call it on a connection and transaction the test owns, as the application role, with UUIDs only.
- In the test database, run `requireScopeForTesting(client, tenancy)` as its owner before the application role connects, so a query with no scope raises.

**`@ten98/runtime/tenancy/system`** (unreleased, #160; same peers as `./tenancy`)
- Create the resolver owner role (NOLOGIN, BYPASSRLS, owning nothing) and declare `resolverOwner` and `resolvers` in `createTenancy`. Put `resolverFunctions(applicationRole)` and the owner's SELECT (and, for `touch`, UPDATE) grants in the custom step.
- Call `createSystemScope(tenancy)` once. Import it only from files listed with a reason in a committed `system-scope.json`; add `"write": true` for files that open write-mode verified scopes.
- Map `WorkspaceAccessError` from a system or verified scope to the job's drop path or the request's uniform refusal.

**`@ten98/runtime/config`** (0.28.0; peer `zod` 4.6.6 for `loadConfig` only)
- Replace the app's `environmentValue` and `secret` helpers with `readEnvironment` and `readSecret`, and keep the app's own `getConfig`, built on `loadConfig`.
- Map `code: 'CONFIG_INVALID'` to a 503 wherever the app mapped `ENOENT` or `EACCES` from configuration (discover's `api.ts:1383`), in the same change.
- Campaign points `SESSION_SECRET_FILE` at its generated `DATA_DIR/session-secret` or at a Compose secret, so existing sessions stay valid.

**`@ten98/runtime/email`** (0.28.0; peer `zod` 4.6.6, plus `nodemailer` 10.1.4 for SMTP)
- Pass `isSuppressed` at every send site. Discover has two, `account-security.ts:242` and `api.ts:138`. An app with no suppression list passes `false`. Books gains the `ses` and `cloudflare` transports, and has no suppression list for them.
- Map `CONFIG_INVALID` to 503, as for `./config`.
- Discover's two email test changes: the expected Cloudflare value becomes `'unconfirmed'`, and `isSuppressed` moves from the test seam to the send option.

`@ten98/runtime/auth` gains its checklist with the 0.29.0 release. Until then the shipped preset is described in the catalogue's `auth` entry.

## Row-level security with Drizzle

Every app forces row-level security and connects as a non-owner role without BYPASSRLS. Declare what Drizzle can carry in the schema and put the rest in a custom migration step (`drizzle-kit generate --custom`); the migration ledger applies both kinds of file the same way. Trial on drizzle-orm 0.45.2 and drizzle-kit 0.31.11 against PostgreSQL 18.6, 2026-11-14:

- In the schema: `pgPolicy(name, { as, for, to, using, withCheck })` in the table callback, `.enableRLS()` on a table without a policy (a policy enables RLS by itself), and `pgRole(name).existing()` to name the application role in `to`. drizzle-kit emits `ENABLE ROW LEVEL SECURITY` and `CREATE POLICY` with the `sql` expression verbatim, and a second generate reports no change.
- In the custom step: `FORCE ROW LEVEL SECURITY`, every `GRANT`, the roles themselves (`pgRole` has no LOGIN, BYPASSRLS or password options), triggers and functions. drizzle-kit keeps no record of these, so it neither generates nor reverts them.
- Review generated SQL. A policy change is emitted as `DROP POLICY` then `CREATE POLICY`. drizzle-kit writes `WITH CHECK` on a `for: 'select'` or `for: 'delete'` policy, which PostgreSQL rejects. Removing `.enableRLS()` from a table without a policy emits `DISABLE ROW LEVEL SECURITY`, which leaves FORCE set but switches the protection off.

`@ten98/runtime/tenancy` carries this split: `createTenancy({ setting, column, tables })` returns `policy(name)` for each scoped table's Drizzle callback, `forceRowLevelSecurity()` for the custom step, `withWorkspace` and `withWorkspaces` for scoped Drizzle transactions, and `assertDatabaseRoles` for start-up. Grants and roles stay in the app's custom step. `@ten98/runtime/db` provides the pool, the int8 and DATE parsers, the one-pool-per-process slot, the team tables and `transaction(db, run)`.

The scope is set only by the tenancy helpers, after the membership check, and by the system scopes below, after locking the workspace row; there is no public setter. Database guard tests that must act as the application role with an arbitrary scope import `setScopeForTesting(client, tenancy, workspaceIds)` from the separate `@ten98/runtime/tenancy/testing` entry, on a connection and transaction the test owns. It accepts UUIDs only. The architecture check refuses an import of it from a file under the app's data roots, so only tests outside them should use it. The check matches text: it catches `from '…'`, a bare `import '…'`, and `import('…')` or `require('…')` with a literal specifier. It does not catch a runtime-built specifier, a path alias, a re-export from outside the roots, the deep `node_modules/…/tenancy-testing.mjs` path, `createRequire(…)`, or a comment before the specifier. Review imports of this entry like any other test-only code. Read access (`'read'` and every `withWorkspaces`) switches its own transaction to READ ONLY once the membership row is share-locked, so a write in a read callback fails with SQLSTATE 25006. Inside a caller's transaction (`outer`, or a transaction passed as `db`, which runs a savepoint) the caller keeps its access mode and gets its own scope back when the inner call returns or throws. PostgreSQL refuses the share lock inside a READ ONLY transaction, so a nested call there fails closed.

- **What it admits:** only memberships of the same user that the transaction's own top-level helper call share-locked, and a removal must wait for those. That check is the transaction's first statement, so no savepoint or ROLLBACK TO can release it.
- **The record lasts only for its transaction.** A transaction object used after its transaction ended, for example by an un-awaited nested call, is refused. So is a nested call after the caller issued its own ROLLBACK and BEGIN inside the helper's transaction. The record is tied to that transaction's `transaction_timestamp()`. Issuing transaction control yourself inside a helper transaction is unsupported.
- **Nested locks are never counted.** A rollback the helper cannot see could release them. So a membership that a nested write call locked is still refused by a later nested read, after the caller has set READ ONLY.
- **Everything else is refused.** That includes another user's membership of the same workspace, any workspace in a READ ONLY transaction the caller opened itself, and any call given a Drizzle savepoint the caller opened itself, even when the lock is held. These throw `UnlockedScopeError` (`code: 'TENANCY_SCOPE_UNLOCKED'`). Map it as a programming error, not a missing workspace.
- **To nest reads across workspaces**, open the outer call for the same user over all of them (`withWorkspaces`), or make it a write call. Await nested calls on one transaction in turn: run at once (`Promise.all`), their scopes and restores interleave, and a callback can see the other call's workspace, though never one outside the user's memberships. Before an app adopts read-only reads, check that no read callback writes (audit or last-seen rows, for example).

**One policy per scoped table.** `assertDatabaseRoles` accepts exactly one policy on each scoped table: the workspace policy from `policy(name)`, PERMISSIVE, for ALL commands and every role, with the scope in USING and WITH CHECK. Per-command policies (a separate SELECT or INSERT policy) and any additional policy are refused, so design scoped tables around that one policy.

**Workspace ids are UUIDs.** `withWorkspace`, `withWorkspaces` and the system scopes take ids in any letter case and use their lower-case form. An id that is not a UUID throws `InvalidWorkspaceIdError` before any statement.

**Drizzle only.** The helpers take Drizzle databases and transactions only. An app with hand-written `pg` transactions turns the policies on one group of tables at a time, as it converts the paths that touch them:
1. Convert every path that reads or writes the group to Drizzle inside `withWorkspace`, `withWorkspaces` or a system scope.
2. Add `policy(name)` to those tables, generate the migration, and add their FORCE statements to the custom step.
3. Add the group to `tables` and run the tests with `requireScopeForTesting`, which turns any path still unscoped into an error.
4. Move to the next group.

**A missing scope is silent in production.** A query on a scoped table with no scope set returns no rows and changes nothing, rather than failing. In test databases only, `requireScopeForTesting(client, tenancy)` from `@ten98/runtime/tenancy/testing` makes the setting's default `unscopedForTesting` and adds a RESTRICTIVE `<table>_requires_scope` policy that raises "No tenancy scope is set" as soon as an unscoped query reaches a row. An insert with no scope already fails the workspace policy's check. Run it as the database owner before the application role connects, because only new connections read the default. An empty scope that a helper set on purpose, such as `withWorkspaces` with no membership, still admits nothing quietly. The extra policy makes `assertDatabaseRoles` refuse that database, so run the role assertion against another. Production policies are unchanged.

### System scopes

`@ten98/runtime/tenancy/system` is a separate entry, absent from `./tenancy` and the root, for work with no user. `createSystemScope(tenancy, { cache })` takes the tenancy from `createTenancy` and returns:
- **`withSystemWorkspace(db, { workspaceId, reason }, run)`** for jobs, schedulers, provider webhooks and operator tools. It runs `run` in one read-write transaction admitting exactly that workspace, under the same policies as a user request.
- **`withVerifiedWorkspace(db, { resolver, credential, reason, mode }, run)`** for request paths that enter one workspace on a credential the app verifies, such as an API key, a share link or a site key. A declared verified resolver returns the workspace id and the verified principal (`kind` and `id`).
- **`resolveWorkspace(db, resolver, credential)`**, which returns the workspace id a declared workspace resolver finds, or undefined, for a webhook that then opens `withSystemWorkspace`.
- **`invalidate(credential)`**, which drops cached resolutions of that credential.

How they behave:
- **No membership check.** Each share-locks the workspace row (`FOR SHARE`) as its first lock, so a concurrent deletion waits for the transaction. A missing or deleted workspace gets `WorkspaceAccessError` before `run`.
- **`reason` is required:** a job, webhook or tool name of 1 to 200 printable ASCII characters. It is set with `set_config(…, true)` in `tenancy.reasonSetting`, which is `<setting>_reason` (for example `app.workspace_ids_reason`), for triggers and audit. Deriving it from the tenancy's own setting keeps it in the app's namespace, needs no extra option, and keeps two tenancies apart. A verified scope also sets `tenancy.principalSetting` (`<setting>_principal`) to `kind:id`.
- **Verified scopes are read-only by default.** The resolver runs first, then the workspace row is share-locked, and only then does the transaction turn READ ONLY, so the app never takes that lock itself. `mode: 'write'` is allowed only in files whose `system-scope.json` entry says `"write": true`. An unresolved credential, one the resolver's argument type cannot take, one longer than 1024 characters, and one whose workspace is gone all get the same `WorkspaceAccessError`, before any scoped statement.
- **Recording use belongs in the resolver.** A resolver declared with `touch: ['last_used_at']` is an UPDATE of the principal's row that sets those columns to now(), so a read-only scope never writes for it.
- **Nesting follows the lock-record rules of `withWorkspace`.** Given a transaction as `db`, a system scope runs in a savepoint and gives the caller its scope and reason back. It must stay in the caller's workspace, so it cannot be widened. A user scope and a system scope cannot be nested in each other in either direction, whether as a savepoint, joined as `outer` or inside the caller's own savepoint; that throws `ScopeNestingError` (`code: 'TENANCY_SCOPE_NESTED'`). In a READ ONLY transaction a nested system scope admits only the workspace that the transaction's own top-level system call locked, and otherwise throws `UnlockedScopeError`.
- **Caching.** A resolver is one indexed lookup, so every call resolves by default. With `cache: { seconds }`, from 1 to 60, verified resolutions are kept in the process, at most 10,000 of them. A revoked credential then keeps resolving for up to that many seconds unless the app calls `invalidate(credential)` when it revokes it. Use recorded by `touch` happens only on a call that resolves. The workspace row is still locked on every call, so a deleted workspace is refused at once.

**Resolvers** are the only cross-tenant reads. Declare each one in `createTenancy({ …, resolverOwner, resolvers })` with its one `parameter` (`text` or `uuid`), its `table`, its `match` column, its `workspace` column (the tenancy column by default), and for a verified resolver its `principal` (a constant `kind` and an `id` column) and optional `touch` columns. `resolverFunctions(applicationRole)` writes the custom step's statements for each:
- `CREATE OR REPLACE FUNCTION` with the body `SELECT … FROM public.<table> WHERE <match> = $1 LIMIT 1`, returning only the workspace id (`RETURNS uuid`), or for a verified resolver `OUT workspace_id uuid, OUT principal_kind text, OUT principal_id text`, never `SETOF`. With `touch` the body is an UPDATE of the row that lookup finds, with `RETURNING` of the same columns;
- `LANGUAGE sql`, `SECURITY DEFINER` and `SET search_path = pg_catalog, pg_temp`, so tables are named `public.…`;
- owner `resolverOwner`, `EXECUTE` revoked from PUBLIC and granted to the application role only.

There is no BYPASSRLS login role, and none is offered as a fallback. Bypass exists only inside the declared resolver functions, owned by a NOLOGIN role. That role is NOLOGIN, not a superuser, has BYPASSRLS, owns no relation, and is not a role the application role is a member of. Grant it SELECT on each looked-up table, and UPDATE for `touch`, in the custom step. The migration role that runs `ALTER FUNCTION … OWNER TO` must be a superuser or a member of the owner role.

With resolvers declared, `assertDatabaseRoles` also checks:
- **each declared resolver:** it exists once, with no overload. It has the declared argument and return, `SECURITY DEFINER`, `LANGUAGE sql`, and that `search_path` as its only setting. It is owned by `resolverOwner`, executable by the application role and not by PUBLIC;
- **the owner role:** its attributes as above;
- **every function the owner role owns,** in any schema, refusing one that is not declared, so a new bypass needs a reviewed declaration.

It does not read function bodies. Review each resolver's body by hand, and prefer the generated one.

**Imports are allowed only from listed files.** The architecture check refuses an import of `@ten98/runtime/tenancy/system` from a file under the app's data roots unless the app's committed `system-scope.json` lists that file:

```json
{
  "src/server/jobs/digest.ts": { "reason": "The nightly digest job runs with no user." },
  "src/server/api/keys.ts": { "reason": "API key requests resolve their workspace by key hash.", "write": true }
}
```

It refuses an entry without a reason, a `"write"` that is not true or false, and an entry for a file that does not import the entry. It also refuses `mode: 'write'` in a listed file whose entry lacks `"write": true`. The check matches text, with the same import forms and the same limits as the `./tenancy/testing` rule above, and finds `mode: 'write'` only when it is written literally. A mode held in a variable passes the check. Tests outside the data roots may import the entry without a listing.

### Transactions and raw statements

Known upstream issue: drizzle-orm 0.45.2's node-postgres `transaction` sends BEGIN before its `try`, so a failed BEGIN never releases the pooled connection, and a failed ROLLBACK replaces the error that caused it. `transaction(db, run)` from `@ten98/runtime/db`, which the tenancy helpers use, checks the connection out itself over a pool and runs BEGIN, COMMIT and ROLLBACK itself. It always releases the connection, discards it when BEGIN, COMMIT or ROLLBACK failed, and rethrows the callback's own error, or a failed COMMIT's. A COMMIT that the server refuses for a constraint or a serialisation failure also discards a connection that was still usable. That costs a reconnect and nothing else. A config that sets nothing (`{}`) sends no `SET TRANSACTION`. Use it in place of `db.transaction`. A pg client checked out of a pool has no `error` listener of its own, so a backend the server terminates mid-transaction (a failover, `pg_terminate_backend`) crashes the process under plain `db.transaction`; `transaction(db, run)` listens for the checkout's lifetime and discards that connection instead. A transaction (a savepoint), or a database on a single client, uses Drizzle's own `transaction`. A single client means a `pg.Client` from the same copy of pg; a pool's checked-out client is one. Any other database is refused with a TypeError instead of falling back silently. That includes one from a second copy of drizzle-orm or pg, and any wrapper object, whatever its shape, because statements through a wrapper could run on different backends.

Application queries are typed Drizzle queries. The architecture check counts raw statements in each app's data roots against the app's committed `raw-statements.json`, and refuses any file whose count rises. It counts:
- pg `.query(`, also written `?.(`, `!(`, `?.<T>(`, `['query'](`, `.query.call(`, `.apply(` or `.bind(`, with comments allowed before the type argument or the parenthesis;
- `sql.raw(`;
- `.execute(` given SQL text, a `sql` template or `sql.join(`, also inside extra parentheses or after a comment.

Each form counts with or without a type argument, with `sql` under any imported name, including the namespace in `import * as d` and `import d, * as ns`.

The check matches text, so a comment or an unrelated `.query(` method is counted. So is a comparison that reads like a type argument, as in `a.query! < b && c > (d)`. These forms are not counted:
- a statement passed to `.execute(` by variable, or as a conditional (`cond ? sql… : sql…`);
- `sql.empty()`;
- `String.raw` text given to `.execute(`;
- a statement reached through a computed key or a destructured `query`;
- `(pool.query)(`;
- `sql` re-exported through an app module, or taken from a dynamic `import()` under another name (`sql` itself is always counted);
- `sql.raw` taken into a variable;
- a type argument with `>` inside a string literal.

Each allowlist entry is `"path": { "count": n, "reason": "…" }`, and the check refuses an entry without a reason. `node node_modules/@ten98/runtime/check.mjs --update-raw-statement-baseline .` records the first allowlist with empty reasons, which fail until someone writes why each file's statements cannot be typed queries; afterwards it only lowers counts and keeps the reasons. The allowlist counts per file, so replacing one raw statement with another in a listed file passes the check and shows only when the diff is reviewed. The runtime is held to the same rule; its own allowlist names the tenancy statements that are raw by necessity (the policy DDL, set_config and the catalogue check), the migration ledger and the team controller.

## Environment configuration

`@ten98/runtime/config` replaces app-local `environmentValue` and `secret` helpers. `readEnvironment(name, env)` returns `NAME`, or the trimmed contents of the file `NAME_FILE` names (a Compose secret), refuses both set at once, and returns undefined when neither is set. As in discover and books, the checks are truthy: an empty `NAME_FILE` is unset and an empty `NAME` never conflicts, but with no file `NAME` comes back unchanged, untrimmed and `''` included. `readSecret(name, { minimumLength = 32, env })` refuses a missing or short secret. `loadConfig(zodObject, env)` reads each schema key that way and parses the strings with zod (use `z.coerce` for numbers), leaving out empty values so `.default()` applies, reporting every failing key in one error with `code: 'CONFIG_INVALID'` and `keys`; messages name keys and never carry values or file paths. Deliberate change from the apps: an unreadable `NAME_FILE` throws that ConfigError (`NAME_FILE names a file that cannot be read (ENOENT)`) instead of the raw fs error with its path. An app that mapped `ENOENT` or `EACCES` from configuration to a 503 (discover's `api.ts:1383`) maps `code: 'CONFIG_INVALID'` instead, in the same change that adopts this entry. `loadConfig` needs the optional `zod` 4.6.6 peer; the readers need nothing. Each app keeps its own `getConfig`. Campaign's generated `DATA_DIR/session-secret` is read with `SESSION_SECRET_FILE` pointing at that file or at a Compose secret, so existing sessions stay valid.

## Presentation ratchet

Apps whose profile has a `presentation` policy keep a committed `presentation-baseline.json`. The architecture check parses each file under the policy's roots and refuses any file whose count rises for a rule: `element` (host tags), `styling` (`className` and `style`), `inner-html`, `create-element` and `stylesheet`. `node node_modules/@ten98/runtime/check.mjs --update-presentation-baseline .` lowers the baseline as screens move onto `@ten98/ui`, and refuses to record a rise. Known limit: `element` counts lowercase host tags, namespaced tags and member tags whose root is not a `@ten98/ui` import. It never counts a capitalised component, whether it comes from `@ten98/ui` or from the app, so it measures host tags and styling, not whether a component comes from the design system. Raw HTML moved into an app-local component is still counted in that component's own file.

## Browser test library

From runtime 0.27.1 the `ten98-discover` profile requires `"playwright": "1.64.1"` in `devDependencies`, the version its CI image `mcr.microsoft.com/playwright:v1.64.1-noble` runs. The entry is required, not just allowed: declare it, with its lockfile entry, in the same change that moves discover to 0.27.1, or the architecture check fails. A different version, a range, or `@playwright/test` in its place is refused.

## Isolated browser audit

Runtime 0.23.0 adds the server-only `@ten98/runtime/browser-audit` entry with `createBrowserAuditControl`, `BrowserControlOptions`, `NativeBrowserResource`, `ObserverTransport`, `BrowserRequestDenial`, `BrowserControlTrace`, `createPublicEgressProxy` and `PublicEgressOptions`. The facade has no capsule startup or third-party dependencies. Use the existing `normalizeLighthouseReport` for supplied reports. Never import these Node mechanisms from browser UI.

The controller owns one physical CDP connection and one reserved observer, guarded target startup/Fetch interception, exact network correlation, bounded resource streams and shutdown ordering. Observers are trusted pinned Puppeteer/Lighthouse clients, not an arbitrary untrusted CDP API; physical tracing streams are outside the synthetic resource-stream ownership contract. Shared/service workers fail closed. A missing network identity is denied and makes coverage partial; two such Other/GET denials remain a known fixture limitation. Never relax this guard to obtain a complete report.

The application supplies current authorization and credential revision checks, sensitive-header names, an exact-byte bounded cancellable `loadResource` callback with public DNS/peer admission and post-wait authority checks, and `stopEgress` that synchronously closes admission/forwarding before returning its closure promise. The reader owns credential selection; it receives no authorization headers from the controller. The proxy's optional authorization callback is not tenancy authorization. CONNECT is opaque TLS and cannot enforce paths or origin headers. Apps retain schedules, job/attempt accounting, storage, report retention and recovery.

Run `node node_modules/@ten98/runtime/browser-audit-capsule.mjs` only as a dedicated Linux process. Provision a fresh 64-hex `TEN98_CAPSULE_CLOSE_CAPABILITY` per operation in the trusted worker and capsule; it is removed from Chromium's environment. The close intent is browser-bound, single-use and valid for three seconds. Unprepared/late/signal/nonzero exits fail. Egress must stop before control teardown; the owner forcibly cleans up failed operations.

The supported launcher requires Chromium at `/ms-playwright/chromium-1248/chrome-linux64/chrome`, writable private `/tmp`, process-group signals, loopback CDP 9222, private capsule listener 9223 advertised as `browser`, and proxy `http://worker:3138`. Use a fresh unprivileged read-only capsule with no application network, credentials, artifact mount, Docker socket or public port; only the trusted worker's operation-scoped proxy is reachable. Image/network provisioning remains an app deployment responsibility. The launcher alone supplies no network isolation.

The compatibility reference uses Node 24.22.1, Lighthouse 13.6.0 and Puppeteer Core 25.16.0. These packages and Chromium are not bundled by runtime. Bind the exact image/dependency/source generation in issue #103 before adoption. Preserve popup, exact outer-first iframe failure, revocation, pending reader, lifecycle and report cases against the packed package and then the actual consumer. Unit fixtures mock DNS/peers and do not establish public-network acceptance. The 1001-request admission test requires explicit `TEN98_BROWSER_AUDIT_LIMIT_TESTS=1`; ordinary test runs retain the DNS/idle deadline cases and skip only that high-volume case.

## OpenRouter Chat Completions protocol

`readOpenRouterAssistantMessageV1(message, finishReason, options)` validates the complete assistant message before exposing calls. Results distinguish `text`, `refusal`, `tool-calls` and `incomplete`; only `tool-calls` is executable protocol evidence. Length, content-filter and error termination remain incomplete. Unknown terminal states or malformed calls reject the whole message with a fixed TypeError.

`validateOpenRouterToolHistoryV1(history, options)` accepts text system/user messages, assistant messages and complete tool-result groups. Systems precede users, assistants follow a user, every call has exactly one matching result before another conversation message, and optional result names match. IDs are unique within each call group and may recur after that group completes. Orphan, duplicate, missing and interleaved results fail.

Options require `allowedToolNames`, `maxContextBytes`, `maxArgumentBytes` and `maxMessageBytes`; an application may explicitly select 131072, 8192 and 2097152 bytes respectively. Bounds use UTF-8 bytes, include tool outputs and reasoning, and reject rather than truncate. Arguments must encode a JSON object; their original string is preserved exactly. Ordered reasoning details, signatures and unknown JSON block fields are retained without interpretation. Outputs are detached from input mutation. Unsupported fields, non-JSON objects, cycles, accessors, NUL and malformed Unicode fail.

These pure helpers perform no I/O and do not parse the response envelope. The app still owns bounded envelope reading, HTTP/choice/model checks, usage, tool definitions, dispatch authorization, tenancy, credential revisions, idempotency, persistence and recovery. Passing a history or receiving a call is not permission to execute it. These helpers do not constitute complete assistant adoption; consumer and live-provider acceptance remain outstanding.

## Exact money arithmetic

Runtime 0.26.0 adds `parseMoney`, `formatMoney`, `addMoney`, `subtractMoney`, `compareMoney`, `multiplyMoney`, `percentOfMoney`, `allocateMoney`, `assertMoneyInRange`, `MONEY_MIN`, `MONEY_MAX` and the `MoneyExponent` and `MoneyRounding` types to both `@ten98/runtime` and `@ten98/runtime/browser`. Amounts are bigint minor units for a currency exponent of 0, 2 or 3; nothing converts to a Number or uses floating point. Import these functions instead of writing another app-local decimal or rounding helper.

`parseMoney` is the wire boundary: it refuses grouping, exponent notation, more fraction digits than the exponent and any amount outside the PostgreSQL `bigint` range (`MONEY_MIN` to `MONEY_MAX`). Arithmetic does not bound its results, so call `assertMoneyInRange` on every computed amount (a total, a converted or taxed amount, an allocation part) before persisting it. `multiplyMoney` and `percentOfMoney` round `half-up`, `half-even` or `down`, symmetrically in sign; `allocateMoney` always sums to the total.

Runtime 0.27.1 adds `convertMoney(amount, fromExponent, rate, toExponent, rounding)` and `rateOfAmounts(target, targetExponent, source, sourceExponent, places, rounding)` for multi-currency lines. A conversion rate is target units per source unit, above zero, with at most 10 fraction digits; a derived rate has exactly `places` digits (0 to 10) and is refused only for a zero source. Each function rounds once on exact integers, so a PostgreSQL guard recomputes the same result with the `div(numeric, numeric)` function on `numeric` integers, never `numeric` division followed by `round`. PostgreSQL has no `div` operator, and `10 ^ b` on integer literals is double precision, so write powers as `power(10::numeric, b)`. `div` truncates toward zero, so apply it to absolute values and restore the sign; the plain form is exact only for positive amounts. With `F` the source amount, `B` the target amount, `R` the rate's integer units, `p` its places and `f`, `b` the exponents, half-up is:

```sql
-- Rate entered: the converted amount.
sign(F) * div(2 * abs(F) * R * power(10::numeric, b) + power(10::numeric, p + f), 2 * power(10::numeric, p + f))
-- Base entered: the derived rate's integer units.
sign(B) * sign(F) * div(2 * abs(B) * power(10::numeric, p + f) + abs(F) * power(10::numeric, b), 2 * abs(F) * power(10::numeric, b))
```

Converting back at a derived rate drifts by at most `F × 10^(b − f − p) / 2` units before rounding. Amounts of opposite sign give a negative derived rate, which `convertMoney` refuses, so check a derived rate before converting with it. Results are not range-checked, a derived rate of zero is returned, and the application owns its rate column's precision, its refusal messages and `assertMoneyInRange` on every converted amount before storing it.

The application still owns its zod wire schema (accept a decimal string, then parse), JSON serialization of bigint values, the `pg` int8 type parser that returns bigint instead of a string or Number, currency selection, display locale, which rounding mode and level a tax rule needs (per line or per document), ledger postings and their transactions. These helpers perform no I/O. Package tests do not establish consumer adoption; record each consumer's imports and checks in its adoption issue.

## Transactional email

Runtime 0.28.0 adds `@ten98/runtime/email`, extracted from discover's and books' `src/server/email.ts`. `sendTransactionalEmail({ to, subject, text }, { env, isSuppressed })` sends one plain-text message (the HTML part is generated from `text`) to one bare mailbox in one attempt, within 15 seconds for the whole send, and resolves `{ accepted: true, delivery: 'unconfirmed' }`: the provider accepted it, nothing more. Every failure, disabled or bad configuration, refused input and a suppressed recipient included, is the same `EmailDeliveryError` with `status` 503 and a fixed message; nothing is logged and no provider error or message content is attached. Input is strict: `to` is one bare mailbox, `subject` at most 200 characters with no control or separator characters, `text` at most 65,536 UTF-8 bytes, and no other fields. `isSuppressed` is required, so no call site sends unchecked by omission. It is either the app's own lookup, `(address) => boolean | Promise<boolean>`, which runs before every transport, or the literal `false` for an app that keeps no suppression list. Only an explicit `false` from the lookup lets the message go; `true`, `undefined`, any other value, a throw or a rejection refuses the send. Missing or `null` options refuse the same way. `getEmailStatus(env)` never throws; read `.configured`. SMTP counts as configured only when the optional `nodemailer` peer is installed. `withEmailTransportsForTests({ fetch, smtp }, action)` substitutes the provider fetch and the SMTP sender inside `action` only.

`EMAIL_TRANSPORT` is `disabled` (the default), `ses`, `cloudflare` or `smtp`, and every setting is read through `readEnvironment`, so each accepts `_FILE`. `EMAIL_FROM` is a bare mailbox. SES uses `sendSesEmail` with `EMAIL_SES_REGION` (one of `SES_REGIONS`), `EMAIL_SES_ACCESS_KEY_ID`, `EMAIL_SES_SECRET_ACCESS_KEY` and an optional `EMAIL_SES_CONFIGURATION_SET`. Cloudflare uses `sendCloudflareEmail` with `EMAIL_CLOUDFLARE_ACCOUNT_ID` and `EMAIL_CLOUDFLARE_API_TOKEN`; a delivered or queued receipt is accepted, a bounce or a Cloudflare suppression is refused. SMTP uses `EMAIL_SMTP_TLS` (`starttls` by default, or `tls`), `EMAIL_SMTP_HOST` (a name, never an IP literal, and never a name whose last label is all digits or any hex label, such as `2130706433`, `127.1`, `0x7f000001` or `127.0x1`), `EMAIL_SMTP_PORT` (587, or 465 for `tls`), `EMAIL_SMTP_USER` and `EMAIL_SMTP_PASSWORD`, and always requires TLS 1.2 or later with a verified certificate and forced authentication. The entry needs the optional `zod` 4.6.6 peer; SMTP also needs the optional `nodemailer` 10.1.4 peer, imported only on the first SMTP send.

Changes from the apps: `sendTransactionalEmail(message, env)` becomes `sendTransactionalEmail(message, { env, isSuppressed })`, suppression applies to every transport rather than SES only, a delivered Cloudflare receipt resolves `'unconfirmed'` instead of discover's `'provider-reported-delivered'`, and `EMAIL_TRANSPORT`, `EMAIL_SMTP_TLS`, `EMAIL_SMTP_PORT`, `EMAIL_SES_REGION` and `EMAIL_SES_CONFIGURATION_SET` now accept `_FILE` too. The application still owns its message text, the suppression list and its feedback webhook, rate limits, and what it tells the user.

The adoption checklist is under [Entry-point checklists](#entry-point-checklists). Package tests use injected transports only.

## Logging

The runtime has no shared logger yet; apps keep their own. The planned `./log` entry ([#142](https://github.com/Ten98-IO-Company/ten98-code-system/issues/142)) wraps pino with path-based redaction: values at listed paths are hidden, a secret under a name nobody listed is written, and values are never scanned, so a password inside a database URL or a token inside a message is written as given. Whichever logger an app uses, log the fields you mean to log, never whole configuration objects, request bodies, request headers or errors that carry configuration.
