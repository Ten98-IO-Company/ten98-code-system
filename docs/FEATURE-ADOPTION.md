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
- Before adopting read-only reads, check that no read callback writes.

**`@ten98/runtime/tenancy/testing`** (0.27.1; peer `pg`)
- Import `setScopeForTesting(client, tenancy, workspaceIds)` only from tests outside the app's data roots; the architecture check refuses it inside them.
- Call it on a connection and transaction the test owns, as the application role, with UUIDs only.

**`@ten98/runtime/config`** (0.28.0; peer `zod` 4.6.6 for `loadConfig` only)
- Replace the app's `environmentValue` and `secret` helpers with `readEnvironment` and `readSecret`, and keep the app's own `getConfig`, built on `loadConfig`.
- Map `code: 'CONFIG_INVALID'` to a 503 wherever the app mapped `ENOENT` or `EACCES` from configuration (discover's `api.ts:1383`), in the same change.
- Campaign points `SESSION_SECRET_FILE` at its generated `DATA_DIR/session-secret` or at a Compose secret, so existing sessions stay valid.

**`@ten98/runtime/email`** (0.28.0; peer `zod` 4.6.6, plus `nodemailer` 10.1.4 for SMTP)
- Pass `isSuppressed` at every send site. Discover has two, `account-security.ts:242` and `api.ts:138`. An app with no suppression list passes `false`. Books gains the `ses` and `cloudflare` transports, and has no suppression list for them.
- Map `CONFIG_INVALID` to 503, as for `./config`.
- Discover's two email test changes: the expected Cloudflare value becomes `'unconfirmed'`, and `isSuppressed` moves from the test seam to the send option.

**Shared-flow register and the ratchet rules** (the first runtime minor after 0.29.0; needs `@ten98/ui` 0.40.0 or later)
- Take `@ten98/ui` 0.40.0 or later first; with an older release the check fails closed.
- Record the register once with `node node_modules/@ten98/runtime/check.mjs --record-shared-flows .`.
- Write every reason and review trigger, and change each feature the app doesn't have to `absent`.
- Name the app's leave-guard adapter in `leaveGuardAdapter`, if it has one. Without it, every `useBlocker` import counts toward `router-blocker`.
- Re-record the baseline once with `--update-presentation-baseline`, and review the diff of both files.
- The details are under [Shared-flow register](#shared-flow-register).

`@ten98/runtime/auth` gains its checklist with the 0.29.0 release. Until then the shipped preset is described in the catalogue's `auth` entry.

## Row-level security with Drizzle

Every app forces row-level security and connects as a non-owner role without BYPASSRLS. Declare what Drizzle can carry in the schema and put the rest in a custom migration step (`drizzle-kit generate --custom`); the migration ledger applies both kinds of file the same way. Trial on drizzle-orm 0.45.2 and drizzle-kit 0.31.11 against PostgreSQL 18.6, 2026-11-14:

- In the schema: `pgPolicy(name, { as, for, to, using, withCheck })` in the table callback, `.enableRLS()` on a table without a policy (a policy enables RLS by itself), and `pgRole(name).existing()` to name the application role in `to`. drizzle-kit emits `ENABLE ROW LEVEL SECURITY` and `CREATE POLICY` with the `sql` expression verbatim, and a second generate reports no change.
- In the custom step: `FORCE ROW LEVEL SECURITY`, every `GRANT`, the roles themselves (`pgRole` has no LOGIN, BYPASSRLS or password options), triggers and functions. drizzle-kit keeps no record of these, so it neither generates nor reverts them.
- Review generated SQL. A policy change is emitted as `DROP POLICY` then `CREATE POLICY`. drizzle-kit writes `WITH CHECK` on a `for: 'select'` or `for: 'delete'` policy, which PostgreSQL rejects. Removing `.enableRLS()` from a table without a policy emits `DISABLE ROW LEVEL SECURITY`, which leaves FORCE set but switches the protection off.

`@ten98/runtime/tenancy` carries this split: `createTenancy({ setting, column, tables })` returns `policy(name)` for each scoped table's Drizzle callback, `forceRowLevelSecurity()` for the custom step, `withWorkspace` and `withWorkspaces` for scoped Drizzle transactions, and `assertDatabaseRoles` for start-up. Grants and roles stay in the app's custom step. `@ten98/runtime/db` provides the pool, the int8 and DATE parsers, the one-pool-per-process slot, the team tables and `transaction(db, run)`.

The scope is set only by the tenancy helpers, after the membership check; there is no public setter. Database guard tests that must act as the application role with an arbitrary scope import `setScopeForTesting(client, tenancy, workspaceIds)` from the separate `@ten98/runtime/tenancy/testing` entry, on a connection and transaction the test owns. It accepts UUIDs only. The architecture check refuses an import of it from a file under the app's data roots, so only tests outside them should use it. The check matches text: it catches `from '…'`, a bare `import '…'`, and `import('…')` or `require('…')` with a literal specifier. It does not catch a runtime-built specifier, a path alias, a re-export from outside the roots, the deep `node_modules/…/tenancy-testing.mjs` path, `createRequire(…)`, or a comment before the specifier. Review imports of this entry like any other test-only code. Read access (`'read'` and every `withWorkspaces`) switches its own transaction to READ ONLY once the membership row is share-locked, so a write in a read callback fails with SQLSTATE 25006. Inside a caller's transaction (`outer`, or a transaction passed as `db`, which runs a savepoint) the caller keeps its access mode and gets its own scope back when the inner call returns or throws. PostgreSQL refuses the share lock inside a READ ONLY transaction, so a nested call there fails closed.

- **What it admits:** only memberships of the same user that the transaction's own top-level helper call share-locked, and a removal must wait for those. That check is the transaction's first statement, so no savepoint or ROLLBACK TO can release it.
- **The record lasts only for its transaction.** A transaction object used after its transaction ended, for example by an un-awaited nested call, is refused. So is a nested call after the caller issued its own ROLLBACK and BEGIN inside the helper's transaction. The record is tied to that transaction's `transaction_timestamp()`. Issuing transaction control yourself inside a helper transaction is unsupported.
- **Nested locks are never counted.** A rollback the helper cannot see could release them. So a membership that a nested write call locked is still refused by a later nested read, after the caller has set READ ONLY.
- **Everything else is refused.** That includes another user's membership of the same workspace, any workspace in a READ ONLY transaction the caller opened itself, and any call given a Drizzle savepoint the caller opened itself, even when the lock is held. These throw `UnlockedScopeError` (`code: 'TENANCY_SCOPE_UNLOCKED'`). Map it as a programming error, not a missing workspace.
- **To nest reads across workspaces**, open the outer call for the same user over all of them (`withWorkspaces`), or make it a write call. Await nested calls on one transaction in turn: run at once (`Promise.all`), their scopes and restores interleave, and a callback can see the other call's workspace, though never one outside the user's memberships. Before an app adopts read-only reads, check that no read callback writes (audit or last-seen rows, for example).

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

Apps whose profile has a `presentation` policy keep a committed `presentation-baseline.json`. The architecture check parses each file under the policy's roots and refuses any file whose count rises for a rule. These rules count `.jsx` and `.tsx` files: `element` (host tags), `styling` (`className` and `style`), `inner-html`, `create-element` and `stylesheet`. `node node_modules/@ten98/runtime/check.mjs --update-presentation-baseline .` lowers the baseline as screens move onto `@ten98/ui`, and refuses to record a rise. Known limit: `element` counts lowercase host tags, namespaced tags and member tags whose root is not a `@ten98/ui` import. It never counts a capitalised component, whether it comes from `@ten98/ui` or from the app, so it measures host tags and styling, not whether a component comes from the design system. Raw HTML moved into an app-local component is still counted in that component's own file.

Five more rules have a target of zero. `t98-selector` counts the `.css` and `.pcss` files under the roots; the other four count every script file there (`.js`, `.jsx`, `.ts`, `.tsx` and their `.mjs`, `.cjs`, `.mts` and `.cts` forms, not `.d.ts`). Test and story files under the roots count for these rules like any other file.
- **`native-dialog`:** calls to `confirm`, `alert` and `prompt`.
  - It counts them as members of `window`, `globalThis` or `self`, or of a chain of those (`window.window.confirm`).
  - Optional calls count (`window.confirm?.(…)`, `window?.confirm(…)`), and so do literal bracket keys (`window['confirm']`), TypeScript casts (`(window as any)`, `<any>window`, `satisfies`), `.call`, `.apply` and `.bind`, and tagged templates.
  - A bare call counts too, unless the file declares a binding of that name anywhere: a variable, a function, a parameter, a catch parameter or an import.
  - Use `useConfirmDialog` from `@ten98/ui` instead.
- **`router-blocker`:** the router exports that block navigation, imported from `@tanstack/react-router`, `react-router` or `react-router-dom`, aliased or not.
  - Those exports are `useBlocker`, `unstable_useBlocker`, `usePrompt`, `unstable_usePrompt` and TanStack's `<Block>`.
  - Every `require(…)` and dynamic `import(…)` of those packages counts as well, whatever is taken from it.
  - It counts imports, not calls, so a file at its baseline can add blocker calls through an import it already has.
  - A type-only import doesn't count, and neither does the register's `leaveGuardAdapter`, when it names one.
  - Use `useLeaveGuard`, passing the adapter as its `useBlocker`.
- **`t98-selector`:** selectors in the app's stylesheets that name a library class.
  - That is a class selector (`.t98-…`), or an attribute selector on `class` whose value holds `t98`, with or without the hyphen (`[class*="t98"]`, `[class^=t98]`, `[class|=t98]`, `[class~="t98-card"]`).
  - Each selector in a list counts once.
  - The scanner skips comments and keeps strings whole. It reads the selectors inside `@media`, `@supports`, `@layer` and nested rules, and the prelude of `@scope (.t98-card)`.
  - It never counts the public custom properties, read (`var(--t98-space-4)`) or declared (`--t98-accent: …`), or any other attribute selector (`[data-theme]`, `[data-density]`, `[data-t98-…]`).
- **`t98-class`:** each string in a `className` or `class` attribute that names a `t98-` class. A string is a literal, a template's literal parts, or a `+` concatenation of literals (`'t98' + '-button'`).
- **`t98-dom`:** DOM calls whose arguments name a library class or a `data-t98` attribute. Any argument counts, not only the first.
  - The calls are `querySelector`, `querySelectorAll`, `closest`, `matches`, `getElementsByClassName`, `getAttribute`, `setAttribute`, `hasAttribute`, `removeAttribute` and `toggleAttribute`.
  - The first four take a selector, so they also count an attribute selector on `class` that names the library, as `t98-selector` does (`querySelector('[class*="t98"]')`, `closest('[class^=t98]')`).
  - So are `classList.add`, `.remove`, `.toggle`, `.contains` and `.replace`.
  - An assignment to `className` (`el.className = 't98-a'`) counts too.

**Private and public.** Every `t98-` class and every `data-t98-*` attribute is private to `@ten98/ui`, including `.t98-theme`, `data-t98-shortcut-scope` and `data-t98-shortcut-modal`. An app reaches the library only through its components, hooks and public API. Two things are public, and no rule counts them:
- the `--t98-*` custom properties (the design tokens), both read with `var(--t98-…)` and declared (`--t98-accent: …`) to set a theme;
- the `data-theme` and `data-density` attributes.

Every run prints the remaining total of each of these five rules across all files, pass or fail. The totals are printed even when an earlier check, such as the manifest check, fails first, provided the parser and the roots resolve. When they don't, or a file can't be parsed, the run prints that the totals are unavailable and why.

The baseline records the rules it was recorded for under `"$rules"`.
- A baseline from before these rules has no `"$rules"`, and may hold only the five older rules. `--update-presentation-baseline` records the new rules once from current counts, alongside lowering the older ones. From then on it only lowers them.
- `"$rules"` must list known rules, including the five older ones and every rule the baseline's entries use. The check and the update refuse a baseline that breaks this, or that repeats a key in one object.
- A rule with an entry anywhere in the baseline is never re-recorded, whatever `"$rules"` says.
- The update also refuses while the shared-flow register has errors. Name the adapter, if the app has one, before recording, or the adapter's own `useBlocker` import is recorded under `router-blocker`.
- **Reviewer check.** The check can't tell a recording from a re-recording, so two edits let the update record afresh at a higher count: deleting one of the five newer rules from `"$rules"` together with every entry that uses it, and deleting the baseline file. Each shows in the diff of `presentation-baseline.json`. Look in every pull request for a rule removed from `"$rules"`, a deleted file or a count that rose, and ask why.

The rules read a real syntax tree, so a comment or a string that mentions `window.confirm` doesn't count. They are signals, not proof; the cross-app acceptance form is still how layout and wording differences are caught in the running apps. They don't see:
- **Dialogs:**
  - one taken into a variable (`const ask = window.confirm`) or reached through a computed key (`window[name]`);
  - one passed as a value, for example as a callback (`run(window.confirm)`) or through a comma (`(0, window.alert)(…)`);
  - one reached through `top`, `parent`, `frames` or `document.defaultView`, or called inside a dependency;
  - a stub or spy on them (`window.confirm = …`, `vi.spyOn(window, 'confirm')`).
- **Navigation blocking:**
  - a router imported under a namespace (`import * as Router`), or re-exported by an app module;
  - `router.history.block(…)` and `beforeunload` handlers.
- **Stylesheets:**
  - CSS-in-JS, styles built at run time, and stylesheets outside the roots;
  - preprocessor files (`.scss`, `.less`), and an `@import` of an outside sheet;
  - CSS escapes in a selector (`.\74 98-card`).
- **Class names:**
  - an object-literal spread (`{...{ className: 't98-a' }}`), and other props that carry classes (`classNames`, `contentClassName`);
  - `t98-` names passed through a variable or a helper defined in another file.
- **DOM access:**
  - walking a flow's markup through refs (`ref.current.firstElementChild`);
  - queries by tag or role into a flow's container (`querySelector('button')`), and selectors built at run time;
  - `dataset.t98…`, and mutation observers.

## Shared-flow register

Common features use the design system's shared flows rather than each app building its own. `@ten98/ui` ships the list of those flows as `shared-flows.json` at its package root, exported as `@ten98/ui/shared-flows.json`, from 0.40.0:

```json
{ "schemaVersion": 1, "features": { "team": { "exports": [{ "name": "TeamFlow", "entry": "@ten98/ui", "since": "0.5.0" }] } } }
```

The check reads that list from the app's own installed `@ten98/ui`, the way it finds rolldown, so each app is held to the list of the release it pins. Nothing is copied into this repository: `architecture.json` names only the register file and the first `@ten98/ui` release that ships the list (`firstUiVersion`). That version appears only in the message for a missing list. The check fails closed when the installed `@ten98/ui` has no list. It also refuses:
- a list it can't parse;
- one whose `schemaVersion` isn't 1;
- one with no features;
- an entry without exports.

`since` is shown in messages only. Each installed list already belongs to its own release, so the check doesn't compare `since` with anything.

Each app commits its own `shared-flows.json` at its root, with one entry for each feature in the list:

```json
{
  "leaveGuardAdapter": "src/lib/leave-guard.ts",
  "features": {
    "team": { "status": "uses" },
    "date-range": { "status": "absent", "reason": "The app has no date filters; every report covers a single day." },
    "provider-credentials": { "status": "exception", "reason": "Streams deployment-sourced secrets the flow can't show yet (design system F3).", "review": { "ui": "0.42.0" } }
  }
}
```

The check refuses:
- **Missing or unknown features:** a feature in the list that is missing from the file, and a feature in the file that isn't in the list.
- **The wrong file shape:** a file with no features, and a key repeated within one object.
- **`uses` without a real use:** some non-test file under the roots must render every one of the feature's exports as a JSX element (`<TeamFlow`, `<TeamFlow.Section`, `<Ui.TeamFlow`), or call it, for hooks and functions (`useConfirmDialog()`, `saveFile.call(…)`).
  - `memo(TeamFlow)`, `React.memo(TeamFlow)` and `createElement(TeamFlow)` render it as a tag does, and so does `component: TeamFlow` (or `Component: TeamFlow`) in an object literal, as route configs write it.
  - The export must come from its `entry`. A named import counts, aliased or not, and so do a namespace import (`Ui.TeamFlow`, or `const { TeamFlow } = Ui`) and an import through the app's own modules (`export * from '@ten98/ui'`, `export { TeamFlow } from '@ten98/ui'`, or an import exported again, reached through relative paths, with or without an extension or a trailing slash).
  - A module's own export of a name wins over its `export *`, as in ES modules. A barrel that declares or re-exports its own `TeamFlow` beside `export * from '@ten98/ui'` hands the app's component on, so an import of `TeamFlow` through it is not an import of the shared flow.
  - These don't count:
    - an import that is never rendered or called;
    - a value or member use (`{ team: TeamFlow }`, `TeamFlow.displayName`, `void TeamFlow`), and a re-export on its own;
    - a type-only import or use;
    - an import from another entry (`@ten98/ui/app`);
    - a local of the same name that isn't the import, such as a parameter or a nearer declaration;
    - any use in a test, mock or story file (`*.test.*`, `*.spec.*`, `*.stories.*`, `*.story.*`, `test-utils.*`, or under `__tests__/`, `__mocks__/` or `tests/`).
- **`absent` problems:** an entry without a reason, or with the export imported anywhere under the roots. That includes a named import, a namespace member or destructuring, a named re-export (`export { TeamFlow } from '@ten98/ui'`), an app module that re-exports `@ten98/ui` whole (`export * from`, `export * as`), and an import in a test file. A namespace import that is passed on whole (`render(Ui)`, `export { Ui }`, `{ ...Ui }`) or read with a computed key (`Ui[name]`) counts as importing every export of the package. A type-only import or re-export doesn't count.
- **`exception` problems:** an entry without a reason or without a review trigger. The trigger is one of:
  - `{ "ui": "<x.y.z>" }`, preferred. It must be a later `@ten98/ui` release than the installed one, in the same major, and at most two minor releases ahead (from 0.40.x, up to 0.42.z). A further trigger is refused; choose a nearer review point.
  - `{ "issue": "https://github.com/Ten98-IO-Company/<repo>/issues/<n>" }`.
- **A due trigger:** a `ui` trigger once the installed `@ten98/ui` has reached it.
  - Versions compare by SemVer precedence: a prerelease (`0.41.0-rc.1`) is below its release, and build metadata is ignored.
  - An installed version that isn't SemVer makes every `ui` trigger due.
  - Review a due entry, and either move it to `uses` or write a new reason and trigger.
- **Bad values:** a reason that is empty or longer than 500 characters, and a status other than `uses`, `absent` or `exception`.
- **A bad adapter:** a `leaveGuardAdapter` that is given but doesn't name a script file under the presentation roots.
- **A register outside the app:** one whose real path isn't inside the app's folder because a link takes it out (a symlink, or a junction on Windows), or whose folder is missing. The check never reads or writes through such a link.

`leaveGuardAdapter` is optional. The adapter is the function the app passes to `useLeaveGuard` as its `useBlocker` (`@ten98/ui`'s `LeaveGuardBlocker` type). The file it names is the one file whose router-blocker imports the `router-blocker` rule doesn't count. When it is left out, no file is exempt, and every such import counts. The check doesn't look inside the adapter, so it can be any script under the roots; the reviewer checks that it is only the adapter.

`node node_modules/@ten98/runtime/check.mjs --record-shared-flows .` writes the first register.
- It marks `uses` wherever every export is already rendered or called.
- It writes every other feature as an `exception` with an empty reason and no trigger, and leaves `leaveGuardAdapter` out.
- Those exceptions fail until someone writes them, as the first raw-statement allowlist does.
- It refuses to replace an existing register.

The register is a written record that the check holds to a few facts. It can't see:
- whether an `issue` trigger has been resolved. The check can't read issues, so the reviewer checks it;
- whether an `absent` feature really is absent. That is a written claim, and the reviewer checks it against the shared-flow table in the stack-standard brief;
- a mode of a flow. Workspace and project rename are modes of `WorkspaceCreateFlow` and `ProjectCreateFlow`; the check sees the export, not the prop that selects the mode;
- a flow that is rendered but wrapped, restyled, hidden or emptied by its props;
- a flow rendered only inside a function that nothing calls;
- a flow rendered for one route while a hand-built version of the same feature serves another;
- an import through a dynamic `import()` (`lazy(() => import(…))` included), `require(…)`, a deep path (`@ten98/ui/dist/…`) or a path alias (`@/ui`). None of these counts as an import for `absent`, or as a use for `uses`;
- a flow taken under another name before it is rendered (`const Flow = TeamFlow; <Flow />`), and a barrel that rebinds it (`export const Flow = TeamFlow`) or exports it as `default`. A truthful `uses` through one of these is refused until the flow is rendered by its own name;
- a flow reached through a ring of barrels that rename it on the way round: the search follows each module once;
- a use through a namespace re-export (`export * as Ui from '@ten98/ui'`) in another module. The re-export itself counts as an import for `absent`, but not as a use.

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
