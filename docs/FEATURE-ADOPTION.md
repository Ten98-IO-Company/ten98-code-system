# Adopt a complete feature

Start with [the feature catalogue](../features/catalog.json) and the canonical `databasePolicy` in [architecture.json](../architecture.json). New stateful Node applications default to PostgreSQL with Drizzle and checked TypeScript; stateless packages need no database. Discover supplies the default framework, identity and feature source on PostgreSQL, Drizzle and pg-boss. Campaign also runs PostgreSQL and Drizzle; its retained identity and routing adapters have separate adoption gaps. Native Cloudflare D1 is an explicit platform exception; other nondefault engines require a recorded purpose and review. Connect is not built yet.

The catalogue retains `defaultAuthenticatedNodeStack` as its framework-source selector for compatibility; database choice comes from the canonical policy. The engine in an existing app is not the default for a new application.

Each catalogue `sources` entry names the app's current release tag. Check out that tag in a fresh working folder, install through its lockfile with Node 24 and the app's own package manager, and run its listed checks before adopting anything. It is a complete reference to adopt into the same stack, not a drop-in package:

```sh
git clone --depth 1 --branch v0.2.1 https://github.com/Ten98-IO-Company/ten98-discover.git work/ten98-feature-reference
```

Entry-point paths in the catalogue are navigation aids, not a list of independently copyable files. A tag carries the complete source closure: routes, UI, controllers, schema and migrations, jobs, public configuration examples, lockfiles, pinned runtime and UI archives, tests, licences and notices. The 2026-10-20 source bundles are archived history and predate Campaign on PostgreSQL, Amazon SES and account closure.

Use imports for `@ten98/runtime` primitives and `@ten98/ui` presentation. A URL validator is not OIDC sign-in; a transport wrapper is not a paid-work lifecycle; a grant predicate is not transactional tenant authorization. Follow the catalogue's full source reference when adopting those features.

For stack-bound features, first run the unmodified reference with its own documented setup and tests. Then trace the caller through route admission, session/token identity, authorization, validation, transaction, provider boundary, receipt and rendered outcome. Adopt the complete flow into the same supported stack or make a controlled adaptation with explicit migrations and compatibility tests. Copying one handler while omitting its schema, lock, worker or authority recheck is incomplete.

Record the source repository and tag, the commit, the source path and the reason for adaptation beside copied code or in the consuming change. Retain copyright and notices. Link the owning code-system GitHub issue and identify who will port later fixes. Prefer improving the maintained canonical implementation and adopting that version together; do not establish independently evolving auth/provider frameworks.

Verification must include the feature's listed tests and actual UI/API/persistence path, plus relevant negative cases: wrong tenant/role, revocation after a wait, expired/reused capability, malformed/incomplete response, failed transaction, stale draft, unmount/navigation, keyboard/narrow layout and uncertain provider outcome. Run network/provider scenarios only in approved isolated fixtures. Synthetic checks are evidence for their fixture scope; they establish no live-provider certification or production deployment.

Before claiming adoption complete, preserve existing accounts/data and error contracts, pass the consumer's architecture/type/test/build gates, obtain independent review, and record the exact source tag and commit, commands, results, skips and remaining gaps in GitHub. The catalogue's issue statuses are a snapshot: consult issues [#4](https://github.com/Ten98-IO-Company/ten98-code-system/issues/4) through [#8](https://github.com/Ten98-IO-Company/ten98-code-system/issues/8) before choosing a reference. Current static dependency checks do not prove complete feature adoption.
