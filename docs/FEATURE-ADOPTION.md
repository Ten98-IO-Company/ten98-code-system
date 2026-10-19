# Adopt a complete feature

Start with [the feature catalogue](../features/catalog.json). It separates importable runtime/UI code from working implementations that require their source application's framework, schema and controllers. The default for a new authenticated Node app is Discover's TanStack Start/Nitro, Better Auth, PostgreSQL/Drizzle and pg-boss stack. Campaign is a retained Node HTTP/SQLite/openid-client reference with explicit migration gaps. Connect is not built yet.

The source release is [feature-library-2026-10-20](https://github.com/Ten98-IO-Company/ten98-code-system/releases/tag/feature-library-2026-10-20). The published `feature-source-manifest.json` records exact bundle/file hashes, executed checks, skips and verification limits. Verify the chosen bundle against that manifest before adoption. Use Node 24 and the bundle's existing package manager and lockfile.

For example, download the default-stack reference into a fresh working folder:

```sh
gh release download feature-library-2026-10-20 --repo Ten98-IO-Company/ten98-code-system --pattern feature-source-manifest.json --pattern ten98-discover-source.zip --dir work/ten98-feature-reference
```

Download the manifest and the required `ten98-campaign-source.zip`, `ten98-discover-source.zip` or `ten98-design-system-source.zip`. Verify SHA256 before extraction. Each bundle must contain the complete reviewed public source closure: routes, UI, controllers, schema/migrations, jobs, public configuration examples, manifests/lockfiles, actively pinned runtime/UI vendor archives, tests, licenses and notices. Dependencies install through the preserved lockfile; dependency trees, secrets, databases and customer data do not belong in source bundles. Entry-point paths in the catalogue are navigation aids, not a list of independently copyable files.

Use imports for `@ten98/runtime` primitives and `@ten98/ui` presentation. A URL validator is not OIDC sign-in; a transport wrapper is not a paid-work lifecycle; a grant predicate is not transactional tenant authorization. Follow the catalogue's full source reference when adopting those features.

For stack-bound features, first run the unmodified reference with its own documented setup and tests. Then trace the caller through route admission, session/token identity, authorization, validation, transaction, provider boundary, receipt and rendered outcome. Adopt the complete flow into the same supported stack or make a controlled adaptation with explicit migrations and compatibility tests. Copying one handler while omitting its schema, lock, worker or authority recheck is incomplete.

Record the release tag, bundle SHA256, source path and reason for adaptation beside copied code or in the consuming change. Retain copyright and notices. Link the owning code-system GitHub issue and identify who will port later fixes. Prefer improving the maintained canonical implementation and adopting that version together; do not establish independently evolving auth/provider frameworks.

Verification must include the feature's listed tests and actual UI/API/persistence path, plus relevant negative cases: wrong tenant/role, revocation after a wait, expired/reused capability, malformed/incomplete response, failed transaction, stale draft, unmount/navigation, keyboard/narrow layout and uncertain provider outcome. Run network/provider scenarios only in approved isolated fixtures. Synthetic checks are evidence for their fixture scope; they establish no live-provider certification or production deployment.

Before claiming adoption complete, preserve existing accounts/data and error contracts, pass the consumer's architecture/type/test/build gates, obtain independent review, and record the exact source/hash, commands, results, skips and remaining gaps in GitHub. The catalogue's issue statuses are a snapshot: consult issues [#4](https://github.com/Ten98-IO-Company/ten98-code-system/issues/4) through [#8](https://github.com/Ten98-IO-Company/ten98-code-system/issues/8) before choosing a reference. Current static dependency checks do not prove complete feature adoption.
