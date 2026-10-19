# Shared feature library implementation brief

The original request correctly asks for consistent care across repeated features, but “make everything the same” can hide missing capabilities or force incompatible stores/controllers together. Equal dependency versions and a few helpers do not meet that objective. The deliverable must make complete working implementations discoverable, adoptable and maintained, with clear proof of what each supports.

## Improved implementation prompt

Maintain ten98-code-system as the canonical technical feature library for the ten98 apps. Reuse the strongest existing complete feature before building another implementation. Apply DRY, KISS and Ponytail after tracing the real flow and every caller. Prefer deleting duplicate implementations through imports; where a feature remains framework-bound, publish its complete reviewed public source as an immutable release bundle and document controlled adoption. Do not create a scaffolder, framework or service to make the catalogue larger.

Use Discover's existing TanStack Start/Nitro, Better Auth, PostgreSQL/Drizzle and pg-boss stack for new authenticated Node apps. Retain Campaign's Node HTTP/SQLite/openid-client implementation as an explicit migration adapter until accounts, credentials, memberships, sessions and data have a tested migration. Preserve the native Cloudflare exception. Connect has no implementation yet and must not be reported as covered.

Catalogue first-user setup, local sign-in/account security, OIDC, workspaces/projects/RBAC/invitations, provider credentials and OpenRouter, native API keys, MCP, search/filters, preferences and shell/navigation. For each, name supported stacks, actual UI/API/persistence entrypoints, schema/jobs/config dependencies, runnable tests, known gaps and owning GitHub issues. Separate portable shared imports from stack-bound references and unavailable capabilities. Never label a helper or synthetic catalogue preview a complete authentication/provider feature.

Publish the full Campaign, Discover and UI public source snapshots under `feature-library-2026-10-20`, using the three named source ZIPs and `feature-source-manifest.json`. Preserve transitive application source, active vendored packages, lockfiles, migrations, public configuration examples and licensing. Exclude secrets, private evidence/data, databases and dependency directories. Record per-file/bundle hashes, source revisions or retained working-tree provenance, exact checks, skipped checks and verification scope. An entrypoint-only excerpt does not satisfy source completeness.

Before implementation, compare candidate flows and explain the smallest reuse boundary. Preserve native tenant checks, transaction/lock ordering, last-owner rules, identity binding, capability expiry/single use, draft generations, secret clearing, exact-byte evidence and paid-operation uncertainty. Common presentation belongs in @ten98/ui; common portable mechanisms belong in @ten98/runtime. Do not weaken a specialized contract to force extraction.

For every adopted or fixed feature, leave the smallest meaningful runnable regression, including an old-behavior negative control for consequential bugs. Run existing offline, integration, UI and build checks appropriate to the change; independently review the complete flow. Record actual commands/results and limits without claiming live identity/provider, production or “battle-tested” acceptance from fixtures. Do not add tests that merely restate catalogue metadata.

Track bugs, adoption work and migration decisions in the existing GitHub issues/project. Preserve required contracts/provenance in source, keep only active versioned vendor archives, and remove obsolete plans, duplicates or generated artifacts only after reference checks and verified preservation. Do not create another progress ledger in each app.

## Completion gates

- A fresh session can locate the correct implementation, supported stack, exact source bundle, dependencies, tests and known issues without reconstructing chat history.
- Each bundle resolves its transitive application imports and immutable vendor inputs from that checkout; its manifest records verified hashes and reproducible check instructions.
- A complete adoption preserves the real UI → API → authorization → persistence/provider → outcome path and its failure/recovery behavior. Missing capabilities are explicit.
- Shared code is imported; controlled copies retain provenance and a fix-propagation owner. The same defect is fixed at the maintained common boundary wherever possible.
- GitHub records current bug/migration status and exact validation evidence. Keep catalogue states tied to the published snapshot and current owning issues; #5/#7/#8 remain open until their acceptance is actually satisfied.

## Independent reviewer checklist

- Open the release manifest and verify each bundle hash; check that catalogue paths/tests exist and the complete source/config/schema/license/vendor closure is present.
- Trace one security feature and one provider feature end to end. Look specifically for omitted authority rechecks, credential context, migration, receipt/uncertainty or UI state handling.
- Compare supported-stack and capability claims against implementation. Confirm Connect absence and Campaign's remaining recovery/MFA/API/MCP gaps are not presented as parity.
- Check meaningful failure/negative-control evidence and consumer gates; distinguish a declared command from a run, and synthetic fixtures from external acceptance.
- Confirm current issues, preservation before cleanup and maintenance ownership. Report the smallest blocking defect rather than requesting speculative infrastructure.
