# ten98 code system

Read README.md, the wiki (https://github.com/Ten98-IO-Company/ten98-code-system/wiki) and architecture.json before editing. This is the canonical home for shared technical mechanisms; @ten98/ui remains the presentation package.

Before implementing a repeated feature, inspect features/catalog.json and follow docs/FEATURE-ADOPTION.md. Prefer imports; copy a pinned complete implementation only when its stack integration requires it. Include every required migration, configuration, frontend/server entrypoint and dependency, the runnable source checks, provenance and known issues. Register the receiving app and version in its adoption issue. Never call a feature complete or battle-tested from helpers or synthetic tests alone.

Apply DRY, KISS and Ponytail: trace all callers, reuse native features, remove duplicate implementations, and add no speculative framework or dependency. Keep application authorization, storage, identity controllers and paid-work accounting in their apps until a concrete migration preserves their contracts.

Use bounded parallel workers with disjoint files: at most two implementation workers and one independent reviewer, twelve minutes per implementation task, two failed repair attempts and 120 seconds per command. Record the task, base, allowlist, acceptance cases and actual checks. Stop on unrelated edits or original failures. No paid calls, deployment or push without task authorization.

For a shared change, run npm test with Node 24, inspect npm pack and run affected consumers' required checks. Nontrivial logic needs a regression that fails without the fix. Architecture checks establish declared versions and dependencies only. Never report missing sources, synthetic fixtures or skipped live acceptance as production verification.

Update the canonical architecture declaration instead of copying its versions into app-owned policy files. Consumers use an immutable vendored archive and lockfile. Preserve immutable releases and source/license notices; keep only actively pinned archives in application folders after verifying historical bytes in GitHub Releases. Preserve unrelated working-tree changes.

Track defects and migration work in this repository's GitHub Issues and linked Project. Write documentation to the wiki, not to docs/ or the README; keep the README to what the project is, who it's for, community and legal links. Keep only files that tools read (catalog, architecture declaration, adoption guide) in the repository, and inline explanations in code comments. Put audit history, progress reports and historical evidence in GitHub instead of adding app-owned ledgers.

Make decisions at the lowest level that has the authority and the facts. Owners decide in-scope, reversible work themselves. The manager coordinates across sessions. The decision council answers high-level questions in issues labelled `decision`. The user decides anything irreversible or outward.
