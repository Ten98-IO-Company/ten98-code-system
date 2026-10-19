# ten98 code system

Read README.md and architecture.json before editing. This is the canonical home for shared technical mechanisms; @ten98/ui remains the presentation package.

Apply DRY, KISS and Ponytail: trace all callers, reuse native features, remove duplicate implementations, and add no speculative framework or dependency. Keep application authorization, storage, identity controllers and paid-work accounting in their apps until a concrete migration preserves their contracts.

Use bounded parallel workers with disjoint files: at most two implementation workers and one independent reviewer, twelve minutes per implementation task, two failed repair attempts and 120 seconds per command. Record the task, base, allowlist, acceptance cases and actual checks. Stop on unrelated edits or original failures. No paid calls, deployment or push without task authorization.

For a shared change, run npm test with Node 24, inspect npm pack and run affected consumers' required checks. Nontrivial logic needs a regression that fails without the fix. Architecture checks establish declared versions and dependencies only. Never report missing sources, synthetic fixtures or skipped live acceptance as production verification.

Update the canonical architecture declaration instead of copying its versions into app-owned policy files. Consumers use an immutable vendored archive and lockfile. Preserve immutable releases and source/license notices; keep only actively pinned archives in application folders after verifying historical bytes in GitHub Releases. Preserve unrelated working-tree changes.

Track defects and migration work in this repository's GitHub Issues and linked Project. Keep README and code comments focused on current operation and non-obvious constraints; put audit history, progress reports and historical evidence in GitHub instead of adding app-owned ledgers.
