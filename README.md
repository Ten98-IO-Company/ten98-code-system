# Ten98 Code System

Shared server-side building blocks for Ten98 apps, so every app gets the same tested behaviour instead of its own copy.

`@ten98/runtime` is the common code behind [Ten98 Campaign](https://github.com/Ten98-IO-Company/ten98-campaign), [Ten98 Discover](https://github.com/Ten98-IO-Company/ten98-discover) and [Ten98 Books](https://github.com/Ten98-IO-Company/ten98-books), for Ten98 apps and their developers. It also holds the architecture contract that keeps their versions, dependencies and source rules consistent. Shared React presentation lives in the [Ten98 Design System](https://github.com/Ten98-IO-Company/ten98-design-system).

## Why Code System

- **Fix once, fixed everywhere.** Workspace roles, safe network reads, database migrations, client addresses behind proxies, Amazon SES email and its bounce and complaint feedback are written, reviewed and tested in one place.
- **No hidden dependencies.** The root entry has no third-party runtime dependencies. Entry points that wrap a library (`./db`, `./tenancy`, `./config`, `./email`, `./log`, `./auth`) take it as an exact optional peer, which the app installs itself. Apps install the runtime from an immutable, checksummed release archive.
- **Consistent stack.** One checker keeps Node, TypeScript, React and dependency versions aligned across apps, and blocks new untyped source.
- **Reuse before rebuilding.** A [feature catalogue](https://github.com/Ten98-IO-Company/ten98-code-system/blob/main/features/catalog.json) points to the maintained implementation of features that already exist in a Ten98 app.
- Open source under the MIT licence.

## Get started

- Install a release archive from [GitHub Releases](https://github.com/Ten98-IO-Company/ten98-code-system/releases) into the app's `vendor/` folder and update the manifest and lockfile together: [Usage](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Usage).
- Import from `@ten98/runtime`, or from an entry point: `/browser`, `/auth`, `/db`, `/tenancy`, `/tenancy/testing`, `/config`, `/email`, `/log` or `/browser-audit`. Every export is in the [Reference](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Reference).
- Adopt an entry point or a feature with the [adoption guide](https://github.com/Ten98-IO-Company/ten98-code-system/blob/main/docs/FEATURE-ADOPTION.md), which has a checklist per entry point, and the [feature catalogue](https://github.com/Ten98-IO-Company/ten98-code-system/blob/main/features/catalog.json).
- Run `node node_modules/@ten98/runtime/check.mjs .` as the app's `check:architecture` script, first in every `test` and `build` script. [architecture.json](https://github.com/Ten98-IO-Company/ten98-code-system/blob/main/architecture.json) declares the shared versions and dependencies.
- Apps keep their own authorization, storage, credentials and paid-work accounting. The runtime owns only the shared mechanism.

More in the [wiki](https://github.com/Ten98-IO-Company/ten98-code-system/wiki): [Development](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Development) to work on the runtime, and [Releases](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Releases) to cut, verify and upgrade a release.

## Community

- Questions and ideas: [Discussions](https://github.com/Ten98-IO-Company/ten98-code-system/discussions)
- Bugs and feature requests: [Issues](https://github.com/Ten98-IO-Company/ten98-code-system/issues)
- Roadmap: [Ten98 Code System Project](https://github.com/orgs/Ten98-IO-Company/projects/5)
- Releases: [GitHub Releases](https://github.com/Ten98-IO-Company/ten98-code-system/releases)
- Contributing: [contributing guide](https://github.com/Ten98-IO-Company/.github/blob/main/CONTRIBUTING.md) · [Code of Conduct](https://github.com/Ten98-IO-Company/.github/blob/main/CODE_OF_CONDUCT.md)

## Security

Report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/Ten98-IO-Company/ten98-code-system/security/advisories/new); see the [security policy](https://github.com/Ten98-IO-Company/.github/blob/main/SECURITY.md). Please don't open public issues for security problems.

## Legal

- Licence: [MIT](LICENSE).
- Provided "as is", without warranty, as stated in the licence.
- Ten98 and the Ten98 logo are trademarks of Ten98 Technologies Ltd. The MIT licence covers the code, not the name or logo: forks must use their own name and branding.
- The hosted apps at *.ten98.io are covered by the Ten98 privacy policy (https://ten98.io/legal/privacy). Self-hosted installs are run by their operator and send no data to Ten98.
