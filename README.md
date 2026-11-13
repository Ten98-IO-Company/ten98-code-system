# Ten98 Code System

Shared server-side building blocks for Ten98 apps, so every app gets the same tested behaviour instead of its own copy.

`@ten98/runtime` is the common code behind [Ten98 Campaign](https://github.com/Ten98-IO-Company/ten98-campaign), [Ten98 Discover](https://github.com/Ten98-IO-Company/ten98-discover) and [Ten98 Books](https://github.com/Ten98-IO-Company/ten98-books), for Ten98 apps and their developers. It also holds the architecture contract that keeps their versions, dependencies and source rules consistent. Shared React presentation lives in the [Ten98 Design System](https://github.com/Ten98-IO-Company/ten98-design-system).

## Why Code System

- **Fix once, fixed everywhere.** Workspace roles, safe network reads, database migrations, client addresses behind proxies, Amazon SES email and its bounce and complaint feedback are written, reviewed and tested in one place.
- **No hidden dependencies.** The runtime has no third-party runtime dependencies. Apps install it from an immutable, checksummed release archive.
- **Consistent stack.** One checker keeps Node, TypeScript, React and dependency versions aligned across apps, and blocks new untyped source.
- **Reuse before rebuilding.** A [feature catalogue](features/catalog.json) points to the maintained implementation of features that already exist in a Ten98 app.
- Open source under the MIT licence.

## Get started

- Install a release archive from [GitHub Releases](https://github.com/Ten98-IO-Company/ten98-code-system/releases) into the app's `vendor/` folder, and update the manifest and lockfile together.
- Import functions from `@ten98/runtime`. Their types ship with the package. Browser code imports from `@ten98/runtime/browser`, which has the workspace roles and response readers and needs no Node built-ins.
- Identity uses `@ten98/runtime/auth`, a better-auth preset with the shared policy. Install `better-auth@1.7.7` (an exact, optional peer) and set `skipLibCheck` in the app's TypeScript config, because better-auth's own type files reference Bun modules. Apps keep their routes, transactions, first-boot claim, OIDC flow and rate limiters. Cookie names default to an origin-derived prefix; an app that already uses better-auth passes its current `cookiePrefix` (Discover: `'better-auth'`) so existing sessions continue.
- Workspaces, members, invitations and instance operators use `createWorkspaceTeam` from `@ten98/runtime` over the common schema shipped as `workspace-team.sql`. Each method runs inside the app's transaction (READ COMMITTED, REPEATABLE READ or SERIALIZABLE; roll back on any error).
- Shopify crawler access uses `parseShopifyCrawlerAccess`, `shopifyCrawlerHeadersFor` and `verifyShopifyCrawlerAccess` for bounded signature parsing, exact-origin expiry checks and verification with a supplied Ed25519 public key. These helpers perform no network calls or credential storage; apps retain authorization and transport safeguards.
- Public-network checks use `addressKey`, `publicNetworkAddress`, `pinnedNetworkPeer` and `resolveNetworkHost`. Resolution returns both DNS families; the caller admits the complete answer set before connecting and verifies the actual connected peer.
- Money uses `bigint` minor units with no floating point. The functions are `parseMoney`, `formatMoney`, `addMoney`, `subtractMoney`, `compareMoney`, `multiplyMoney`, `percentOfMoney` and `allocateMoney`, from `@ten98/runtime` or `@ten98/runtime/browser`.
  - The currency exponent is 0, 2 or 3, so BHD, KWD and OMR use 3.
  - Parsing refuses more fraction digits than the exponent.
  - Rates and percentages are decimal strings, rounded `half-up` (away from zero), `half-even` or `down` (toward zero). All three modes are symmetric for negative amounts.
  - Allocation by weights always sums to the total.
  - Apps keep currency selection, display locale and ledger postings.
- `normalizeLighthouseReport` validates and reduces a supplied local Lighthouse report. It preserves unavailable measurements, errors and coverage limits; it does not run a browser or authorize a website request.
- Isolated browser execution uses the server-only `@ten98/runtime/browser-audit` entry. It provides `createBrowserAuditControl` and `createPublicEgressProxy`; the capsule runs separately with `node node_modules/@ten98/runtime/browser-audit-capsule.mjs`. See the [complete deployment and authority contract](docs/FEATURE-ADOPTION.md#isolated-browser-audit). This candidate does not establish production or consumer acceptance.
- Run `node node_modules/@ten98/runtime/check.mjs .` as the app's `check:architecture` script, first in every `test` and `build` script. [architecture.json](architecture.json) declares the shared versions and dependencies.
- Apps keep their own authorization, storage, credentials and paid-work accounting. The runtime owns only the shared mechanism.

Installation, configuration and guides are in the [wiki](https://github.com/Ten98-IO-Company/ten98-code-system/wiki):

- [Development](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Development): work on the runtime locally, run the tests and contribute code.
- [Usage](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Usage): install a release in an app and run the architecture check.
- [Releases](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Releases): cut, verify and upgrade a release.
- [Reference](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Reference): every exported function and what it guarantees.

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
