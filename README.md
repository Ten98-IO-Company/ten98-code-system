# Ten98 Code System

Shared server-side building blocks for Ten98 apps, so every app gets the same tested behaviour instead of its own copy.

`@ten98/runtime` is the common code behind [Ten98 Campaign](https://github.com/Ten98-IO-Company/ten98-campaign) and [Ten98 Discover](https://github.com/Ten98-IO-Company/ten98-discover). It also holds the architecture contract that keeps their versions, dependencies and source rules consistent. Shared React presentation lives in the [Ten98 Design System](https://github.com/Ten98-IO-Company/ten98-design-system).

## Why it exists

- **Fix once, fixed everywhere.** Email delivery, workspace roles, migrations, client addresses behind proxies and safe network reads are written, reviewed and tested in one place.
- **No hidden dependencies.** The runtime has no third-party runtime dependencies; apps install it from an immutable, checksummed release archive.
- **Consistent stack.** One checker keeps Node, TypeScript, React and dependency versions aligned across apps, and blocks new untyped source.
- **Open source** under the MIT licence.

## What's inside

| Area | Exports |
|---|---|
| Workspace roles | `workspaceRoles`, `mayGrantWorkspaceRole`, `mayManageWorkspaceMember` |
| Network reads | `readResponseText`, `openRouterFetch`, `oidcEndpoint` |
| Database migrations | `createMigrationLedger` |
| Client address behind proxies | `parseTrustedProxies`, `resolveClientAddress`, `normalizeClientAddress` |
| Email through Amazon SES | `sendSesEmail`, `verifySnsMessage`, `classifyEmailFeedback` |
| Architecture checks | `check.mjs` and [architecture.json](architecture.json) |

Each function's options and guarantees are in the [Runtime API](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Runtime-API) guide and in the type declarations shipped with the package.

## Get started

Guides are in the [wiki](https://github.com/Ten98-IO-Company/ten98-code-system/wiki):

- [Runtime API](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Runtime-API)
- [Architecture contract](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Architecture-Contract)
- [Verify and release](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Verify-and-Release)
- [Feature contracts](https://github.com/Ten98-IO-Company/ten98-code-system/wiki/Feature-Contracts)

Building a feature that already exists in a Ten98 app? Start with the [feature catalogue](features/catalog.json) and the [adoption guide](docs/FEATURE-ADOPTION.md).

## Community

- Questions and ideas: [Discussions](https://github.com/Ten98-IO-Company/ten98-code-system/discussions)
- Bugs and adoption work: [Issues](https://github.com/Ten98-IO-Company/ten98-code-system/issues), tracked on the [Ten98 project](https://github.com/orgs/Ten98-IO-Company/projects/1)
- Releases: [GitHub Releases](https://github.com/Ten98-IO-Company/ten98-code-system/releases)
- Contributing: [contributing guide](https://github.com/Ten98-IO-Company/.github/blob/main/CONTRIBUTING.md) and [Code of Conduct](https://github.com/Ten98-IO-Company/.github/blob/main/CODE_OF_CONDUCT.md)

## Security

Please report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/Ten98-IO-Company/ten98-code-system/security/advisories/new), not in public issues. See the [security policy](https://github.com/Ten98-IO-Company/.github/blob/main/SECURITY.md).

## Licence

[MIT](LICENSE). The software is provided "as is", without warranty, as the licence states.
