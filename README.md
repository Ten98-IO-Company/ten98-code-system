# ten98 code system

The maintained home for common ten98 technical behavior and architecture declarations. The separate [design system](https://github.com/Ten98-IO-Company/ten98-design-system) owns React presentation. This repository ships the dependency-free `@ten98/runtime` package and its architecture checker.

## Common implementation

Import these functions from `@ten98/runtime`:

- `workspaceRoles` and `mayGrantWorkspaceRole(actor, role)` own the four membership roles and grant rule: owners manage all known roles; administrators manage editors/viewers; other or unknown actors cannot grant access. Database tenant checks, last-owner locks and instance-operator authority remain app-owned.

- `readResponseText(response, { maxBytes, signal })` counts received bytes, rejects malformed UTF-8 and cancels/releases the reader on completion, failure or abort. Callers retain JSON/schema parsing, status policy and safe errors.
- `openRouterFetch(path, { apiKey, title, body, signal, metadata }, send)` uses the fixed HTTPS OpenRouter API, rejects redirects, omits ambient credentials and makes one request. GET defaults to a 10-second deadline; JSON POST defaults to 60 seconds. Pass a signal when requests share one deadline. Paid authorization, idempotency, receipts and reconciliation remain app-owned.
- `oidcEndpoint(raw, { issuer, allowHttp })` validates HTTPS URLs without credentials or fragments; issuers also reject queries. `allowHttp` is for an explicitly admitted test fixture. Apps retain framework PKCE/state/nonce/signature checks, single-use transactions, identity linking, MFA and endpoint/DNS policies.

## Architecture contract

[architecture.json](architecture.json) is the canonical declaration of shared versions, package pins and approved runtime dependencies. [check.mjs](check.mjs) checks those declarations and the test/build gates:

```sh
node check.mjs ../ten98-design-system ../ten98-campaign ../ten98-discover .
```

Campaign, Discover and the design-system development tools share Node 24, React, TypeScript and Vite versions. Their existing npm/pnpm lockfiles remain installation inputs. Application consumers use the same accepted immutable UI and runtime archives in `vendor`; standalone Docker builds require no sibling checkout or private registry. A design-system source version can be ahead of the last accepted consumer archive.

Shared presentation belongs in `@ten98/ui`; common server mechanisms belong here. Frontends call their app's authenticated API. Provider keys, database access and paid dispatch stay on the server. Reuse installed frameworks and native platform capabilities before adding a library. Runtime dependency or version changes require updating this contract and checking affected consumers together.

Current retained adapters are explicit: Campaign uses Node HTTP, SQLite and `openid-client`; Discover uses TanStack Start/Nitro, PostgreSQL/Drizzle and Better Auth. Their storage, routing and identity controllers have not been unified. Shared primitives preserve their distinct security and accounting contracts. The checker verifies declared consistency; it does not prove framework equivalence, runtime call coverage, OIDC interoperability or release readiness.

Docker applications use project-scoped volumes, private database networking, loopback host bindings, native `init`, bounded health probes and a 30-second stop grace. Discover's separate migration/worker lifecycle remains necessary. Image pins and service layout remain deployment-owned; there is no Compose generator or universal service template.

`ten98-io` remains a native Cloudflare Worker/static site; its D1, email and rate-limiting bindings need no React, Node server controllers or Compose. Third-party infrastructure retains upstream stacks. `ten98-connect` had no local source or accessible repository at the initial audit and is not certified. New apps must be inventoried and added to the contract before claiming suite coverage.

## Verify and release

```sh
npm test
npm pack --dry-run
npm pack
```

There is no build step or third-party runtime dependency. Inspect the archive, copy the same bytes into each consumer's `vendor`, update its manifest and existing lockfile together, then run the consumer's architecture, offline, type and build checks. Retain earlier releases unchanged. Changed shared code needs a new package version; never overwrite consumed bytes. Application publication and deployment are separate actions.

Specialized network readers remain when they enforce additional contracts, such as exact content-length evidence, binary MCP output or inbound request error semantics. Extract them only when every existing guard can be preserved with less code.
