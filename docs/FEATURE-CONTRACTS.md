# Identity, navigation and search contracts

Use the [catalogue](../features/catalog.json) to obtain the complete versioned implementation and its tests. Shared imports own portable policy and presentation; application adapters retain transactions, identity and persistence. New stateful Node applications default to SQLite with Drizzle and checked TypeScript under the canonical `databasePolicy` in [architecture.json](../architecture.json). Stateless packages remain database-free; native Cloudflare D1 is an explicit platform exception. Discover is an existing PostgreSQL/pg-boss feature reference, not a ready SQLite adaptation; preserving accounts, atomic enqueue, paid-work receipts and recovery is required before conversion.

## Membership and invitations

Import `workspaceRoles`, `mayGrantWorkspaceRole` and `mayManageWorkspaceMember` from `@ten98/runtime`. A member change requires authority over both the saved role and the requested role; removal requires authority over the saved role. Unknown roles fail closed. These predicates do not establish tenant access or protect the last owner.

Read current actor and target memberships inside the same transaction as mutation. Preserve at least one owner, scope every query to the workspace, and recheck authority after asynchronous work. Permanently invalidate outstanding invitations when their sender loses the relevant grant authority or their recipient is removed. Restoring a membership must never revive an invalidated invitation.

Ownership transfer requires a current owner, a different existing member in the same workspace and explicit confirmation of that member's email. Atomically promote the recipient and demote the actor to administrator, preserve other owners, invalidate invitations that the actor can no longer grant, and record the change. A client that cannot confirm the outcome must reload current authority before retrying.

New invitation links carry the capability in `#invite=`, never a query string. Read it once into client state and remove it from browser history. Inspect, accept and initiate invitation-related OIDC sign-in using POST bodies. Keep existing valid query links and earlier API paths usable during migration; do not generate new links in those forms. Tokens remain expiring, single use and stored as hashes. Existing-account acceptance requires the invited identity's authenticated session and cannot replace its name or password.

## Authentication adapters

Both adapters require a host-held first-owner capability, a persistent claimed installation, atomic setup and no reopening of setup after account removal. Preserve password access, user IDs, workspace memberships, instance operators and issuer/subject bindings during any migration. Never link an existing account using an unproved email assertion.

Use [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) and the [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html): Authorization Code with S256 PKCE, transaction-specific state/nonce, exact registered callbacks and verified issuer/subject identity. Delegate protocol construction and token validation to maintained libraries. Campaign uses its installed `openid-client`; Discover uses Better Auth's OAuth helpers and JOSE verifier. Discover's approved JWK import, DNS pinning, endpoint restrictions and bounded transport surround that verifier; they do not replace JWT signature verification. Do not introduce a private protocol, manually decode a JWT as proof, or remove those network guards to simplify SDK integration.

Both adapters verify asymmetric ID-token signatures against the issuer's JWKS in addition to claims. Campaign enables `openid-client`'s official `enableNonRepudiationChecks`; configure an advertised asymmetric signing algorithm and matching JWKS. This is a shared validation requirement, stronger than the direct TLS token-response validation that OIDC Core also permits. Run Campaign's signed HTTPS fixture as documented in `docs/OIDC-TESTING.md`; its ordinary unit run explicitly skips that opt-in check.

OIDC authenticates a subject; workspace admission and owner grants remain application authorization policy. Both invitation-based and explicitly configured provisioning adapters must preserve account-link proof and prevent an email assertion from taking over an existing account.

Discover supplies the default invitation-based OIDC admission, explicit linking, password recovery, MFA, scoped native API keys and MCP implementation. Campaign retains its existing Node HTTP/openid-client controllers, now on PostgreSQL: configured allowlisted OIDC addresses can provision accounts, while already linked issuer/subject identities retain access independently of later provisioning-list changes. Campaign still allows owner invitations as well as explicit transfer. These admission policies are distinct, deliberate compatibility boundaries; changing them requires an explicit access-policy decision and migration tests. The invitation transport, current-authority and revocation guarantees above apply to both adapters.

Campaign host password recovery is a fallback, not web recovery or MFA parity. Its outbound provider credentials are not native API keys. Adopt Discover's complete native implementations when those capabilities are needed; do not copy partial handlers into a different store or build an unused shared identity service. Track migration decisions and receiving versions in the owning GitHub issue.

A controller migration must first test an isolated restore with preserved user/workspace/project IDs, exact issuer/subject pairs, owner counts and operator grants. Legacy password hashes need a verified compatibility path or an explicit recovery transition; copying incompatible hashes is insufficient. Define session invalidation, invitation handling, encrypted credential/key availability and rollback before cutover. Compare login, linking, revocation, concurrent membership changes and current-authority checks against the retained adapter through actual HTTP and persistence. Only then replace the adapter and remove its old callers. Publish the migration and its full schema/configuration closure with the implementation.

Instance-operator grants are host-only and independent of workspace ownership. Bootstrap and successful host grant/revoke commands persist audit events in the same transaction as authority changes, including idempotent host commands. Audit failure must refuse the operation; active sessions observe revocation immediately. A host may revoke the final operator and regrant an existing account through the same host CLI. Retain existing operator rows on upgrade without fabricating earlier audit events; Campaign's history starts when the audit schema is installed. Password recovery and workspace memberships remain independent.

## Sidebar and authentication presentation

Import `useSidebarNavigation` and `AuthLayout` from `@ten98/ui`. The sidebar hook uses the shared 760px breakpoint, excludes closed mobile navigation from focus, makes an open drawer modal, contains visible keyboard controls, supports Escape, restores trigger focus and releases scroll/inert state on desktop resize. Native modal dialogs retain their own focus and Escape behavior; a nonmodal `dialog.show()` does not release drawer containment. Spread `sidebarProps` on the referenced sidebar and `contentProps` on the background content; label the sidebar and connect its trigger with `aria-controls` and `aria-expanded`.

Applications retain routing, selected workspace/project, authentication controllers and unsaved-draft guards. `AuthLayout` may omit `title` when its children already supply the native heading. Keep one main landmark, the existing heading hierarchy, labelled inputs, mobile decoration rules and accessible control sizes. Support React versions declared by the package, including native inert behavior.

## Search boundaries

Search explicit values that the interface displays. Campaign collection search uses display labels and joins provider/account names where shown; hidden identifiers and metadata must not accidentally match. Preserve numeric zero, unavailable values, original row identity and selection. Label the collection being searched and hide an inactive search control.

Discover tool navigation searches its declared labels and aliases. Report filters retain their applied/draft, pagination and loaded-versus-total semantics. Shared DataTable search uses declared columns. These different operations share a standard of explicit searchable fields; they must not be collapsed into a whole-record serializer or a query that silently changes scope.

## Acceptance

Run Node 24 shared tests, inspect actual package contents, install identical immutable archives with valid lockfiles, and pass affected consumer checks. Consequential fixes require a regression that fails against the earlier behavior. Verify identity through actual HTTP/session/persistence paths and navigation through a real browser, including narrow layout, keyboard, revocation, stale authority and uncertain outcomes. Record exact provenance, actual commands, limitations and downstream versions in GitHub. Local signed OIDC and mail fixtures do not certify a live provider or production deployment.
