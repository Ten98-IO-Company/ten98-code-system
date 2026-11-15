# `@ten98/runtime/api`: design note

Status: proposal for review by the coordinator and the books, discover and campaign sessions. No code is built from this note until they confirm it. The constraints come from [#123](https://github.com/Ten98-IO-Company/ten98-code-system/issues/123), including its comment "Design requirement for the `./api` handler shape: ordering is structural". Related work: `./start` (PR #155), `./log` (#142) and the team controller's ordering fix (#153).

The note describes the entry, then what each app keeps, then how each app migrates, then the open questions. File references to the apps are to `dev` in books and discover and to `feat/consent-history` in campaign, as read on 2026-11-15.

## 1. Goals and limits

- **One request pipeline in a fixed order.** The order is: authenticate, resolve and authorise the scope, parse and validate, then run in the scoped transaction. A route author declares each stage and cannot reorder them. The route function receives `{ access, input }` only after authorisation.
- **Same answers as today.** The paths, status codes and response shapes stay the same, and so do discover's OpenAPI document and MCP tool surface. The exceptions are the changes listed in section 5. Each app accepts or refuses them.
- **Apps migrate one module at a time.** Routes that have not moved keep running through the app's existing dispatch, which sits in a fallback chain.
- **Out of scope.** The entry does not do authentication, sessions, rate-limit storage, OpenAPI generation, MCP, static files or HTML rendering. The apps keep these; see section 4.
- **Dependencies.**
  - It uses the runtime's `readJsonBody`, `readResponseBytes`, `resolveClientAddress` and `clientLimitKey`.
  - It uses `./log` for the request id and the error line.
  - zod 4.6.6 is its existing exact optional peer.
  - It adds no new library. Path matching uses the native `URLPattern`, which is global in Node 24.22.1 (checked).
  - The entry imports neither `./tenancy` nor drizzle. Apps pass the scope function in (section 2.5).

## 2. The entry

### 2.1 Shape

```ts
import { createApi, route, json, form, raw, stream, ApiError } from '@ten98/runtime/api';

export const api = createApi<Principal>({
  ready: () => assertDatabase(),                        // memoised: section 2.3
  live: ['/api/health/live'],                           // paths that skip ready()
  prelude: [collectorCors],                             // (request, ctx) => Response | null, before the route table
  fallback: [legacyApi],                                // (request, ctx) => Response | null, after it
  origin: { methods: 'unsafe', exempt: request => request.headers.has('authorization') },
  authenticate: request => principalFrom(request),      // the app's session, API key or capability; null when none
  client: { trustedProxies, secret: config.authSecret }, // peer() defaults to srvx's socket address
  limit: (key, max, windowMinutes) => spend(key, max, windowMinutes), // app storage; throws the app's 429
  scope: (principal, id, mode, run) => tenancy.withWorkspace(db, principal.userId, id, mode, run),
  guards: [{ prefix: '/api/companies/', check: ({ principal, access }) => requireFactor(principal, access) }],
  mapError,                                             // runs first on every error; null hands it to the defaults
  encode,                                               // optional; the default JSON encoder is in section 2.8
  headers,                                              // optional; added to every response that lacks them
  log,                                                  // a ./log logger
}, [...companyRoutes, ...voucherRoutes]);

export const voucherRoutes = [
  route({
    method: 'POST',
    path: '/api/companies/:companyId(uuid)/vouchers',
    scope: { param: 'companyId', mode: 'write' },
    limit: { key: ({ principal }) => `vouchers:${principal.userId}`, max: 600 },
    body: json(voucherInput, { maxBytes: 256 * 1024 }),
    run: async ({ access, input, tx, reply }) => reply(await postVoucher(tx, access, input.body), { status: 201 }),
  }),
];
```

`api.handle(request: Request): Promise<Response>` is the whole public surface of the instance. Books and discover call it from their existing `/api/$` route and Nitro middleware. Campaign needs a Node bridge; see section 6.3 and open question 7.

### 2.2 The route declaration

| Field | Meaning |
|---|---|
| `method` | One method, or an array of methods. `HEAD` and `OPTIONS` are never implied (section 2.4). |
| `path` | `URLPattern` pathname syntax. The named constraints `uuid` and `int` expand to fixed regexes. Any other constraint is a regex group. |
| `auth` | `'required'` (the default), `'optional'` or `'none'`. A route with a `scope` must use `'required'`. |
| `scope` | `{ param, mode: 'read' \| 'write', transaction?: boolean }`. It names the path parameter that holds the workspace or company id. |
| `access` | An optional async predicate, `({ principal, access, meta }) => void`. It throws the app's own error and runs at the end of stage 2. |
| `limit` | `{ key, max, windowMinutes? }` or an array of them. `key` receives `{ principal, client }` and never the scope id (section 2.6). |
| `params`, `query` | zod schemas for the path parameters other than the scope, and for the query. `query: 'refuse'` refuses any query string. |
| `body` | `json(schema, opts)`, `form(schema, opts)`, `raw(opts)`, `stream(opts)`, or nothing, meaning no body (section 2.7). |
| `origin` | `false` exempts the route from the origin check. Use it for signed webhooks and RFC 8058 one-click unsubscribe. |
| `meta` | App data that guards and `access` can read, such as discover's API-key scope for the route. |
| `run` | The route's logic. It receives the context in section 2.5, and never the `Request` or its body. |

**Building the table.** `createApi` checks the route table when it is built, and refuses:
- two routes with the same method and pattern;
- a `scope.param` that the pattern does not capture;
- a `scope` on a route that does not use `auth: 'required'`;
- a `stream` body on a route with a scoped transaction.

### 2.3 Dispatch and the fallback chain

For each request:

1. **Normalise.** One trailing slash is stripped, as books and discover do today. The path is not lowercased. The request id is taken through `./log`'s `requestId(request)`, and a logger bound to it is created.
2. **Liveness.** Paths listed in `live` and routes declared `live: true` skip readiness.
3. **Readiness.** `await ready()`. The function is memoised:
   - a success is cached for the life of the process;
   - concurrent requests share one in-flight call;
   - a rejection is not cached, so the next request retries it. A database that comes up later is served without a restart.

   A failure becomes the coded error `NOT_READY` (503) and goes through `mapError` first.
4. **Prelude chain.** Each function returns a `Response` or `null`. This is where discover's collector CORS (7 paths) and campaign's short links and webhooks go until they move to routes.
5. **Route table.** The path and method are matched in declaration order.
   - When both match, the route's pipeline runs (section 2.4).
   - When the path matches but the method does not, the fallback chain runs first, so a half-migrated path keeps serving the methods that have not moved. If the fallback returns `null`, the answer is `METHOD_NOT_ALLOWED` (405) with an `allow` header listing the route's methods.
6. **Fallback chain.** Each function returns a `Response` or `null`. The app's existing hand-written dispatch goes here, minus the modules already migrated.
7. **Not found.** `ROUTE_NOT_FOUND` (404). An app that wants signed-out callers to keep getting 401 for unknown paths, as all three do today, sets `notFound: 'authenticate-first'`. The answer is then `AUTH_REQUIRED` when there is no principal and `ROUTE_NOT_FOUND` otherwise.

Path parameters are percent-decoded once and must then match their constraint. `uuid` parameters are lowercased. A scope id that does not match its constraint does not match the route. It falls through to not-found, never to a 400, so a malformed scope id and an unknown one get the same kind of answer.

### 2.4 The pipeline: ordering is structural

A matched route runs these stages. A route author cannot reorder them, skip them, or reach the request body before stage 3.

| Stage | What runs | Refusals |
|---|---|---|
| 0. Origin | For methods in `origin.methods`, the `Origin` header must equal the configured origin. `'unsafe'` means every method except GET, HEAD and OPTIONS (books and campaign); `['POST']` is discover's set. `exempt(request)` sees headers only, such as discover's bearer requests. A route with `origin: false` is exempt. | `ORIGIN_REFUSED` 403 |
| 1. Authenticate | `authenticate(request)` returns a principal or `null`. Then the guards that match the path prefix and need only the principal run (`stage: 'principal'`). Then the route's `limit` entries are spent. | `AUTH_REQUIRED` 401; the app's own errors from guards and `limit` |
| 2. Scope | `scope(principal, id, mode, run)`, which is the app's `withWorkspace` (section 2.5). Then the scope-stage guards, then the route's `access` predicate. | Whatever `scope` throws for a missing or foreign scope, which must be one answer; the app's own errors |
| 3. Input | Path parameters, then the query, then the body, each validated by its declared schema. | `INPUT_INVALID` 400, `BODY_*` 400/413/415, `QUERY_REFUSED` 400, `BODY_NOT_ALLOWED` 400, `BODY_TIMEOUT` 408 |
| 4. Run | `run({ access, input, tx, principal, ... })` inside the scoped transaction. | The route's own errors |

Unscoped routes skip stage 2. A public route (`auth: 'none'`) skips stages 1 and 2, apart from its `limit`. On a public or signed-in route without a scope there is no tenant to leak, so it is enough that input comes after authentication.

**Before stage 3, nothing reads the body.**
- Stage 0 to 2 hooks receive the request's method, URL and headers only. They never receive the body stream.
- A request refused before stage 3 has its body cancelled, unread, so the declared length, the media type and the bytes play no part in the answer.
- The body-size refusal from a declared `Content-Length` is in stage 3 too. An outsider sending a 7 MB body to a scoped route gets the same not-found answer as one sending `{}`, and the server reads none of it.

**Where the body is read relative to the transaction.** A slow client must not hold a transaction open while it uploads, which is why books reads voucher bodies before `withCompany` today. So for a scoped route with a body:

1. **Pre-check.** `scope(principal, id, mode, async () => undefined)` checks the scope in a short transaction of its own. It runs the same membership query and gives the same refusal.
2. **Read and validate.** The input is parsed and validated outside any transaction.
3. **Locked check and run.** `scope(principal, id, mode, run)` checks again under the membership share lock and runs the route in that transaction.

A member removed between steps 1 and 3 gets the not-found answer at step 3. A route without a body skips the pre-check: its query and parameters are validated inside the transaction, after the locked check, which takes no I/O.

**`scope.transaction: false`** is for routes whose logic must not sit in one transaction, such as provider calls, paid work and `stream` bodies. Stage 2 then runs only the pre-check. `run` receives `access` from that check but no `tx`, and opens its own `withWorkspace` calls. `access` is then a point-in-time answer, and the guide says so.

### 2.5 The scope function and the route context

`scope` has the signature of the runtime's `withWorkspace` with the principal in place of the user id:

```ts
scope: <T>(principal: P, id: string, mode: 'read' | 'write', run: (tx: Tx, access: A) => Promise<T>) => Promise<T>
```

- **What each app passes.** Books passes `tenancy.withWorkspace` bound to its database (or, until it moves, its own `withCompany`, which has the same shape; see open question 4). Discover's adapter also checks an API-key principal's workspace inside the transaction, as `authorizeApiKey` does today. Campaign's adapter resolves a project to its workspace.
- **Not-found guarantee.** The entry relies on `scope` throwing one error for a missing scope and for a foreign one. `withWorkspace` already does this (`WorkspaceAccessError`, "Workspace not found or unavailable."), and the reference test (section 3) checks it for each app's adapter.

The context passed to `run`:

| Field | Present |
|---|---|
| `access` | Scoped routes: the value `scope` gave (for `withWorkspace`, `{ workspaceId, name, role }`). |
| `input` | `{ params, query, body }`, typed from the declared schemas. `body` is a `ReadableStream` for `stream` and a `Uint8Array` for `raw`. |
| `tx` | Scoped routes with a transaction. |
| `principal` | Routes with `auth: 'required'`; the principal or `null` with `'optional'`. |
| `url`, `headers`, `signal` | Always. `signal` aborts when the client goes away. |
| `requestId`, `log` | Always. `log` is bound to the request id. |
| `client(scope)` | The client's rate-limit key (section 2.6). |
| `limit(key, max, windowMinutes?)` | Spends a limit from inside the route, for keys that need the scope or the parsed input. |
| `reply(body, { status, headers })` | Encodes through the app's encoder. Multiple `set-cookie` values are appended one by one. |

`run` returns a `Response`, which passes through (section 2.8), or a value, which is encoded with status 200.

### 2.6 Guards and rate limits

**Guards** are table-level checks. A route cannot forget them.
- Each guard is `{ prefix?, stage: 'principal' | 'scope', check }`. Without `prefix` it applies to every route with `auth: 'required'`.
- A `scope`-stage guard receives `{ principal, access, route }`. It runs after the scope is authorised, so outsiders keep getting the not-found answer and only members meet the guard.
- Books' workspace factor gate becomes a scope-stage guard on `/api/companies/` and `/api/workspaces/`. Today it is a path-prefix check at `api.ts:56` before any area runs. This is the "carry the predicate into withCompany" upgrade path its comment names (`teams.ts:34-36`).
- Discover's rule that a key may call only listed routes becomes a principal-stage guard. It reads `route.meta.apiKeyScope` and keeps its 403 text.

**Rate limits.** The entry decides when a limit is spent. The app keeps how it is stored.
- **Storage.** `limit(key, max, windowMinutes)` is the app's storage. In books and discover that is the `request_limit` table. In campaign it is `login_limits`. The function throws the app's own 429.
- **Route `limit` field.** It is spent in stage 1, after authentication and before the scope check. Its `key` function receives `{ principal, client }` only. **It never receives the unauthorised scope id**, so an outsider cannot use up a workspace's limit by naming it. Limits keyed by workspace, invitation or e-mail address are spent inside `run` through `ctx.limit`, after authorisation and parsing. Books' resend limits and sign-in e-mail limit are examples.
- **`client(scope)`.** It returns `clientLimitKey(scope, resolveClientAddress(peer(request), x-forwarded-for, trustedProxies), secret)`.
  - The default `peer` reads srvx's `request.runtime.node.req.socket.remoteAddress`. Books (`client-rate-limit.ts:13-19`) and discover (`analytics-network.ts:54-65`) each have a copy of this today, which the default replaces.
  - An unresolved address gets the runtime's dedicated `<scope>:unresolved` key, which callers give a stricter limit.
  - The key text changes from the apps' `${scope}:client:<hmac>` to `${scope}:<hmac>`. Buckets expire within 60 minutes, so nothing needs migrating.
- **Public routes.** A limit on a public route is spent before its body is read. Discover's collector currently spends its per-site limit after parsing; it moves into `run` because its key needs the parsed site key.

### 2.7 Body modes and limits

Every body mode requires an explicit `maxBytes`. There is no default limit, so migrating a route cannot lower its existing limit by accident. Every mode reads under a deadline (`bodyTimeoutMs`, default 30 s), and a request that runs past it gets `BODY_TIMEOUT` (408).

| Mode | Media type | Reads with | Gives `run` |
|---|---|---|---|
| none (no `body`) | — | — | Nothing. A request with a body, meaning `Content-Length` other than 0 or any `Transfer-Encoding`, is refused with `BODY_NOT_ALLOWED`. This replaces discover's 25 inline checks (`api.ts:194` and others) and books' two (`account-security.ts:144,336`). |
| `json(schema, { maxBytes, allowEmpty? })` | `application/json` | `readJsonBody` (runtime, unchanged, plus a `signal` option) | The parsed and validated value. |
| `form(schema, { maxBytes })` | `application/x-www-form-urlencoded` only | bounded UTF-8 text, then `URLSearchParams` | A validated object. A repeated key is refused. Multipart is not supported; no app accepts it. |
| `raw({ maxBytes, type? })` | `type` when given | `readResponseBytes` | `Uint8Array`. For HMAC and SNS webhooks, which verify the bytes before parsing them. |
| `stream({ maxBytes, timeoutMs, type })` | `type`, exact | none | A `ReadableStream`. `Content-Length` is required and at most `maxBytes`, and `Transfer-Encoding` is refused, as campaign does (`zernio-media.ts:136`). The stream errors past the declared length, and stops on `signal` or the timeout. Requires `scope.transaction: false`. |

**Query.** Undeclared, it is ignored, as most routes do today. `query: schema` validates an object of single values, and a repeated key is refused. `query: 'refuse'` refuses any query string or fragment. That replaces discover's three hand-written patterns (`url.search`, `includes('?')` and `searchParams.size`) and books' two refusals.

**Byte limits each app needs** (from the current code; each one becomes an explicit `maxBytes`):

| App | Limits in use |
|---|---|
| books | 8,192 (default), 131,072 (balance preview), 262,144 (voucher writes) |
| discover | 17 distinct limits, from 256 (OpenRouter models) to 6,400,000 (reports); raw SES feedback 262,144 |
| campaign | JSON 2,048 (tracking events), 65,536 (default), 2 MiB (posts and the other large routes), 7 MiB (Drive upload); raw 4,096 (unsubscribe, discarded), 266,240 (SNS), 1 MiB (Zernio); form 65,536 (Twilio); stream 5,000,000,000 with a 30-minute timeout (media upload) |

### 2.8 Responses

- **A `Response` from `run` passes through.** This covers streams with backpressure, which stop on `signal`, exports with `content-disposition`, 302 and 303 redirects, HTML, `text/xml` and GIF.
- **Any other value goes through the encoder.** The default encoder matches books and discover:
  - JSON, with a `bigint` written as a decimal string;
  - `content-type: application/json`;
  - `cache-control: no-store`;
  - `x-content-type-options: nosniff`.

  Campaign passes its own encoder for `application/json; charset=utf-8`.
- **Default headers.** `headers(ctx)` and `x-request-id` are added to every response, passed-through ones included, but only where the response does not already set that header. So campaign's link pages keep their own CSP. Responses whose headers are immutable are rebuilt with the same body stream.

### 2.9 Errors

**Coded errors.** Every refusal the entry makes is an `ApiError` with a fixed `code`, `status` and public message. `readJsonBody` refusals keep their `JsonBodyError` codes. A zod failure in stage 3 becomes `INPUT_INVALID`. It carries the issue paths and codes and never the input values.

**Order of handling:**
1. **`mapError(error, ctx)` runs first on every error**, the entry's own included, and wins when it returns a `Response`. Each app keeps its existing texts and shapes this way: campaign's `{ error: { code, message } }`, books' `{ error, code: 'validation' }`, discover's `AccountClosureBlocked` blockers and its `retry-after: 5` on busy errors.
2. **When `mapError` returns `null`, the defaults apply:**
   - An `ApiError` is rendered as `{ "error": <its fixed message> }` with its status. A 405 gets `allow`, and a 429 gets `retry-after` when the error carries it. The default messages are the texts books and discover already share: "Sign in to continue.", "Route unavailable.", "Method not allowed.", "This action must originate from the application.", "Check the submitted fields and try again." and "The installation is not ready. Check configuration and database migrations." Each can be replaced through `messages`.
   - Any other error is a 500 with a **fixed body and the request id**: `{ "error": <the app's fixed 500 text>, "reference": "<request id>" }`. The `x-request-id` header carries the same id. The default text is "Something went wrong.", the same sentence `./start` uses. Books and discover set their current text through `messages.internal`. The error's own message, fields and stack never reach the response.
3. **If `mapError` throws**, the 500 default applies to the original error.

**The log line.** Each 500 writes one line through `./log`: the app's fixed log text as `msg`, the `requestId`, and the error under `err`. `./log`'s default serialiser removes statement parameters and query text from `pg` and drizzle errors (#142), so the line never carries bound values. The same id appears in the response body, the response header and the log line, so an operator can find the line from a user's report. Whether the line carries the error at all is open question 2. Today's books and discover lines carry only the fixed text.

`./start` uses the same pattern: `Something went wrong. Reference <id>.` in the browser and `Error reference <id>:` on the server. `./start` mints a reference per error. `./api` uses the request id, because an API request has one and `./start`'s server functions do not.

## 3. The reference test

`tests/api.test.mts` ships with the entry. It builds a fixture app on PostgreSQL with `createTenancy` and runs `withWorkspace` as `scope`. The fixture has user A, a member of workspace W1, and user B, a member of W2. Its routes cover:
- a JSON write;
- a read with a query schema;
- a form body;
- a raw body;
- a stream body with `transaction: false`;
- a route with extra path parameters.

**Outsider answers are identical.** User B calls each scoped route with two scope ids: W1, which exists, and a random UUID, which does not. With each scope id, B sends:
1. a valid body and query;
2. a body that fails the schema;
3. malformed JSON;
4. the wrong `content-type`;
5. a declared `Content-Length` above `maxBytes`;
6. an empty body;
7. a refused or invalid query;
8. an invalid extra path parameter.

**Assertions:**
- All 16 answers for a route are identical: the same status, the same body bytes, and the same headers apart from `date` and `x-request-id`.
- The answer is the not-found answer.
- The body stream the test supplies records every read, and **no byte of it is read** for any outsider request.
- The same holds for an anonymous caller, who gets `AUTH_REQUIRED`.
- User A gets each 400, 413 and 415 for the invalid cases, so validation errors are reachable, but only by an authorised caller.

**Mutation proofs:**
- Moving stage 3 before stage 2 in the compiled output fails the test.
- Passing the request to a stage 0 to 2 hook fails the test.
- Removing the pre-check fails the "no byte read" assertion for body routes.

**Type test:** `tests/api.types.mts` uses `@ts-expect-error` to show that `run`'s context has no `request` and no unparsed body.

**`./api/testing` for the apps.** It exports `assertOutsiderAnswers(api, { outsider, member, existing, missing })`. The helper walks the route table and runs the cases above against every scoped route, using each route's declared body mode to build the invalid bodies. Each app runs it in its own test suite, so a newly migrated route is covered with no extra test. Discover's and campaign's scope adapters are checked the same way.

## 4. What each app keeps

| Concern | Books | Discover | Campaign |
|---|---|---|---|
| Authentication | Better Auth session through `authenticate` | Better Auth session, API keys (`parseApiKeyHeaders`, `authenticateApiKey`), board-share, website-share and tracked-share capabilities, all as principal kinds of `authenticate` | Its own session cookie and OIDC, through `authenticate` |
| Scope and roles | `withCompany`, or the runtime tenancy (open question 4); the factor gate as a scope guard | `workspaceAccess`, `projectAccess` and `authorizeApiKey` in its scope adapter | `workspaceAccess` and `projectAccess` in its scope adapter; viewer, admin and instance-operator rules as `access` predicates |
| Rate-limit storage and values | `request_limit`, `limit` and `limitWindow` | `request_limit`, `limit` and `limitWindow`, about 120 call sites | `login_limits` with a 15-minute window; tracking buckets |
| Errors | `mapError` for `FoundationError`, `InputError`, `DatabaseRoleError`, 23505 and the 503 codes; its 500 and log texts | The same, plus `AccountClosureBlocked`, the busy codes with `retry-after`, and the CORS headers on errors | `mapError` for `HttpError`, `IntegrationError` and its module error codes |
| Readiness | `assertSchema` and `assertRoles` inside `ready()` | `assertSchema` and the configuration readability checks | `SELECT 1` and the migration ledger |
| Responses | The default encoder | The default encoder; MCP's JSON-RPC bodies | Its own encoder, security headers and CSP nonce |
| Other | Idempotency-key handling in `runLedger`; Better Auth sign-out pass-through | OpenAPI document (`openapi.ts`); MCP (`mcp.ts`, `mcp-tools.ts`) in the prelude; collector CORS and its origin lookup; SES feedback verification | Webhook signature checks; short links and tracking; the media upload to R2; `Idempotency-Key` in `operation()`; static SPA serving outside `/api` |

## 5. Behaviour changes the apps must accept

Each app gets these on every route it moves. Every other answer must stay the same.

1. **Input after authorisation.** An outsider's request to a scoped route gets the not-found answer, whatever its body and query. A signed-out request to a route that requires a session gets 401 whatever its body. Today some routes answer 400, 413 or 415 first (section 6).
2. **The body is read only after authentication** and, on scoped routes, after authorisation. Unread bodies are cancelled.
3. **405 with `allow`** for every known path with an undeclared method, decided before authentication. Today some routes fall through to 404, or to 401 when the caller is signed out.
4. **`HEAD` and `OPTIONS` are not implied.** An undeclared one gets 405 with `allow`, like any other method. Today they end in 401 or 404 on API routes.
5. **A malformed scope id is not-found**, never 400. Today books' team routes and discover's loose `[0-9a-f-]{36}` id can give 400 for a 36-character non-UUID.
6. **The 500 body gains `reference`.** Every response gains `x-request-id`.
7. **A body on a route that declares none is refused.** Most routes ignore it today (open question 9).
8. **Readiness is memoised.** A per-request `assertSchema` check, as in books and discover today, stops after the first success (open question 11).

## 6. Migration, per app

All three apps run `@ten98/runtime` 0.27.1 today. `./api` needs the 0.29.0 auth migration first, because `withWorkspaces` becomes async there. It also needs `./log` (open question 14). In each app the first step mounts `createApi` with no routes and the whole existing dispatch as the single fallback. That step changes nothing: the request id header is the only difference. Modules then move one at a time, and each move adds the module's routes to the `assertOutsiderAnswers` run.

### 6.1 Books (first: the smallest and most regular)

**Mount.** `src/routes/api/$.ts` calls `api.handle`. The pieces of `api.ts:33-61` map as follows:
- `GET /api/health/live` is a `live` route.
- `assertSchema` and `assertRoles` go into `ready()`.
- The origin gate becomes `origin: { methods: 'unsafe' }`. Public routes stay covered, as today.
- `accountApi` and `sessionApi` become `auth: 'none'` or `'optional'` routes.
- `signedIn` becomes `authenticate`.
- `requireWorkspaceFactor` becomes a scope guard.
- The area chain sits in the fallback until each area moves.

**Area order:**
1. reports, the GET-only routes;
2. masters, vouchers and voucher entry;
3. bills, cost centres, stock masters and currencies;
4. companies;
5. team, after #153;
6. account security and session.

**Routes whose answers change:**
- `GET /api/companies/:id/trial-balance` and `GET /api/companies/:id/ledgers/:lid/balance`. `period(url)` validates `from` and `to` before `runLedger` (`api/vouchers.ts:17-18,29,35`). Under `./api` it is a query schema, checked after the scope.
- `POST /api/companies/:id/setup`. `parseCompany` (`companies.ts:120`) runs before the membership query (125). It moves after the scope.
- **Every ledger write.** `readLedgerBody` runs before `runLedger`:
  - `api/masters.ts:44`
  - `api/vouchers.ts:44`
  - `api/bills.ts:66`
  - `api/cost-centres.ts:45`
  - `api/stock-masters.ts:45`
  - `api/currencies.ts:23`
  - `api/voucher-entry.ts:44`

  It becomes a `json` body read after the pre-check and before the transaction, so posting stays as short as today.
- **Team routes `/api/workspaces/:id/...`.**
  - `readJson` and the strict empty-body parse (`api/team.ts:40-44,58,60-63`) move after the scope.
  - The controller's own order is fixed in the runtime by #153, which also moves its workspace row lock after the membership check.
  - The loose id pattern (`api/team.ts:13`, `api/companies.ts:5`) becomes `uuid`.
- **Account routes.** Account security, preferences and invitation accept parse the body before the session lookup (`account-security.ts:206,247-248,337-338`; `session.ts:52,59`). Under `./api` the optional session comes first. The routes that need a session get 401 for a signed-out bad body.
- **Wrong methods.** Team routes, `GET /api/me`, `/api/session` and `/api/status` move from 404 or 401 to 405 with `allow`. The password-recovery 405s gain `allow`.

**Carried over unchanged:** limits of 8,192, 131,072 and 262,144; `cache-control: no-store`, `nosniff` and the bigint encoding; the CSV exports as `Response`; the idempotency-key replays answering 200.

**Retired:** the local `readJson` (`validation.ts:13-39`) becomes the runtime `readJsonBody`; its texts are open question 8. The `peer` copy in `client-rate-limit.ts:13-19` and the `notAllowed` helpers in each area also go.

### 6.2 Discover (second: the largest)

**Mount.** `collector-alias-middleware.ts` and `src/routes/api/$.ts` call `api.handle`. The chain in `handleApi` (`api.ts:190-1375`) maps as follows:
- `health/live` and `openapi.json` are `live` routes.
- `assertSchema` goes into `ready()`.
- MCP, the collector and CORS block (`api.ts:300-354`), and SES feedback stay in the prelude at first.
- The API-key gate (`api.ts:238-279`) becomes `authenticate` plus a principal-stage guard reading `route.meta`.
- Board, website and tracked shares become capability principals.
- The CSRF check (`api.ts:355`) becomes `origin: { methods: ['POST'], exempt: bearer }`. The repeated checks in `google-api.ts:27`, `oidc.ts:427`, `account-security.ts` and `reports.ts:258` are removed as each module moves.
- `signedIn` and `requireWorkspaceFactor` become `authenticate` and a scope guard.

**Routes whose answers change.** Most of discover's work is here. Many services take raw input and do their own access check after validating it. Moving such a route changes the service signature to `(tx, access, input)` and moves its check into the scope adapter.
- **In `api.ts`:**
  - `POST /api/workspaces/:id/projects` parses at 1251 and checks membership at 1257, after taking the workspace row lock. The lock and the parse both move after the scope.
  - The strict empty-body parse before the controller (1168, 1219, 1220, 1222) applies to `POST /api/workspaces/:id/(api-keys|providers)/:id/(revoke|check)`, `members/:id/remove` and `invitations/:id/(revoke|resend|new-link)`.
  - `/api/projects/:id/destinations*` checks the `environment` query (1127-1128) before any access check.
  - URL-shape 400s come before `projectAccess` at 586, 598, 688, 737, 755, 778, 817, 833 and 1009, plus the analytics export 422 and the board routes at 429, 466 and 472.
- **Routes that read the body in `api.ts` and leave authorisation to a service:** cohorts (533), segments (550), funnels and goals (568), annotations (496), boards (437, 473), website shares (451), domains (1062), prompts (1096), context (1083), retention (1145), management (1157), team (1197-1201), analytics settings (1123), project delete (1108), analytics reset (1116), redirect checks (1052) and tracked assets.
- **Services that validate before their own check:**
  - `cohorts.ts:34,52-55`, `segments.ts:37-40`, `annotations.ts:31,57-59`, `funnels.ts:56-59,176`
  - `domains.ts:134-135`, `prompts.ts:41,63-65`, `rank-tracking.ts:87-89`, `api-keys.ts:83-84`, `providers.ts:65-67`
  - `retention.ts:63`, `destinations.ts:446-448`, `native-analytics.ts:87`, `analytics-export.ts:50`
  - `project-delete.ts:26-27`, `analytics-reset.ts:42-43`, `boards.ts:92-93,245-247`, `website-shares.ts:55-56`
  - `keyword-research.ts:74-75`, `saved-keywords.ts:164-165`, `project-context.ts:186-187`, `analytics.ts:111`, `revenue.ts:55`
- **Account routes.** Account security, preferences, closure and invitation accept read the body before the session (`account-security.ts:246-247,277,333-334,421-422`; `api.ts:364,371`).
- **Capability reads** (`api.ts:215,232`) read the body before verifying the token. Under `./api` the token is verified in `authenticate`.
- **Wrong methods.** Analytics settings (1119-1124), management (1150-1175), team (1187-1241) and workspace projects (1242-1268) move from 404 to 405 with `allow`. The other 405s gain `allow`.

**Carried over unchanged:**
- the 17 body limits, each as an explicit `maxBytes`;
- the post-parse 16,384-byte check on performance observations, kept in `run`;
- the exports, the streamed site-audit CSV, report preview HTML and the 303 redirects as `Response`;
- the share responses' `referrer-policy` and `x-robots-tag`;
- the 25 no-body checks and the three query-refusal patterns, replaced by the body and query modes.

**OpenAPI and MCP.** A test captures `/api/openapi.json` and the MCP tool list before the first move and compares them after each move.

### 6.3 Campaign (third: needs a bridge first)

**Bridge.** Campaign serves plain Node `http` (`index.ts:184`) with one dispatch chain inside a `try`. `./api` handles Fetch `Request`s, so campaign first needs a Node-to-Fetch bridge, which is open question 7. Its pieces map as follows:
- `links.publicHandle`, the three webhooks, unsubscribe and `/api/health` stay in the prelude at first. The health route is `live`, because it runs its own `SELECT 1`.
- The origin check at `index.ts:208` becomes `origin: { methods: 'unsafe' }`, with `origin: false` on the webhooks and unsubscribe when they move.
- `auth.user` becomes `authenticate`.
- The security headers and the CSP nonce (`index.ts:185-190`) stay in campaign's Node wrapper, because the nonce is used only for HTML outside `/api`. The header set is also passed to `headers`.
- Static serving stays outside `./api`.

**Routes whose answers change:**
- **Every mutating `/api` route** except DELETE and the media PUT. The global body read at `index.ts:209` runs before `auth.user` (263) and before `workspaceAccess` and `projectAccess` (354). Anonymous and outsider callers can therefore get 413, 415 or 400 instead of 401 or 404. Examples are `POST /api/projects/:id/posts`, `PATCH /api/projects/:id`, `PATCH /api/workspaces/:id/members/:uid`, `POST /api/workspaces/:id/invitations`, `POST /api/projects/:id/approvals/policy`, `POST /api/projects/:id/integrations/drive/upload` and the collection CRUD routes (`index.ts:433`). Each route gets its own body mode and limit, read after the scope.

  This is the one change campaign could make before `./api`: move the read at line 209 after the 401 gate and the access checks.
- `POST /api/projects` carries its workspace id in the body and validates it (`index.ts:339`) before `workspaceAccess` (open question 6).
- **Trailing slashes and path parameters.** Today they are not stripped (`/api/state/` is a 404). Path parameters are not decoded, except in `activations.ts:28`. Both change.
- **Wrong methods** move from 404 to 405 with `allow`. No 405 sends `allow` today.
- **500s.** Today they have no log line and no reference. They gain both.
- **The media upload** (`PUT /api/projects/:id/integrations/media/uploads/:uuid/content`) becomes a `stream` route with `maxBytes` 5,000,000,000, a 30-minute timeout and `transaction: false`.

**Scope adapter.** Campaign has no row-level tenancy. Its adapter wraps `projectAccess` (`index.ts:179-183`) and `workspaceAccess` (`174-178`) in a transaction and gives one not-found answer, as today. Adopting `createTenancy` is separate work (open question 5).

## 7. Open questions

1. **The 500 body.** Is `{ error, reference }` acceptable, or should the reference go inside the message as `./start` does? Does discover's OpenAPI error schema allow the extra property?
2. **The 500 log line.** Should it carry the error through `./log`'s safe serialiser, or only the fixed text as books and discover log today? Without the error, the reference finds a line that says nothing.
3. **Incoming `x-request-id`.** `./log` accepts any valid incoming id. Should `./api` accept it only from a trusted proxy, under the same trust as `X-Forwarded-For`?
4. **Books' scope.** Books runs `withCompany` on a `pg` `PoolClient`, while the runtime's `withWorkspace` runs on drizzle. Does books pass `withCompany` as its `scope` adapter for now, or move its ledger to the runtime tenancy before migrating?
5. **Discover and campaign have no row-level tenancy.** Are adapters around their current access checks acceptable for the first release, with tenancy adoption tracked separately?
6. **Campaign's `POST /api/projects`** takes its scope from the body. The entry supports scopes from the path only. Options:
   - a signed-in route that calls `scope` itself, which keeps a 400 for a malformed `workspaceId`;
   - adding `POST /api/workspaces/:id/projects` and keeping the old path as an alias.
7. **Campaign's Node bridge.** The options are srvx's Node adapter, pinned exactly as a campaign dependency, or a small bridge in campaign. A third option is moving campaign to Nitro. In every case the bridge must keep backpressure, `request.signal` on disconnect, and the 30-minute upload timeout.
8. **Body refusal texts.** The runtime's `readJsonBody` says "The request body is too large."; books' and discover's `readJson` say "body too large". Do the apps adopt the runtime texts, or map the codes back in `mapError`?
9. **Defaults for bodies and queries.** A body on a route without a body mode is refused, and an undeclared query is ignored. Should both be refused?
10. **`HEAD` and `OPTIONS`.** Should `HEAD` be implied for `GET` routes, and should an undeclared `OPTIONS` answer 204 with `allow` instead of 405?
11. **Memoised readiness.** Books and discover check the schema version on every request today. Memoising it means a migration applied by another process is noticed only after a restart. Is that acceptable?
12. **The pre-check costs one extra membership query** on scoped routes with a body. The alternative is to read the body inside the transaction under a deadline, which lets a slow client hold the transaction and its share lock.
13. **One `PublicError`.** Should `./start`'s `PublicError` move to the root entry, so that `./api`'s `ApiError` and Start server functions share one "this message is public" class?
14. **Release order.** `./api` needs `./log`. The release plan lists `./api` in 0.30.0, and `./log` as its own minor after 0.29.0. `./log` has to ship first.
15. **Architecture rule.** Should the check refuse `request.json()`, `request.text()` and local body readers in an app's API modules once it has adopted `./api`, as the `./start` rule does for `createStart`?
16. **Later work, not in this release:** OpenAPI generation from the route table, and promoting books' and discover's identical `request_limit` storage into the runtime.
