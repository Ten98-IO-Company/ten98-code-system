import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { createCsrfMiddleware } from '@tanstack/react-start';
import { PublicError, publicErrorMessage, ten98RootErrorOptions, ten98StartOptions } from '@ten98/runtime/start';

const root = fileURLToPath(new URL('../', import.meta.url));
// The markers tests/fixtures/start-app/src/secrets.ts throws with; none may reach a response.
const hidden = ['fixture-hidden-message', '/srv/app/hidden/path', 'fixture-hidden-cause', 'fixture-hidden-field', 'fixture-hidden-digest', 'FixtureHiddenName', 'TypeError', 'AggregateError', 'RangeError'];
const PUBLIC_MESSAGE = 'Your plan has expired.';
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';

interface Server { origin: string; process: ChildProcess; stdout: string; stderr: string }
const servers: Record<string, Server> = {};
let app = '';

// One production build of the fixture, served three times: Start's options with no arguments, with app middleware and
// with a reporter. The copy sits two folders below this package, where the fixture's alias finds the built start.mjs.
before(async () => {
  mkdirSync(join(root, 'work'), { recursive: true });
  app = mkdtempSync(join(root, 'work', 'start-'));
  cpSync(join(root, 'tests', 'fixtures', 'start-app'), app, { recursive: true });
  const build = spawnSync(process.execPath, [join(root, 'node_modules', 'vite', 'bin', 'vite.js'), 'build'], { cwd: app, encoding: 'utf8', timeout: 110_000, windowsHide: true });
  assert.equal(build.status, 0, `fixture build failed: ${build.error?.message ?? ''}${build.stdout}${build.stderr}`);
  for (const mode of ['default', 'middleware', 'reporter']) {
    const child = spawn(process.execPath, [join(app, '.output', 'server', 'index.mjs')], { cwd: app, env: { ...process.env, PORT: '0', HOST: '127.0.0.1', TEN98_FIXTURE_MODE: mode }, windowsHide: true });
    const server: Server = { origin: '', process: child, stdout: '', stderr: '' };
    child.stderr!.on('data', chunk => { server.stderr += chunk; });
    server.origin = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`fixture server did not start: ${server.stdout}${server.stderr}`)), 15_000);
      child.stdout!.on('data', chunk => {
        server.stdout += chunk;
        const listening = /Listening on: (http:\/\/127\.0\.0\.1:\d+)/u.exec(server.stdout);
        if (listening) { clearTimeout(timer); resolve(listening[1]!); }
      });
      child.once('exit', code => { clearTimeout(timer); reject(new Error(`fixture server exited ${code}: ${server.stderr}`)); });
    });
    servers[mode] = server;
  }
});

after(async () => {
  // Windows keeps the build folder locked until each server process has exited.
  await Promise.all(Object.values(servers).map(server => new Promise(resolve => {
    if (server.process.exitCode !== null) return resolve(undefined);
    server.process.once('exit', resolve);
    server.process.kill();
  })));
  if (app) rmSync(app, { recursive: true, force: true, maxRetries: 5 });
});

// The fixture server closes a keep-alive socket after five idle seconds, so a request sent on one just closed is sent
// once more; every request here is safe to repeat.
const send = async (url: string, init: RequestInit): Promise<Response> => {
  try { return await fetch(url, init); }
  catch (error) {
    if ((error as { cause?: { code?: string } }).cause?.code !== 'ECONNRESET') throw error;
    return fetch(url, init);
  }
};
const page = async (mode: string, path: string) => {
  const response = await send(servers[mode]!.origin + path, { redirect: 'manual' });
  return { status: response.status, location: response.headers.get('location'), body: await response.text() };
};
// The server function URLs the fixture renders, by button id.
const functionUrls = async (mode: string): Promise<Record<string, string>> => Object.fromEntries([...(await page(mode, '/server-fn')).body.matchAll(/id="(\w+)" data-url="([^"]+)"/gu)].map(match => [match[1], match[2]]));
const callFunction = async (mode: string, name: string, headers: Record<string, string>, method = 'POST') => {
  const response = await send(servers[mode]!.origin + (await functionUrls(mode))[name], { method, headers: { 'x-tsr-serverFn': 'true', ...headers }, redirect: 'manual' });
  return { status: response.status, headers: response.headers, body: await response.text() };
};
const sameOrigin = (mode: string) => ({ Origin: servers[mode]!.origin });
const assertHidden = (body: string, where: string) => {
  for (const marker of hidden) assert.ok(!body.includes(marker), `${where} carries ${marker}`);
  // No stack frame, and nothing serialised by Start's own Error plugin, which keeps the message.
  assert.doesNotMatch(body, /file:\/\/|_ssr\/|\bat (?:Object\.|async |new )|\$TSR\/Error|new Error\(/u, where);
};

// Against an app with no src/start.ts this test fails on the adapter marker in the same-origin answer, not on a 403:
// that app already has Start's own default CSRF. Against a start instance without the shared options it fails on 403.
test('CSRF holds in every configuration: a server-function call not from the same origin answers 403', async () => {
  for (const mode of ['default', 'middleware', 'reporter']) {
    // Another origin or site, by Origin or Sec-Fetch-Site; a request with no origin headers at all; and the same calls
    // to a GET server function and with other methods.
    const calls: [string, string, Record<string, string>][] = [];
    for (const headers of [{ Origin: 'https://elsewhere.example' }, { 'Sec-Fetch-Site': 'cross-site' }, { 'Sec-Fetch-Site': 'same-site' }, {}] as Record<string, string>[]) {
      calls.push(['failing', 'POST', headers], ['reading', 'GET', headers], ['failing', 'PUT', headers]);
    }
    for (const [name, method, headers] of calls) {
      const refused = await callFunction(mode, name, headers, method);
      assert.equal(refused.status, 403, `${mode} ${method} ${name} ${JSON.stringify(headers)}`);
      assert.equal(refused.body, 'Forbidden');
      // The CSRF middleware runs first, so the app's own middleware never sees a refused request.
      assert.equal(refused.headers.get('x-fixture-app-middleware'), null);
    }
    // The same calls from the app's own origin reach the function, and the app's middleware runs after the check.
    const allowed = await callFunction(mode, 'failing', sameOrigin(mode));
    assert.equal(allowed.status, 200, mode);
    assert.match(allowed.body, /"\$TSR\/t\/ten98\/error"/u);
    assert.equal(allowed.headers.get('x-fixture-app-middleware'), mode === 'middleware' ? 'ran' : null);
    const read = await callFunction(mode, 'reading', { 'Sec-Fetch-Site': 'same-origin' }, 'GET');
    assert.equal(read.status, 200, mode);
    assert.match(read.body, /fixture-read/u);
  }
});

test('no part of an error reaches the browser from beforeLoad, a loader, a server function or a cause chain', async () => {
  for (const path of ['/before-load', '/throw-loader', '/detailed', '/server-loader']) {
    const { status, body } = await page('default', path);
    assert.equal(status, 500, path);
    assertHidden(body, path);
    assert.match(body, new RegExp(`ten98/error"\\)\\(\\$R\\[\\d+\\]=\\{reference:"${UUID}"\\}\\)`, 'u'), `${path} carries only a reference`);
  }
  const { body } = await callFunction('default', 'failing', sameOrigin('default'));
  assertHidden(body, 'the server function payload');
  assert.match(body, new RegExp(`"c":"\\$TSR/t/ten98/error"`, 'u'));
  assert.match(body, new RegExp(`\\{"k":\\["reference"\\],"v":\\[\\{"t":1,"s":"${UUID}"\\}\\]\\}`, 'u'));
});

test('a PublicError crosses as its message only, from a loader and from a server function', async () => {
  const route = await page('default', '/public-error');
  assertHidden(route.body, '/public-error');
  assert.match(route.body, /ten98\/error"\)\(\$R\[\d+\]=\{public:"Your plan has expired\."\}\)/u);
  assert.match(route.body, /<p id="public-error" data-public="true">Your plan has expired\.<\/p>/u);
  const call = await callFunction('default', 'public', sameOrigin('default'));
  assertHidden(call.body, 'the PublicError payload');
  assert.match(call.body, /\{"k":\["public"\],"v":\[\{"t":1,"s":"Your plan has expired\."\}\]\}/u);
});

test('an errorComponent showing publicErrorMessage never renders the original message, on the server or after hydration', async () => {
  for (const [path, id] of [['/error-component', 'error-component'], ['/server-loader', 'server-loader']]) {
    const { body } = await page('default', path!);
    assertHidden(body, path!);
    assert.match(body, new RegExp(`<p id="${id}">Something went wrong\\.</p>`, 'u'), path);
  }
  // What the same component shows in the browser, given what the adapter rebuilds there.
  const [adapter] = ten98StartOptions({ reporter: () => {} }).serializationAdapters;
  const original = Object.assign(new TypeError('hidden message'), { reference: 'hidden reference' });
  const rebuilt = adapter.fromSerializable(adapter.toSerializable(original)) as Error & { reference: string };
  assert.equal(publicErrorMessage(rebuilt), `Something went wrong. Reference ${rebuilt.reference}.`);
  assert.equal(publicErrorMessage(original), 'Something went wrong.');
  assert.equal(publicErrorMessage(adapter.fromSerializable(adapter.toSerializable(new PublicError(PUBLIC_MESSAGE)))), PUBLIC_MESSAGE);
  for (const other of [undefined, null, 'hidden', { message: 'hidden', reference: rebuilt.reference }, new Error('hidden')]) assert.equal(publicErrorMessage(other), 'Something went wrong.');
});

test('publicErrorMessage always returns a string, and shows a reference only for an error rebuilt from one', () => {
  const [adapter] = ten98StartOptions({ reporter: () => {} }).serializationAdapters;
  const rebuilt = adapter.fromSerializable(adapter.toSerializable(new Error('hidden'))) as Error & { reference: string };
  const shown = `Something went wrong. Reference ${rebuilt.reference}.`;
  assert.equal(publicErrorMessage(rebuilt), shown);
  // A server original with a reference-shaped field of its own, and a rebuilt error whose field was changed afterwards.
  assert.equal(publicErrorMessage(Object.assign(new Error('hidden'), { reference: crypto.randomUUID() })), 'Something went wrong.');
  rebuilt.reference = crypto.randomUUID();
  assert.equal(publicErrorMessage(rebuilt), shown);
  assert.equal(publicErrorMessage(adapter.fromSerializable({ reference: '<img src=x>' })), 'Something went wrong.');
  // A PublicError whose message is not a string, or cannot be read.
  for (const descriptor of [{ value: 42 }, { value: undefined }, { value: { toString: () => 'hidden' } }, { get: () => { throw new Error('hidden'); } }]) {
    const error = new PublicError(PUBLIC_MESSAGE);
    Object.defineProperty(error, 'message', descriptor);
    assert.equal(publicErrorMessage(error), 'Something went wrong.');
  }
});

test('hydrateTen98Start hydrates the document with StrictMode and StartClient inside startTransition, with the root callbacks', () => {
  // A child process, so node:test's module mocks replace hydrateRoot and wrap startTransition for start.mjs alone.
  const probe = `
    import { mock } from 'node:test';
    const react = await import('react');
    const calls = [], logged = [], reported = [];
    let inTransition = false;
    mock.module('react', { defaultExport: react.default, namedExports: { ...react, startTransition: run => { inTransition = true; try { run(); } finally { inTransition = false; } } } });
    mock.module('react-dom/client', { namedExports: { hydrateRoot: (container, children, options) => { calls.push({ container, children, options, inTransition }); } } });
    globalThis.document = { nodeType: 9 };
    console.error = (...args) => { logged.push(args.length); };
    const { StartClient } = await import('@tanstack/react-start/client');
    const { hydrateTen98Start } = await import('@ten98/runtime/start');
    hydrateTen98Start({ reporter: (error, details) => { reported.push(details.kind); } });
    const [call] = calls, root = call?.children, inner = root?.props?.children;
    for (const name of ['onCaughtError', 'onUncaughtError', 'onRecoverableError']) call?.options?.[name]?.(new Error('render'), { componentStack: 'at Widget' });
    process.stdout.write(JSON.stringify({
      calls: calls.length, document: call?.container === globalThis.document, inTransition: call?.inTransition,
      strictMode: root?.type === react.StrictMode, startClient: inner?.type === StartClient, innerProps: inner && Object.keys(inner.props),
      callbacks: Object.keys(call?.options ?? {}).sort(), logged: logged.length, reported,
    }));`;
  for (const mode of ['production', 'development']) {
    const run = spawnSync(process.execPath, ['--experimental-test-module-mocks', '--no-warnings', '--input-type=module', '-e', probe], { cwd: root, encoding: 'utf8', timeout: 60_000, windowsHide: true, env: { ...process.env, NODE_ENV: mode } });
    assert.equal(run.status, 0, run.stderr);
    assert.deepEqual(JSON.parse(run.stdout), {
      calls: 1, document: true, inTransition: true, strictMode: true, startClient: true, innerProps: [],
      callbacks: ['onCaughtError', 'onRecoverableError', 'onUncaughtError'],
      logged: mode === 'production' ? 0 : 3, reported: ['caught', 'uncaught', 'recoverable'],
    }, mode);
  }
});

test('redirect() and notFound() still work from routes and server functions', async () => {
  for (const path of ['/redirect', '/server-redirect']) {
    const { status, location } = await page('default', path);
    assert.equal(status, 307, path);
    assert.equal(new URL(location!, servers.default!.origin).pathname, '/');
  }
  for (const path of ['/not-found', '/server-not-found']) {
    const { status, body } = await page('default', path);
    assert.equal(status, 404, path);
    assert.match(body, /custom not found/u);
  }
  const redirecting = await callFunction('default', 'redirecting', sameOrigin('default'));
  assert.equal(redirecting.headers.get('location'), '/');
  assert.match(redirecting.body, /"isSerializedRedirect":true/u);
  assert.match((await callFunction('default', 'missing', sameOrigin('default'))).body, /\{"k":\["isNotFound"\]/u);
});

test('the server logs each error once with the reference the browser shows, or hands it to the reporter', async () => {
  const reference = (body: string) => new RegExp(`reference:"(${UUID})"`, 'u').exec(body)?.[1];
  const shown = reference((await page('default', '/throw-loader')).body);
  assert.ok(shown);
  await new Promise(resolve => setTimeout(resolve, 100));
  const lines = servers.default!.stderr.split('\n').filter(line => line.includes(shown));
  assert.deepEqual(lines, [`Error reference ${shown}: Error: fixture-hidden-message /srv/app/hidden/path`]);
  const reported = reference((await page('reporter', '/throw-loader')).body);
  assert.ok(reported);
  await new Promise(resolve => setTimeout(resolve, 100));
  assert.ok(servers.reporter!.stdout.includes(`fixture reporter ${reported} fixture-hidden-message`));
  assert.ok(!servers.reporter!.stderr.includes(reported), 'the reporter replaces the default log line');
});

test('a PublicError subclass with its own name and fields crosses as its message only, and is never logged', () => {
  class PlanExpired extends PublicError { override name = 'PlanExpired'; code = 'hidden'; }
  const reported: unknown[] = [];
  const [adapter] = ten98StartOptions({ reporter: error => { reported.push(error); } }).serializationAdapters;
  const wire = adapter.toSerializable(new PlanExpired(PUBLIC_MESSAGE, { cause: new Error('hidden') }));
  assert.deepEqual(wire, { public: PUBLIC_MESSAGE });
  assert.deepEqual(reported, []);
  const rebuilt = adapter.fromSerializable(wire);
  assert.ok(rebuilt instanceof PublicError);
  assert.equal(rebuilt.name, 'PublicError');
  assert.equal(rebuilt.message, PUBLIC_MESSAGE);
  assert.equal(publicErrorMessage(new PlanExpired(PUBLIC_MESSAGE)), PUBLIC_MESSAGE);
});

// Runs `run` and fails if any promise rejection was left unhandled by the time the event loop turns.
const withoutUnhandledRejections = async (run: () => void | Promise<void>): Promise<void> => {
  const unhandled: unknown[] = [], spy = (reason: unknown) => { unhandled.push(reason); };
  process.on('unhandledRejection', spy);
  try {
    await run();
    await new Promise(resolve => setImmediate(resolve));
  } finally { process.off('unhandledRejection', spy); }
  assert.deepEqual(unhandled, [], 'a failing reporter left an unhandled rejection');
};
const failingReporters = { throwing: () => { throw new Error('reporter down'); }, rejecting: async () => { throw new Error('reporter down'); } };

test('the adapter rebuilds a PublicError and a referenced Error, and logs one line per error object', async () => {
  const [adapter] = ten98StartOptions().serializationAdapters;
  const publicError = adapter.fromSerializable(adapter.toSerializable(new PublicError(PUBLIC_MESSAGE, { cause: new Error('hidden') })));
  assert.ok(publicError instanceof PublicError);
  assert.equal(publicError.message, PUBLIC_MESSAGE);
  assert.equal(publicError.cause, undefined);
  const original = Object.assign(new RangeError('hidden'), { code: 'hidden' });
  const logged: unknown[][] = [], { error } = console;
  console.error = (...args: unknown[]) => { logged.push(args); };
  try {
    const wire = adapter.toSerializable(original);
    assert.deepEqual(adapter.toSerializable(original), wire, 'the same error keeps its reference');
    assert.deepEqual(Object.keys(wire), ['reference']);
    const rebuilt = adapter.fromSerializable(wire) as Error & { reference: string };
    assert.ok(!(rebuilt instanceof PublicError));
    assert.equal(rebuilt.name, 'Error');
    assert.equal(rebuilt.message, `Something went wrong. Reference ${rebuilt.reference}.`);
    assert.match(rebuilt.reference, new RegExp(`^${UUID}$`, 'u'));
    assert.equal(logged.length, 1);
    assert.equal(logged[0]![1], original);
    // A reporter that throws or rejects still leaves the error, with the reference the browser shows, in the server log.
    for (const [name, reporter] of Object.entries(failingReporters)) {
      await withoutUnhandledRejections(async () => {
        const [reporting] = ten98StartOptions({ reporter }).serializationAdapters, failed = new Error(name);
        const { reference } = reporting.toSerializable(failed) as { reference: string };
        await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(logged.at(-1), [`Error reference ${reference}:`, failed], name);
      });
    }
    assert.equal(logged.length, 3);
    // A malformed reference is never shown as given.
    assert.match(adapter.fromSerializable({ reference: '<img src=x>' }).message, /Reference unavailable\./u);
  } finally { console.error = error; }
});

// What a request middleware answers for one request to a server function: a status, or NEXT where it lets the request
// on. Start passes the middleware the request, the handler type and next.
const NEXT = 'next';
const answer = async (middleware: unknown, headers: Record<string, string>, method = 'POST', handlerType = 'serverFn'): Promise<number | string> => {
  const { server } = (middleware as { options: { server: (context: object) => Promise<unknown> } }).options;
  const result = await server({ request: new Request('http://app.test/_serverFn/fn', { method, headers }), handlerType, next: () => NEXT });
  return result instanceof Response ? result.status : result as string;
};
const crossOrigin = { Origin: 'https://elsewhere.example' };

test('the CSRF middleware always comes first, ahead of the app middleware, and no call can change another', async () => {
  const marker = { options: {} } as never;
  const [csrf, ...rest] = ten98StartOptions({ requestMiddleware: [marker] }).requestMiddleware;
  assert.deepEqual(rest, [marker]);
  assert.equal(ten98StartOptions().requestMiddleware.length, 1);
  assert.equal(await answer(csrf, crossOrigin), 403);
  assert.equal(await answer(csrf, { Origin: 'http://app.test' }), NEXT);
  // Turning off the middleware one call returned, in place or by replacing its options, leaves every later call's,
  // the no-argument call's included, refusing a cross-origin request.
  const allow = (context: { next: () => unknown }) => context.next();
  for (const options of [ten98StartOptions(), ten98StartOptions({ requestMiddleware: [marker] })]) {
    const [changed] = options.requestMiddleware as unknown as { options: { server: unknown } }[];
    changed!.options.server = allow;
    assert.equal(await answer(changed, crossOrigin), NEXT);
  }
  Object.assign(ten98StartOptions().requestMiddleware[0], { options: { server: allow } });
  for (const options of [ten98StartOptions(), ten98StartOptions({ requestMiddleware: [marker] })]) {
    assert.equal(await answer(options.requestMiddleware[0], crossOrigin), 403);
  }
});

test('the CSRF middleware refuses every server-function call not proven same-origin, whatever its method', async () => {
  const [csrf] = ten98StartOptions().requestMiddleware;
  const refused: Record<string, string>[] = [crossOrigin, { Origin: 'null' }, { 'Sec-Fetch-Site': 'cross-site' }, { 'Sec-Fetch-Site': 'same-site' }, { 'Sec-Fetch-Site': 'none' },
    { 'Sec-Fetch-Site': 'same-site', Origin: 'http://app.test' }, { Referer: 'https://elsewhere.example/page' }, {}];
  const allowed: Record<string, string>[] = [{ 'Sec-Fetch-Site': 'same-origin' }, { Origin: 'http://app.test' }, { Referer: 'http://app.test/page' }];
  for (const method of ['POST', 'GET', 'PUT', 'PATCH', 'DELETE']) {
    for (const headers of refused) assert.equal(await answer(csrf, headers, method), 403, `${method} ${JSON.stringify(headers)}`);
    for (const headers of allowed) assert.equal(await answer(csrf, headers, method), NEXT, `${method} ${JSON.stringify(headers)}`);
  }
  // Server routes and page requests are outside it, as they are outside Start's own default.
  assert.equal(await answer(csrf, crossOrigin, 'POST', 'router'), NEXT);
});

// Tripwires for a Start upgrade: the shared middleware is Start's own with Start's default options, and
// hydrateTen98Start copies Start's default client entry, so either changing upstream must fail here first.
test("Start's own CSRF default still refuses a request with no origin headers or from the same site", async () => {
  const startDefault = createCsrfMiddleware();
  for (const headers of [{}, { 'Sec-Fetch-Site': 'same-site' }] as Record<string, string>[]) assert.equal(await answer(startDefault, headers), 403, JSON.stringify(headers));
  assert.equal(await answer(startDefault, { 'Sec-Fetch-Site': 'same-origin' }), NEXT);
});

test("Start's default client entry is still the one hydrateTen98Start copies", () => {
  const entry = readFileSync(join(root, 'node_modules', '@tanstack', 'react-start', 'dist', 'plugin', 'default-entry', 'client.tsx'), 'utf8');
  assert.equal(entry.replace(/\s+/gu, ' ').trim(), [
    "import { StrictMode, startTransition } from 'react'",
    "import { hydrateRoot } from 'react-dom/client'",
    "import { StartClient } from '@tanstack/react-start/client'",
    'startTransition(() => { hydrateRoot( document, <StrictMode> <StartClient /> </StrictMode>, ) })',
  ].join(' '));
});

test('React root errors are silent in production apart from the reporter, and logged with the component stack in development', async () => {
  const logged: unknown[][] = [], reported: unknown[][] = [], { error } = console, environment = process.env.NODE_ENV;
  console.error = (...args: unknown[]) => { logged.push(args); };
  const thrown = new Error('render failed'), info = { componentStack: '\n    at Widget' };
  try {
    process.env.NODE_ENV = 'production';
    const production = ten98RootErrorOptions({ reporter: (...args) => { reported.push(args); } });
    production.onCaughtError(thrown, info);
    production.onUncaughtError(thrown, info);
    production.onRecoverableError(thrown, info);
    ten98RootErrorOptions().onUncaughtError(thrown, info);
    assert.deepEqual(logged, []);
    assert.deepEqual(reported.map(([, details]) => details), ['caught', 'uncaught', 'recoverable'].map(kind => ({ kind, componentStack: info.componentStack })));
    // A reporter that throws or rejects adds nothing: no console line in production and no unhandled rejection.
    for (const reporter of Object.values(failingReporters)) await withoutUnhandledRejections(() => ten98RootErrorOptions({ reporter }).onCaughtError(thrown, info));
    assert.deepEqual(logged, []);
    process.env.NODE_ENV = 'development';
    for (const reporter of Object.values(failingReporters)) await withoutUnhandledRejections(() => ten98RootErrorOptions({ reporter }).onCaughtError(thrown, info));
    assert.deepEqual(logged, [['React caught error:', thrown, info.componentStack], ['React caught error:', thrown, info.componentStack]]);
  } finally {
    console.error = error;
    if (environment === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = environment;
  }
});

test('./start is an optional-peer entry, and the root and browser entries load with no node_modules', () => {
  const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const profile = JSON.parse(readFileSync(join(root, 'architecture.json'), 'utf8')).profiles['@ten98/runtime'];
  assert.deepEqual(manifest.exports['./start'], { types: './start.d.mts', import: './start.mjs' });
  for (const [name, version] of Object.entries({ '@tanstack/react-start': '1.168.61', '@tanstack/react-router': '1.170.42', react: '19.2.8', 'react-dom': '19.2.8' })) {
    assert.equal(manifest.peerDependencies[name], version);
    assert.deepEqual(manifest.peerDependenciesMeta[name], { optional: true });
    assert.equal(profile.peerDependencies[name], version);
  }
  // Every built module, in a folder with no node_modules above it.
  const bare = mkdtempSync(join(tmpdir(), 'ten98-bare-'));
  try {
    for (const file of readdirSync(root).filter(file => file.endsWith('.mjs'))) cpSync(join(root, file), join(bare, file));
    writeFileSync(join(bare, 'package.json'), '{"type":"module"}');
    const load = (file: string) => spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(new URL(file, `file:///${bare.replaceAll('\\', '/')}/`).href)});`], { cwd: bare, encoding: 'utf8', timeout: 10_000, windowsHide: true });
    for (const file of ['index.mjs', 'browser.mjs']) assert.equal(load(file).status, 0, `${file}: ${load(file).stderr}`);
    // The same folder refuses ./start, which needs its peers, so the absence of node_modules is real.
    const start = load('start.mjs');
    assert.notEqual(start.status, 0);
    assert.match(start.stderr, /ERR_MODULE_NOT_FOUND/u);
  } finally { rmSync(bare, { recursive: true, force: true }); }
});
