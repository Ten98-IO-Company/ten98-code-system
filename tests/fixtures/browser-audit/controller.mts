import assert from 'node:assert/strict';
import test from 'node:test';
import { createBrowserAuditControl as start, type BrowserControlOptions, type ObserverTransport } from '../../../browser-audit-control.mjs';

type Message = { id: number; method: string; params: Record<string, unknown>; sessionId?: string };
class FakeSocket extends EventTarget {
  static OPEN = 1;
  static CLOSED = 3;
  static instance: FakeSocket;
  static creations = 0;
  readyState = 0;
  sent: Message[] = [];
  lifecycle: string[] = [];
  rejectCommand?: { method: string; sessionId: string };
  holdFetch = false;
  holdFrameTree = false;
  rootFrameId = 'frame-main';
  held: Message[] = [];
  constructor() {
    super(); FakeSocket.instance = this; FakeSocket.creations++;
    queueMicrotask(() => { this.readyState = 1; this.dispatchEvent(new Event('open')); });
  }
  send(value: string) {
    const message = JSON.parse(value) as Message;
    this.sent.push(message);
    this.lifecycle.push(`send:${message.method}`);
    if (this.holdFetch && message.method === 'Fetch.enable') { this.held.push(message); return; }
    if (this.holdFrameTree && message.method === 'Page.getFrameTree') { this.held.push(message); return; }
    queueMicrotask(() => {
      if (message.method === this.rejectCommand?.method && message.sessionId === this.rejectCommand.sessionId) {
        this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify({ id: message.id,
          error: { code: -32000, message: 'SYNTHETIC_GUARD_INITIALIZATION_FAILURE' }, sessionId: message.sessionId }) }));
      } else if (message.method === 'Browser.close') {
        this.reply(message); this.remoteClose();
      } else if (message.method === 'Target.createBrowserContext') this.reply(message, { browserContextId: 'context-test' });
      else if (message.method === 'Target.attachToBrowserTarget') this.reply(message, { sessionId: 'observer-browser' });
      else if (message.method === 'Page.getFrameTree') this.reply(message, { frameTree: { frame: { id: this.rootFrameId } } });
      else if (message.method === 'Target.createTarget') {
        this.event('Target.attachedToTarget', { sessionId: 'guard-main', targetInfo: { targetId: 'main', type: 'page', url: 'about:blank' }, waitingForDebugger: true });
        this.reply(message, { targetId: 'main' });
      } else this.reply(message);
    });
  }
  close() { this.lifecycle.push('socket.close'); this.remoteClose(); }
  remoteClose() {
    if (this.readyState === FakeSocket.CLOSED) return;
    this.readyState = FakeSocket.CLOSED; this.lifecycle.push('socket.closed'); this.dispatchEvent(new Event('close'));
  }
  reply(message: Message, result: Record<string, unknown> = {}) {
    this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify({ id: message.id, result, sessionId: message.sessionId }) }));
  }
  event(method: string, params: Record<string, unknown>, sessionId?: string) {
    this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify({ method, params, sessionId }) }));
  }
}
const tick = () => new Promise<void>(resolve => setTimeout(resolve, 15));
const baseOptions = (signal: AbortSignal): BrowserControlOptions => ({
  endpoint: 'ws://browser:9223/devtools/browser/11111111-1111-1111-1111-111111111111', signal, origin: 'https://site.example',
  closeCapability: 'a'.repeat(64), proxyOrigin: 'http://worker:3138', proxyToken: 'test-proxy-secret', authorize: async () => ({}), stopEgress: async () => {},
});
async function fixture(run: (controller: Awaited<ReturnType<typeof start>>, socket: FakeSocket, abort: AbortController) => Promise<void>,
  overrides: Partial<BrowserControlOptions> = {}) {
  const native = globalThis.WebSocket;
  const nativeFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    assert.equal(String(url), 'http://browser:9223/control/prepare-close');
    assert.equal(init?.method, 'POST');
    assert.equal((init?.headers as Record<string, string>).Authorization, 'Bearer ' + 'a'.repeat(64));
    FakeSocket.instance.lifecycle.push('prepare-close');
    return new Response('{"prepared":true}', {status:200});
  };
  Object.defineProperty(globalThis, 'WebSocket', { configurable: true, writable: true, value: FakeSocket });
  const abort = new AbortController();
  let controller: Awaited<ReturnType<typeof start>> | undefined;
  try {
    controller = await start({ ...baseOptions(abort.signal), ...overrides });
    await controller.send('Target.createTarget', { url: 'about:blank' });
    await controller.sessionForTarget('main');
    await run(controller, FakeSocket.instance, abort);
  } finally { try { await controller?.close(); } finally { globalThis.fetch = nativeFetch; Object.defineProperty(globalThis, 'WebSocket', { configurable: true, writable: true, value: native }); } }
}
function network(socket: FakeSocket, id: string, url: string, session = 'guard-main', frame: string | undefined = 'frame-main', method = 'GET') {
  socket.event('Network.requestWillBeSent', { requestId: id, request: { url, method }, frameId: frame, timestamp: 1 }, session);
}
function paused(socket: FakeSocket, id: string, url: string, headers: Record<string, string> = {}, resourceType = 'Fetch', method = 'GET') {
  socket.event('Fetch.requestPaused', { requestId: `fetch-${id}`, networkId: id, frameId: 'frame-main', request: { url, method, headers }, resourceType }, 'guard-main');
}
function rpc(transport: ObserverTransport) {
  let id = 0;
  const pending = new Map<number, { resolve(value: Record<string, unknown>): void; reject(error: Error): void }>();
  transport.onmessage = value => {
    const message = JSON.parse(value) as { id?: number; result?: Record<string, unknown>; error?: { message: string } };
    if (message.id === undefined) return;
    const call = pending.get(message.id); if (!call) return;
    pending.delete(message.id);
    if (message.error) call.reject(new Error(message.error.message)); else call.resolve(message.result ?? {});
  };
  return (method: string, params: Record<string, unknown> = {}, sessionId = 'observer-main') => new Promise<Record<string, unknown>>((resolve, reject) => {
    const commandId = ++id; pending.set(commandId, { resolve, reject });
    transport.send(JSON.stringify({ id: commandId, method, params, sessionId }));
  });
}
async function nativeClient(controller: Awaited<ReturnType<typeof start>>, socket: FakeSocket) {
  const transport = await controller.createObserverTransport();
  socket.event('Target.attachedToTarget', { sessionId: 'observer-main', targetInfo: { targetId: 'main', type: 'page' }, waitingForDebugger: true }, 'observer-browser');
  await tick();
  return { transport, call: rpc(transport) };
}
const resourceParams = { frameId: 'frame-main', url: 'https://site.example/robots.txt', options: { disableCache: true, includeCredentials: true } };
function resource(response: Record<string, unknown>) {
  return response.resource as { success: boolean; stream?: string; httpStatusCode?: number; headers?: Record<string, string>; netErrorName?: string };
}
test('one socket routes observer browser commands and response IDs without exposing guard replies', async () => {
  const before = FakeSocket.creations;
  await fixture(async (controller, socket) => {
    const observer = await controller.createObserverTransport();
    const received: Record<string, unknown>[] = [];
    observer.onmessage = value => received.push(JSON.parse(value));
    observer.send(JSON.stringify({ id: 1, method: 'Browser.getVersion' }));
    await controller.send('Browser.getVersion'); await tick();
    assert.equal(FakeSocket.creations - before, 1);
    assert.equal(received.length, 1); assert.equal(received[0]!.id, 1);
    assert.equal(socket.sent.find(item => item.method === 'Browser.getVersion' && item.sessionId)?.sessionId, 'observer-browser');
    assert.equal(new Set(socket.sent.map(item => item.id)).size, socket.sent.length);
  });
});
test('observer attachments and resume wait for a real Fetch acknowledgement', async () => {
  await fixture(async (controller, socket) => {
    const observer = await controller.createObserverTransport();
    const received: Record<string, unknown>[] = [];
    observer.onmessage = value => received.push(JSON.parse(value));
    socket.holdFetch = true;
    socket.event('Target.attachedToTarget', { sessionId: 'guard-popup', targetInfo: { targetId: 'popup', type: 'page' }, waitingForDebugger: true });
    socket.event('Target.attachedToTarget', { sessionId: 'observer-popup', targetInfo: { targetId: 'popup', type: 'page' }, waitingForDebugger: true }, 'observer-browser');
    observer.send(JSON.stringify({ id: 9, method: 'Runtime.runIfWaitingForDebugger', sessionId: 'observer-popup' }));
    await tick();
    assert.equal(received.length, 0);
    assert.equal(socket.sent.filter(item => item.method === 'Runtime.runIfWaitingForDebugger' && item.sessionId !== 'guard-main').length, 0);
    assert.equal(socket.held.length, 1);
    socket.reply(socket.held[0]!); await tick();
    assert(received.some(item => item.method === 'Target.attachedToTarget'));
    assert(socket.sent.some(item => item.method === 'Runtime.runIfWaitingForDebugger' && item.sessionId === 'observer-popup'));
    assert.equal(controller.stats.failure, undefined);
  });
});
for (const [name, command] of [
  ['Fetch ownership', { method: 'Fetch.disable', sessionId: 'observer-main' }],
  ['guard detach', { method: 'Target.detachFromTarget', params: { sessionId: 'guard-main' } }],
  ['unsafe autoattach', { method: 'Target.setAutoAttach', params: { autoAttach: true, flatten: true, waitForDebuggerOnStart: false } }],
] as const) test(`observer cannot bypass ${name}`, async () => {
  await fixture(async (controller, socket) => {
    const observer = await controller.createObserverTransport();
    socket.event('Target.attachedToTarget', { sessionId: 'observer-main', targetInfo: { targetId: 'main', type: 'page' }, waitingForDebugger: true }, 'observer-browser');
    await tick();
    const before = socket.sent.length;
    observer.send(JSON.stringify({ id: 7, ...command })); await tick();
    assert(controller.signal.aborted);
    assert.deepEqual(socket.sent.slice(before).map(item => item.method), ['Browser.close']);
  });
});
test('exact-origin native headers are stripped from redirected external requests', async () => {
  await fixture(async (controller, socket) => {
    network(socket, 'one', 'https://site.example/main'); paused(socket, 'one', 'https://site.example/main'); await tick();
    network(socket, 'two', 'https://asset.example/file'); paused(socket, 'two', 'https://asset.example/file', { 'X-Proof': 'stale', Authorization: 'stale' }); await tick();
    const requests = socket.sent.filter(item => item.method === 'Fetch.continueRequest');
    assert.deepEqual(requests[0]!.params.headers, [{ name: 'X-Proof', value: 'fresh' }]);
    assert.deepEqual(requests[1]!.params.headers, []);
    assert.equal(controller.stats.admissions, 2);
  }, { authorize: async (url): Promise<Record<string, string>> => url.origin === 'https://site.example' ? { 'X-Proof': 'fresh' } : {} });
});
test('authorization finishing after cancellation cannot continue a request', async () => {
  let authorize: (headers: Record<string, string>) => void = () => {};
  await fixture(async (controller, socket, abort) => {
    network(socket, 'one', 'https://site.example/main'); paused(socket, 'one', 'https://site.example/main'); await tick();
    abort.abort(); authorize({ 'X-Proof': 'late' }); await tick();
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 0);
    assert(controller.signal.aborted);
  }, { authorize: () => new Promise(resolve => { authorize = resolve; }) });
});
test('worker admission joins the exact parent, request ID, URL and method for arbitrary URLs', async () => {
  await fixture(async (controller, socket) => {
    socket.event('Target.attachedToTarget', { sessionId: 'guard-worker', targetInfo: { targetId: 'worker', type: 'worker' }, waitingForDebugger: true }, 'guard-main');
    await controller.sessionForTarget('worker');
    const url = 'https://site.example/unrelated-path?x=1';
    paused(socket, 'worker-request', url); await tick();
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 0);
    network(socket, 'worker-request', url, 'guard-worker', undefined); await tick();
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 1);
    assert.equal(controller.stats.failure, undefined);
  });
});
test('detached worker cannot provide an admission identity', async () => {
  await fixture(async (controller, socket) => {
    socket.event('Target.attachedToTarget', { sessionId: 'guard-worker', targetInfo: { targetId: 'worker', type: 'worker' }, waitingForDebugger: true }, 'guard-main');
    await controller.sessionForTarget('worker');
    socket.event('Target.detachedFromTarget', { sessionId: 'guard-worker' }, 'guard-main');
    network(socket, 'stale', 'https://site.example/any', 'guard-worker', undefined); await tick();
    assert(controller.signal.aborted);
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 0);
  });
});
test('non-GET subresource is denied without ending unrelated rendering', async () => {
  await fixture(async (controller, socket) => {
    paused(socket, 'post', 'https://site.example/collect', {}, 'Fetch', 'POST'); await tick();
    assert.equal(controller.stats.denials, 1); assert.equal(controller.signal.aborted, false);
    network(socket, 'get', 'https://site.example/main'); paused(socket, 'get', 'https://site.example/main'); await tick();
    assert.equal(controller.stats.admissions, 1);
  });
});
test('main cross-origin navigation fails and receives no native headers', async () => {
  await fixture(async (controller, socket) => {
    paused(socket, 'redirect', 'https://external.example/', {}, 'Document'); await tick();
    assert.equal(controller.stats.failure, 'MAIN_ORIGIN_CHANGED');
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 0);
  });
});
test('website authentication never receives proxy credentials', async () => {
  await fixture(async (controller, socket) => {
    socket.event('Fetch.authRequired', { requestId: 'auth', authChallenge: { source: 'Server', origin: 'https://site.example', scheme: 'basic', realm: 'audit' } }, 'guard-main'); await tick();
    assert.equal(controller.stats.failure, 'UNEXPECTED_AUTH_CHALLENGE');
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueWithAuth').length, 0);
  });
});
test('unqualified service worker fails before any resume command', async () => {
  await fixture(async (controller, socket) => {
    socket.event('Target.attachedToTarget', { sessionId: 'guard-sw', targetInfo: { targetId: 'sw', type: 'service_worker' }, waitingForDebugger: true }); await tick();
    assert.equal(controller.stats.failure, 'UNQUALIFIED_AUXILIARY_TARGET');
    assert.equal(socket.sent.filter(item => item.method === 'Runtime.runIfWaitingForDebugger' && item.sessionId === 'guard-sw').length, 0);
  });
});
test('only the pinned omnibox browser UI target receives the non-network allowance', async () => {
  await fixture(async (controller, socket) => {
    socket.event('Target.attachedToTarget', { sessionId: 'guard-ui', targetInfo: { targetId: 'ui', type: 'browser_ui', url: 'chrome://omnibox-popup.top-chrome/omnibox_popup_aim.html' }, waitingForDebugger: true });
    await controller.sessionForTarget('ui');
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.enable' && item.sessionId === 'guard-ui').length, 0);
    socket.event('Target.attachedToTarget', { sessionId: 'guard-unknown', targetInfo: { targetId: 'unknown', type: 'browser_ui', url: 'https://site.example/' }, waitingForDebugger: true }); await tick();
    assert.equal(controller.stats.failure, 'UNEXPECTED_BROWSER_UI');
  });
});
test('a pending authorization reserves its network identity against a duplicate pause', async () => {
  let calls = 0;
  let finish: (headers: Record<string, string>) => void = () => {};
  await fixture(async (controller, socket, abort) => {
    network(socket, 'duplicate', 'https://site.example/value');
    paused(socket, 'duplicate', 'https://site.example/value');
    paused(socket, 'duplicate', 'https://site.example/value'); await tick();
    assert.equal(calls, 1);
    finish({}); await tick();
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 0);
    assert.equal(controller.stats.failure, 'REQUEST_CORRELATION_AMBIGUOUS');
    abort.abort(); await tick();
  }, { authorize: () => { calls++; return new Promise(resolve => { finish = resolve; }); } });
});
test('a non-document without Network identity is denied without native authorization or continuation', async () => {
  let authorityCalls = 0;
  await fixture(async (controller, socket) => {
    const observer = await controller.createObserverTransport();
    observer.send(JSON.stringify({ id: 80, method: 'Network.loadNetworkResource', params: { url: 'https://site.example/private?secret=hidden' } }));
    socket.event('Fetch.requestPaused', { requestId: 'protocol-fetch', frameId: 'frame-main', resourceType: 'Other',
      request: { url: 'https://site.example/private?secret=hidden', method: 'GET', headers: { Authorization: 'secret-header' } } }, 'guard-main');
    await tick();
    assert.equal(authorityCalls, 0);
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 0);
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.failRequest').length, 1);
    assert.equal(controller.signal.aborted, false);
    assert.equal(controller.stats.reportIncomplete, true);
    assert.deepEqual(controller.stats.deniedRequests, [{ reason: 'network-identity-unavailable', resourceType: 'Other', method: 'GET', targetType: 'page' }]);
    assert(controller.stats.recentObserverMethods.includes('Network.loadNetworkResource'));
    assert(!JSON.stringify(controller.stats).includes('secret'));
    network(socket, 'ordinary', 'https://site.example/main'); paused(socket, 'ordinary', 'https://site.example/main'); await tick();
    assert.equal(authorityCalls, 1);
    assert.equal(controller.stats.admissions, 1);
  }, { authorize: async () => { authorityCalls++; return {}; } });
});
test('a document without Network identity remains an operation failure after denial', async () => {
  let authorityCalls = 0;
  await fixture(async (controller, socket) => {
    socket.event('Fetch.requestPaused', { requestId: 'document-fetch', frameId: 'frame-main', resourceType: 'Document',
      request: { url: 'https://site.example/', method: 'GET', headers: {} } }, 'guard-main'); await tick();
    assert.equal(authorityCalls, 0);
    assert.equal(controller.stats.failure, 'FETCH_NETWORK_ID_MISSING');
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 0);
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.failRequest').length, 1);
  }, { authorize: async () => { authorityCalls++; return {}; } });
});
test('denial diagnostics and recent observer methods remain bounded', async () => {
  await fixture(async (controller, socket) => {
    const observer = await controller.createObserverTransport();
    for (let index = 0; index < 40; index++) {
      observer.send(JSON.stringify({ id: index + 1, method: 'Browser.getVersion' }));
      socket.event('Fetch.requestPaused', { requestId: `protocol-${index}`, resourceType: 'Other',
        request: { url: 'https://site.example/private', method: 'GET', headers: {} } }, 'guard-main');
    }
    await tick();
    assert.equal(controller.stats.denials, 40);
    assert.equal(controller.stats.deniedRequests.length, 32);
    assert.equal(controller.stats.recentObserverMethods.length, 32);
    assert.equal(controller.stats.failure, undefined);
  });
});
test('Lighthouse protocol resource loader is refused before physical dispatch', async () => {
  let authorityCalls = 0;
  await fixture(async (controller, socket) => {
    const observer = await controller.createObserverTransport();
    const received: Array<{ id?: number; error?: { code: number; message: string } }> = [];
    observer.onmessage = value => received.push(JSON.parse(value));
    observer.send(JSON.stringify({ id: 91, method: 'Network.loadNetworkResource', params: {
      frameId: 'frame-main', url: 'https://site.example/robots.txt', options: { disableCache: true, includeCredentials: true },
    } }));
    await tick();
    assert.equal(socket.sent.filter(item => item.method === 'Network.loadNetworkResource').length, 0);
    assert.equal(authorityCalls, 0);
    assert.deepEqual(received, [{ id: 91, error: { code: -32000, message: 'AUDIT_RESOURCE_LOADER_UNAVAILABLE' } }]);
    assert.equal(controller.stats.protocolDenials, 1);
    assert.equal(controller.stats.reportIncomplete, true);
    assert.deepEqual(controller.stats.deniedCommands, [{ method: 'Network.loadNetworkResource', reason: 'unmediated-resource-loader' }]);
    assert.equal(controller.signal.aborted, false);
  }, { authorize: async () => { authorityCalls++; return {}; } });
});
test('raw render API cannot dispatch the bypassing protocol loader either', async () => {
  await fixture(async (controller, socket) => {
    await assert.rejects(controller.send('Network.loadNetworkResource', { url: 'https://site.example/robots.txt' }, 'guard-main'), /AUDIT_RESOURCE_LOADER_UNAVAILABLE/);
    assert.equal(socket.sent.filter(item => item.method === 'Network.loadNetworkResource').length, 0);
    assert.equal(controller.stats.protocolDenials, 1);
  });
});
test('native reader preserves binary bytes, status and headers using bounded IO reads', async () => {
  const bytes = Uint8Array.from({ length: 65540 }, (_, index) => index % 256);
  const order: string[] = [];
  await fixture(async (controller, socket) => {
    const { call } = await nativeClient(controller, socket);
    const loaded = resource(await call('Network.loadNetworkResource', resourceParams));
    assert.equal(loaded.success, true); assert.equal(loaded.httpStatusCode, 200);
    assert.deepEqual(loaded.headers, { 'content-type': 'application/octet-stream' });
    assert.equal(typeof loaded.stream, 'string');
    assert.deepEqual(order, ['authorize', 'load']);
    const first = await call('IO.read', { handle: loaded.stream });
    const second = await call('IO.read', { handle: loaded.stream });
    assert.equal(first.base64Encoded, true); assert.equal(first.eof, false); assert.equal(second.eof, true);
    assert.deepEqual(Buffer.concat([Buffer.from(first.data as string, 'base64'), Buffer.from(second.data as string, 'base64')]), Buffer.from(bytes));
    const seek = await call('IO.read', { handle: loaded.stream, offset: 2, size: 3 });
    assert.deepEqual(Buffer.from(seek.data as string, 'base64'), Buffer.from([2, 3, 4]));
    assert.equal(socket.sent.filter(item => item.method === 'Network.loadNetworkResource' || item.method === 'IO.read').length, 0);
    assert.equal(controller.stats.nativeResourceReading, 'stateless-authorized-native');
    await call('IO.close', { handle: loaded.stream });
    assert.equal(controller.stats.activeStreams, 0); assert.equal(controller.stats.streamBytes, 0);
  }, { authorize: async () => { order.push('authorize'); return {}; }, loadResource: async () => { order.push('load'); return { status: 200, body: bytes, headers: { 'content-type': 'application/octet-stream' } }; } });
});
test('native reader never runs when authorization fails', async () => {
  let loads = 0;
  await fixture(async (controller, socket) => {
    const { call } = await nativeClient(controller, socket);
    await assert.rejects(call('Network.loadNetworkResource', resourceParams), /REVOKED/);
    assert.equal(loads, 0); assert.equal(controller.signal.aborted, true);
    assert.equal(socket.sent.filter(item => item.method === 'Network.loadNetworkResource').length, 0);
  }, { authorize: async () => { throw new Error('REVOKED'); }, loadResource: async () => { loads++; return { status: 200, body: new Uint8Array() }; } });
});
test('native network failures remain explicit incomplete resource failures without leaking exception data', async () => {
  await fixture(async (controller, socket) => {
    const { call } = await nativeClient(controller, socket);
    assert.deepEqual(resource(await call('Network.loadNetworkResource', resourceParams)), { success: false, netErrorName: 'AUDIT_NATIVE_RESOURCE_FAILED' });
    assert.equal(controller.stats.reportIncomplete, true); assert.equal(controller.signal.aborted, false);
    assert(!JSON.stringify(controller.stats).includes('private-provider-secret'));
  }, { loadResource: async () => { throw new Error('private-provider-secret'); } });
});
test('native HTTP failure preserves its real status and creates no stream', async () => {
  await fixture(async (controller, socket) => {
    const { call } = await nativeClient(controller, socket);
    assert.deepEqual(resource(await call('Network.loadNetworkResource', resourceParams)), { success: false, httpStatusCode: 404, headers: {} });
    assert.equal(controller.stats.activeStreams, 0); assert.equal(controller.stats.reportIncomplete, false);
  }, { loadResource: async () => ({ status: 404, body: Uint8Array.of(1, 2) }) });
});
test('resource frame must belong to the ready observer target before native authorization', async () => {
  let authorizations = 0, loads = 0;
  await fixture(async (controller, socket) => {
    const { call } = await nativeClient(controller, socket);
    await assert.rejects(call('Network.loadNetworkResource', { ...resourceParams, frameId: 'foreign-frame' }), /NATIVE_RESOURCE_FRAME/);
    assert.equal(authorizations, 0); assert.equal(loads, 0);
  }, { authorize: async () => { authorizations++; return {}; }, loadResource: async () => { loads++; return { status: 200, body: new Uint8Array() }; } });
});
test('virtual streams reject foreign sessions and read bounds without touching physical IO', async () => {
  await fixture(async (controller, socket) => {
    const { call } = await nativeClient(controller, socket);
    const loaded = resource(await call('Network.loadNetworkResource', resourceParams));
    socket.event('Target.attachedToTarget', { sessionId: 'observer-other', targetInfo: { targetId: 'main', type: 'page' }, waitingForDebugger: true }, 'observer-browser'); await tick();
    await assert.rejects(call('IO.read', { handle: loaded.stream }, 'observer-other'), /AUDIT_STREAM_NOT_OWNED/);
    for (const args of [{ offset: -1 }, { offset: 4 }, { size: 0 }, { size: 65537 }, { size: 1.5 }]) {
      await assert.rejects(call('IO.read', { handle: loaded.stream, ...args }), /AUDIT_STREAM_READ_BOUNDS/);
    }
    assert.equal(controller.signal.aborted, false);
    await assert.rejects(controller.send('IO.read', { handle: loaded.stream }, 'guard-main'), /AUDIT_STREAM_NOT_OWNED/);
    await call('IO.close', { handle: loaded.stream });
    await assert.rejects(call('IO.read', { handle: loaded.stream }), /AUDIT_STREAM_NOT_OWNED/);
    assert.equal(socket.sent.filter(item => item.method.startsWith('IO.')).length, 0);
  }, { loadResource: async () => ({ status: 200, body: Uint8Array.of(0, 128, 255) }) });
});
test('observer close releases all virtual streams and prevents handle reuse', async () => {
  await fixture(async (controller, socket) => {
    const { transport, call } = await nativeClient(controller, socket);
    const loaded = resource(await call('Network.loadNetworkResource', resourceParams));
    assert.equal(controller.stats.activeStreams, 1);
    transport.close(); await tick();
    assert.equal(controller.stats.activeStreams, 0); assert.equal(controller.stats.streamBytes, 0);
    const next = await nativeClient(controller, socket);
    await assert.rejects(next.call('IO.read', { handle: loaded.stream }), /AUDIT_STREAM_NOT_OWNED/);
    assert.equal(socket.sent.filter(item => item.method.startsWith('IO.')).length, 0);
  }, { loadResource: async () => ({ status: 200, body: Uint8Array.of(1) }) });
});
test('stream count is capped before another native request is dispatched', async () => {
  let loads = 0;
  await fixture(async (controller, socket) => {
    const { call } = await nativeClient(controller, socket);
    for (let index = 0; index < 16; index++) await call('Network.loadNetworkResource', resourceParams);
    await assert.rejects(call('Network.loadNetworkResource', resourceParams), /AUDIT_STREAM_LIMIT/);
    assert.equal(loads, 16); assert.equal(controller.stats.activeStreams, 16);
    assert.equal(controller.stats.reportIncomplete, true);
  }, { loadResource: async () => { loads++; return { status: 200, body: new Uint8Array() }; } });
});
test('total retained native bytes cannot exceed eight MiB', async () => {
  let loads = 0;
  await fixture(async (controller, socket) => {
    const { call } = await nativeClient(controller, socket);
    await call('Network.loadNetworkResource', resourceParams);
    await assert.rejects(call('Network.loadNetworkResource', resourceParams), /AUDIT_STREAM_BYTE_LIMIT/);
    assert.equal(controller.stats.activeStreams, 1); assert.equal(controller.stats.streamBytes, 8 * 1024 * 1024);
  }, { loadResource: async () => ({ status: 200, body: new Uint8Array(++loads === 1 ? 8 * 1024 * 1024 : 1) }) });
});
test('observer close aborts its pending native reader without retaining bytes', async () => {
  let capturedSignal: AbortSignal | undefined;
  let finish: (value: { status: number; body: Uint8Array }) => void = () => {};
  await fixture(async (controller, socket) => {
    const { transport, call } = await nativeClient(controller, socket);
    void call('Network.loadNetworkResource', resourceParams).catch(() => {}); await tick();
    assert(capturedSignal); transport.close();
    assert.equal(capturedSignal.aborted, true);
    finish({ status: 200, body: Uint8Array.of(1) }); await tick();
    assert.equal(controller.stats.activeStreams, 0); assert.equal(controller.stats.pendingResourceLoads, 0);
    assert.equal(controller.signal.aborted, false);
  }, { loadResource: (_url, signal) => { capturedSignal = signal; return new Promise(resolve => { finish = resolve; }); } });
});
test('cross-origin subframe document initially paused on main target is admitted under its exact frame identity', async () => {
  await fixture(async (controller, socket) => {
    const url = 'https://asset.example/frame';
    socket.event('Page.frameAttached', { frameId: 'frame-child', parentFrameId: 'frame-main' }, 'guard-main');
    network(socket, 'subframe', url, 'guard-main', 'frame-child');
    socket.event('Fetch.requestPaused', { requestId: 'fetch-subframe', networkId: 'subframe', frameId: 'frame-child', resourceType: 'Document',
      request: { url, method: 'GET', headers: { 'X-Proof': 'forged' } } }, 'guard-main');
    await tick();
    assert(socket.sent.some(item => item.method === 'Page.getFrameTree' && item.sessionId === 'guard-main'));
    const continued = socket.sent.filter(item => item.method === 'Fetch.continueRequest');
    assert.equal(continued.length, 1); assert.deepEqual(continued[0]!.params.headers, []);
    assert.equal(controller.stats.failure, undefined);
  }, { sensitiveHeaderNames: ['x-proof'] });
});
test('an unavailable initial root frame prevents guard readiness and target resume', async () => {
  await fixture(async (controller, socket) => {
    socket.rootFrameId = '';
    socket.event('Target.attachedToTarget', { sessionId: 'guard-popup', targetInfo: { targetId: 'popup', type: 'page' }, waitingForDebugger: true }); await tick();
    assert.equal(controller.stats.failure, 'ROOT_FRAME_UNAVAILABLE');
    assert(!socket.sent.some(item => item.method === 'Runtime.runIfWaitingForDebugger' && item.sessionId === 'guard-popup'));
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 0);
  });
});
test('root-frame state-changing navigation still aborts after denial', async () => {
  await fixture(async (controller, socket) => {
    paused(socket, 'root-post', 'https://site.example/submit', {}, 'Document', 'POST'); await tick();
    assert.equal(controller.stats.failure, 'MAIN_STATE_CHANGING_NAVIGATION');
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.failRequest').length, 1);
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 0);
  });
});

test('paused main navigation uses its pre-resume root snapshot without another renderer query', async () => {
  await fixture(async (controller, socket) => {
    const rootQuery = socket.sent.findIndex(item => item.method === 'Page.getFrameTree' && item.sessionId === 'guard-main');
    const resumed = socket.sent.findIndex(item => item.method === 'Runtime.runIfWaitingForDebugger' && item.sessionId === 'guard-main');
    assert(rootQuery >= 0 && resumed > rootQuery);
    socket.holdFrameTree = true;
    network(socket, 'main-document', 'https://site.example/');
    paused(socket, 'main-document', 'https://site.example/', {}, 'Document'); await tick();
    assert.equal(socket.held.length, 0);
    assert.equal(socket.sent.filter(item => item.method === 'Fetch.continueRequest').length, 1);
    assert.equal(controller.stats.failure, undefined);
  });
});

test('observer and guard resume wait for the initial authoritative root-frame reply', async () => {
  await fixture(async (controller, socket) => {
    const observer = await controller.createObserverTransport();
    const received: Record<string, unknown>[] = []; observer.onmessage = value => received.push(JSON.parse(value));
    socket.holdFrameTree = true;
    socket.event('Target.attachedToTarget', { sessionId: 'guard-popup', targetInfo: { targetId: 'popup', type: 'page' }, waitingForDebugger: true });
    socket.event('Target.attachedToTarget', { sessionId: 'observer-popup', targetInfo: { targetId: 'popup', type: 'page' }, waitingForDebugger: true }, 'observer-browser');
    await tick();
    assert.equal(received.length, 0);
    assert(!socket.sent.some(item => item.method === 'Runtime.runIfWaitingForDebugger' && item.sessionId === 'guard-popup'));
    assert.equal(socket.held.length, 1);
    socket.reply(socket.held[0]!, { frameTree: { frame: { id: 'frame-popup' } } }); await tick();
    assert.equal(received.length, 1);
    assert(socket.sent.some(item => item.method === 'Runtime.runIfWaitingForDebugger' && item.sessionId === 'guard-popup'));
  });
});

test('an unknown Document frame cannot masquerade as an allowed cross-origin subframe', async () => {
  let authorized = 0;
  await fixture(async (controller, socket) => {
    const url = 'https://external.example/';
    network(socket, 'unknown-frame', url, 'guard-main', 'new-root');
    socket.event('Fetch.requestPaused', { requestId: 'fetch-unknown', networkId: 'unknown-frame', frameId: 'new-root', resourceType: 'Document',
      request: { url, method: 'GET', headers: {} } }, 'guard-main'); await tick();
    assert.equal(controller.stats.failure, 'DOCUMENT_FRAME_UNVERIFIED'); assert.equal(authorized, 0);
    assert(!socket.sent.some(item => item.method === 'Fetch.continueRequest'));
  }, { authorize: async () => { authorized++; return {}; } });
});

test('root-frame navigation preserves its identity and rejects replacement roots', async () => {
  await fixture(async (controller, socket) => {
    socket.event('Page.frameNavigated', { frame: { id: 'frame-main', url: 'https://site.example/' } }, 'guard-main');
    assert.equal(controller.stats.failure, undefined);
    socket.event('Page.frameNavigated', { frame: { id: 'replacement-root', url: 'https://external.example/' } }, 'guard-main');
    assert.equal(controller.stats.failure, 'ROOT_FRAME_CHANGED');
  });
});

test('removed child-frame ancestry cannot be reused by a later Document pause', async () => {
  await fixture(async (controller, socket) => {
    socket.event('Page.frameAttached', { frameId: 'frame-child', parentFrameId: 'frame-main' }, 'guard-main');
    socket.event('Page.frameAttached', { frameId: 'frame-grandchild', parentFrameId: 'frame-child' }, 'guard-main');
    socket.event('Page.frameDetached', { frameId: 'frame-child', reason: 'remove' }, 'guard-main');
    const url = 'https://external.example/';
    socket.event('Fetch.requestPaused', { requestId: 'fetch-removed', networkId: 'removed', frameId: 'frame-grandchild', resourceType: 'Document',
      request: { url, method: 'GET', headers: {} } }, 'guard-main'); await tick();
    assert.equal(controller.stats.failure, 'DOCUMENT_FRAME_UNVERIFIED');
    assert(!socket.sent.some(item => item.method === 'Fetch.continueRequest'));
  });
});

test('guard initialization failure synchronously stops egress before abort, browser close, socket close or detach', async () => {
  let active: Awaited<ReturnType<typeof start>> | undefined;
  let stops = 0;
  let abortedAtStop: boolean | undefined;
  await fixture(async (controller, socket) => {
    active = controller;
    const before = socket.lifecycle.length;
    socket.rejectCommand = { method: 'Fetch.enable', sessionId: 'guard-iframe' };
    socket.event('Target.attachedToTarget', { sessionId: 'guard-iframe', targetInfo: { targetId: 'iframe', type: 'iframe' }, waitingForDebugger: true }, 'guard-main');
    await tick(); await controller.close();
    assert.equal(controller.stats.failure, 'SYNTHETIC_GUARD_INITIALIZATION_FAILURE');
    assert.equal(stops, 1); assert.equal(abortedAtStop, false);
    const events = socket.lifecycle.slice(before);
    const stoppedAt = events.indexOf('egress.stop'); assert(stoppedAt >= 0);
    const shutdown = events.map((event, index) => ({ event, index })).filter(({ event }) =>
      ['send:Browser.close', 'socket.close', 'socket.closed', 'send:Target.detachFromTarget'].includes(event));
    assert(shutdown.length > 0);
    assert(shutdown.every(({ index }) => index > stoppedAt));
    assert(events.indexOf('prepare-close') > stoppedAt);
    assert(events.indexOf('send:Browser.close') > events.indexOf('prepare-close'));
    assert(!socket.sent.some(item => item.method === 'Runtime.runIfWaitingForDebugger' && item.sessionId === 'guard-iframe'));
    assert.equal(socket.readyState, FakeSocket.CLOSED);
  }, { stopEgress: () => {
    stops++; abortedAtStop = active?.signal.aborted; FakeSocket.instance.lifecycle.push('egress.stop');
    return Promise.resolve();
  } });
});

test('slow egress closure holds the physical connection and prevents browser close or detach until resolved', async () => {
  let release: () => void = () => {};
  let stops = 0;
  await fixture(async (controller, socket) => {
    const before = socket.lifecycle.length;
    socket.rejectCommand = { method: 'Fetch.enable', sessionId: 'guard-iframe' };
    socket.event('Target.attachedToTarget', { sessionId: 'guard-iframe', targetInfo: { targetId: 'iframe', type: 'iframe' }, waitingForDebugger: true }, 'guard-main');
    await tick();
    let finished = false;
    const closing = controller.close().then(() => { finished = true; });
    try {
      assert.equal(stops, 1); assert.equal(controller.signal.aborted, true);
      assert.equal(socket.readyState, FakeSocket.OPEN); assert.equal(finished, false);
      assert(!socket.lifecycle.slice(before).some(event => ['send:Browser.close', 'socket.close', 'socket.closed', 'send:Target.detachFromTarget'].includes(event)));
      await tick(); assert.equal(finished, false);
    } finally { release(); await closing; }
    assert.equal(socket.readyState, FakeSocket.CLOSED);
    assert.equal(socket.sent.filter(item => item.method === 'Browser.close').length, 1);
  }, { stopEgress: () => { stops++; return new Promise(resolve => { release = resolve; }); } });
});

test('authorization resolving after guard initialization failure cannot continue the paused request', async () => {
  let resolveAuthority: (headers: Record<string, string>) => void = () => {};
  let calls = 0;
  await fixture(async (controller, socket) => {
    network(socket, 'pending-before-failure', 'https://site.example/resource');
    paused(socket, 'pending-before-failure', 'https://site.example/resource'); await tick();
    assert.equal(calls, 1);
    socket.rejectCommand = { method: 'Fetch.enable', sessionId: 'guard-iframe' };
    socket.event('Target.attachedToTarget', { sessionId: 'guard-iframe', targetInfo: { targetId: 'iframe', type: 'iframe' }, waitingForDebugger: true }, 'guard-main');
    await tick(); assert.equal(controller.signal.aborted, true);
    resolveAuthority({ 'X-Proof': 'late' }); await tick();
    assert.equal(controller.stats.admissions, 0);
    assert(!socket.sent.some(item => item.method === 'Fetch.continueRequest'));
  }, { authorize: () => { calls++; return new Promise(resolve => { resolveAuthority = resolve; }); } });
});

test('parent guard detachment cancels a worker request even when native authorization resolves later', async () => {
  let resolveAuthority: (headers: Record<string, string>) => void = () => {};
  let calls = 0;
  await fixture(async (controller, socket) => {
    socket.event('Target.attachedToTarget', { sessionId: 'guard-worker', targetInfo: { targetId: 'worker', type: 'worker' }, waitingForDebugger: true }, 'guard-main');
    await controller.sessionForTarget('worker');
    const url = 'https://site.example/arbitrary-worker-endpoint';
    network(socket, 'pending-worker', url, 'guard-worker', undefined); paused(socket, 'pending-worker', url); await tick();
    assert.equal(calls, 1);
    socket.event('Target.detachedFromTarget', { sessionId: 'guard-main' });
    await tick(); assert.equal(controller.signal.aborted, true);
    await assert.rejects(controller.sessionForTarget('worker'));
    resolveAuthority({ 'X-Proof': 'late' }); await tick();
    assert.equal(controller.stats.admissions, 0);
    assert(!socket.sent.some(item => item.method === 'Fetch.continueRequest'));
  }, { authorize: () => { calls++; return new Promise(resolve => { resolveAuthority = resolve; }); } });
});

test('iframe Fetch acknowledgment precedes resume without top-level-only download commands', async () => {
  await fixture(async (controller, socket) => {
    await controller.send('Target.createBrowserContext', { disposeOnDetach: true });
    assert(socket.sent.some(item => item.method === 'Browser.setDownloadBehavior' && item.params.behavior === 'deny' && item.params.browserContextId === undefined));
    assert(socket.sent.some(item => item.method === 'Browser.setDownloadBehavior' && item.params.behavior === 'deny' && item.params.browserContextId === 'context-test'));
    socket.holdFetch = true;
    socket.event('Target.attachedToTarget', { sessionId: 'guard-iframe', targetInfo: { targetId: 'iframe', type: 'iframe' }, waitingForDebugger: true }, 'guard-main');
    await tick();
    assert.equal(socket.held.length, 1);
    assert.equal(socket.held[0]!.method, 'Fetch.enable'); assert.equal(socket.held[0]!.sessionId, 'guard-iframe');
    assert(!socket.sent.some(item => item.method === 'Runtime.runIfWaitingForDebugger' && item.sessionId === 'guard-iframe'));
    socket.reply(socket.held[0]!); await controller.sessionForTarget('iframe');
    const commands = socket.sent.filter(item => item.sessionId === 'guard-iframe');
    assert(commands.findIndex(item => item.method === 'Fetch.enable') < commands.findIndex(item => item.method === 'Runtime.runIfWaitingForDebugger'));
    assert(!commands.some(item => item.method === 'Page.setDownloadBehavior'));
    assert.equal(controller.stats.failure, undefined);
  });
});


test('missing close capability is rejected before opening CDP', async () => {
  const before = FakeSocket.creations;
  await assert.rejects(start({ ...baseOptions(new AbortController().signal), closeCapability: '' }), /CLOSE_CAPABILITY_INVALID/);
  assert.equal(FakeSocket.creations, before);
});
test('prepare rejection cannot send Browser.close or clear the original failure', async () => {
  await assert.rejects(fixture(async (controller, socket) => {
    globalThis.fetch = async () => new Response('', {status:403});
    socket.rejectCommand = { method: 'Fetch.enable', sessionId: 'guard-iframe' };
    socket.event('Target.attachedToTarget', { sessionId: 'guard-iframe', targetInfo: { targetId: 'iframe', type: 'iframe' }, waitingForDebugger: true }, 'guard-main');
    await tick();
    await assert.rejects(controller.close(), /CAPSULE_CLOSE_REJECTED/);
    assert.equal(controller.stats.failure, 'SYNTHETIC_GUARD_INITIALIZATION_FAILURE');
    assert(!socket.sent.some(item => item.method === 'Browser.close'));
  }), /CAPSULE_CLOSE_REJECTED/);
});
test('failed egress cleanup prevents close intent and records failure', async () => {
  await assert.rejects(fixture(async (controller, socket) => {
    await assert.rejects(controller.close(), /EGRESS_STOP_FAILED/);
    assert.equal(controller.stats.failure, 'EGRESS_STOP_FAILED');
    assert(!socket.lifecycle.includes('prepare-close'));
    assert(!socket.sent.some(item => item.method === 'Browser.close'));
  }, {stopEgress: async () => {throw new Error('synthetic cleanup failure');}}), /EGRESS_STOP_FAILED/);
});
test('Browser.close waits for prepare acknowledgement after egress closure', async () => {
  await fixture(async (controller, socket) => {
    let release!: () => void;
    globalThis.fetch = async () => { await new Promise<void>(resolve => {release = resolve;}); return new Response('',{status:200}); };
    const closing = controller.close(); await tick();
    assert(controller.stats.trace.some(item => item.event === 'egress-closed'));
    assert(!socket.sent.some(item => item.method === 'Browser.close'));
    assert.equal(socket.readyState, FakeSocket.OPEN);
    release(); await closing;
    assert.equal(socket.sent.filter(item => item.method === 'Browser.close').length, 1);
  });
});


test('physical closure stays true when native readyState regresses after its close event', async () => {
  await fixture(async (controller, socket) => {
    await controller.close();
    assert.equal(controller.stats.socketClosed, true);
    socket.readyState = 2;
    assert.equal(controller.stats.socketClosed, true);
    await controller.close();
    assert.equal(controller.stats.failure, undefined);
  });
});
test('an unsolicited genuine close is remembered before asynchronous egress cleanup', async () => {
  await fixture(async (controller, socket) => {
    let duplicateCloseCalls = 0;
    socket.close = () => { duplicateCloseCalls++; };
    socket.remoteClose();
    socket.readyState = 2;
    await controller.close();
    assert.equal(controller.stats.socketClosed, true);
    assert.equal(controller.stats.failure, 'CDP_SOCKET_CLOSED');
    assert.equal(duplicateCloseCalls, 0);
    assert(!socket.lifecycle.includes('prepare-close'));
    assert(!socket.sent.some(item => item.method === 'Browser.close'));
  });
});
test('a closing readyState without a genuine close event cannot claim physical closure', async () => {
  await fixture(async (controller, socket) => {
    socket.readyState = 2;
    socket.close = () => {};
    let finished = false;
    const closing = controller.close().then(() => {finished = true;});
    await tick();
    assert.equal(controller.stats.socketClosed, false);
    assert.equal(finished, false);
    socket.remoteClose();
    await closing;
    assert.equal(controller.stats.socketClosed, true);
  });
});


test('concurrent observer creation reserves the single observer before attachment', async () => {
  await fixture(async controller => {
    const results = await Promise.allSettled([controller.createObserverTransport(), controller.createObserverTransport()]);
    const accepted = results.filter(result => result.status === 'fulfilled');
    assert.equal(accepted.length, 1, 'exactly one observer may attach');
    const rejected = results.find(result => result.status === 'rejected');
    assert.ok(rejected && rejected.status === 'rejected');
    assert.match(String(rejected.reason), /OBSERVER_LIMIT/);
  });
});
