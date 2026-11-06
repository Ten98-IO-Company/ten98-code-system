import { randomUUID } from 'node:crypto';

type Json = Record<string, unknown>;
export interface NativeBrowserResource {
  status: number | null;
  body: Uint8Array | null;
  headers?: Readonly<Record<string, string>>;
}
export interface ObserverTransport {
  onmessage?: (message: string) => void;
  onclose?: () => void;
  send(message: string): void;
  close(): void;
}
export interface BrowserControlOptions {
  endpoint: string;
  signal: AbortSignal;
  closeCapability: string;
  origin: string;
  proxyOrigin: string;
  proxyToken: string;
  /** Must synchronously stop admission and destroy forwarding sockets before returning its closure promise. */
  stopEgress(): Promise<void>;
  authorize(url: URL): Promise<Readonly<Record<string, string>>>;
  maxRequests?: number;
  sensitiveHeaderNames?: readonly string[];
  /** Stateless native reader: caller owns DNS admission, post-DNS authorization and bounded decoding; no browser cookies. */
  loadResource?(url: URL, signal: AbortSignal): Promise<NativeBrowserResource>;
}
type DenialReason = 'network-identity-unavailable' | 'unsupported-url' | 'unsupported-method' | 'main-origin-changed';
const resourceTypes = ['Document', 'Stylesheet', 'Image', 'Media', 'Font', 'Script', 'TextTrack', 'XHR', 'Fetch', 'Prefetch',
  'EventSource', 'WebSocket', 'Manifest', 'SignedExchange', 'Ping', 'CSPViolationReport', 'Preflight', 'Other'] as const;
export interface BrowserRequestDenial {
  reason: DenialReason;
  resourceType: (typeof resourceTypes)[number] | 'Unknown';
  method: 'GET' | 'HEAD' | 'POST' | 'Other';
  targetType: 'page' | 'iframe' | 'worker' | 'other';
}
interface Target {
  id: string; session: string; parent?: string; type: string; ready: boolean; detached: boolean;
  resumed: boolean; inherited?: Target; rootFrameId?: string; frames?: Map<string, string | undefined>;
}
interface NetworkRequest {
  session: string; owner: Target; worker?: Target; id: string; url: string; method: string;
  frame?: string; used: boolean;
}
interface Observer {
  root: string; sessions: Map<string, string>; types: Map<string, string>; transport: ObserverTransport; closed: boolean; abort: AbortController;
}
interface NativeStream { owner: Observer; session: string; bytes: Uint8Array; offset: number }
export interface BrowserControlTrace { at: number; event: string; method?: string; session?: string; targetType?: string; phase?: string; requestId?: string }
const nativeStreamPrefix = 'ten98-audit-stream:';
const maxStreamBytes = 8 * 1024 * 1024;
class ProtocolError extends Error {
  code: number;
  constructor(message: string, code: number) { super(message); this.code = code; }
}
const record = (value: unknown): value is Json => !!value && typeof value === 'object' && !Array.isArray(value);
const text = (value: unknown, max = 8192): value is string => typeof value === 'string' && value.length > 0 && value.length <= max;
function requireValue(value: unknown, code: string): asserts value { if (!value) throw new Error(code); }
function safeUrl(value: string): URL {
  const url = new URL(value);
  requireValue(['http:', 'https:'].includes(url.protocol) && !url.username && !url.password, 'REQUEST_URL_UNSUPPORTED');
  return url;
}

/** The caller owns the isolated capsule, current authority and proxy lifetime. Observers are trusted pinned clients. */
export async function createBrowserAuditControl(options: BrowserControlOptions) {
  const endpoint = new URL(options.endpoint);
  requireValue(['ws:', 'wss:'].includes(endpoint.protocol) && !endpoint.username && !endpoint.password && !endpoint.hash, 'CDP_ENDPOINT');
  requireValue(/^[a-f0-9]{64}$/.test(options.closeCapability ?? ''), 'CLOSE_CAPABILITY_INVALID');
  requireValue(/^\/devtools\/browser\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(endpoint.pathname) && !endpoint.search, 'CLOSE_BROWSER_IDENTITY');
  const origin = safeUrl(options.origin).origin;
  const proxyOrigin = safeUrl(options.proxyOrigin).origin;
  requireValue(options.origin === origin && options.proxyOrigin === proxyOrigin && text(options.proxyToken, 4096), 'CONTROL_OPTIONS');
  const maxRequests = options.maxRequests ?? 100;
  requireValue(Number.isSafeInteger(maxRequests) && maxRequests > 0 && maxRequests <= 10000, 'REQUEST_LIMIT_OPTION');
  requireValue(typeof options.stopEgress==='function','EGRESS_STOP_REQUIRED');
  options.signal.throwIfAborted();
  const socket = new WebSocket(options.endpoint);
  const internal = new AbortController();
  const sessions = new Map<string, Target>();
  const targets = new Map<string, Target>();
  const initializing = new Map<string, Promise<void>>();
  const observers = new Set<Observer>();
  let observerAttaching = false;
  const observerSessions = new Map<string, Observer>();
  const network: NetworkRequest[] = [];
  const auth = new Set<string>();
  const deniedRequests: BrowserRequestDenial[] = [];
  const deniedCommands: Array<{ method: 'Network.loadNetworkResource'; reason: 'unmediated-resource-loader' }> = [];
  const recentObserverMethods: string[] = [];
  const streams = new Map<string, NativeStream>();
  let streamBytes = 0;
  let pendingResourceLoads = 0;
  const sensitive = new Set(['authorization', 'proxy-authorization', ...(options.sensitiveHeaderNames ?? []).map(name => name.toLowerCase())]);
  const pending = new Map<number, { method:string;sessionId?:string;resolve(value: Json): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }>();
  let nextId = 0;
  let receivedBytes = 0;
  let closed = false;
  let physicalClosed = false;
  let closePromise: Promise<void> | undefined;
  let egressStop:Promise<void>|undefined;
  let mainTargetId: string | undefined;
  let failure: Error | undefined;
  let reportIncomplete = false;
  const counts = { physicalConnections: 1, requests: 0, admissions: 0, denials: 0, protocolDenials: 0, proxyChallenges: 0, commands: 0,
    nativeResourceRequests: 0, nativeResourceBytes: 0 };
  const traceStart=performance.now(),trace:BrowserControlTrace[]=[];
  function mark(event:string,session?:string,method?:string,phase?:string,requestId?:string){
    const target=session?sessions.get(session):undefined;
    trace.push({at:Math.round((performance.now()-traceStart)*1000)/1000,event,...(session?{session,targetType:target?.type??'observer'}:{}),...(method?{method}:{}),phase:phase??(closed?'shutdown':target&&!target.ready?'initializing':'active'),...(requestId?{requestId}: {})});
    if(trace.length>512)trace.shift();
  }

  function live() { requireValue(!closed && !internal.signal.aborted, failure?.message ?? 'CONTROLLER_CLOSED'); }
  function stopAdmission(){
    if(egressStop)return egressStop;
    mark('egress-stop');
    try{egressStop=options.stopEgress();}catch{egressStop=Promise.reject(new Error('EGRESS_STOP_FAILED'));}
    void egressStop.catch(()=>{});
    return egressStop;
  }
  function fail(error: unknown) {
    if (closed || failure) return;
    failure = error instanceof Error ? error : new Error('CONTROLLER_FAILURE');
    mark('failure');
    stopAdmission();
    internal.abort(failure);
    void close().catch(() => {});
  }
  function sendPhysical(method: string, params: Json = {}, sessionId?: string): Promise<Json> {
    live();
    // Chromium's protocol loader can bypass a Fetch denial; it must never reach the socket.
    if (method === 'Network.loadNetworkResource') {
      reportIncomplete = true; counts.protocolDenials++;
      deniedCommands.push({ method, reason: 'unmediated-resource-loader' });
      if (deniedCommands.length > 32) deniedCommands.shift();
      throw new ProtocolError('AUDIT_RESOURCE_LOADER_UNAVAILABLE', -32000);
    }
    if (method.startsWith('IO.') && typeof params.handle === 'string' && params.handle.startsWith(nativeStreamPrefix)) {
      throw new ProtocolError('AUDIT_STREAM_NOT_OWNED', -32000);
    }
    requireValue(socket.readyState === WebSocket.OPEN && pending.size < 256 && ++counts.commands <= 20000, 'CDP_COMMAND_LIMIT_OR_CLOSED');
    const id = ++nextId;
    mark('command',sessionId,method);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id);mark('command-error',sessionId,method,'timeout'); const error = new Error(`CDP_TIMEOUT:${method}`); reject(error); fail(error); }, 5000);
      pending.set(id, { method,sessionId,resolve, reject, timer });
      try { socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) })); }
      catch (error) { clearTimeout(timer); pending.delete(id); reject(error instanceof Error ? error : new Error('CDP_SEND')); fail(error); }
    });
  }
  async function waitFor(predicate: () => boolean, code: string, milliseconds = 1500) {
    const deadline = performance.now() + milliseconds;
    while (!predicate()) {
      live(); requireValue(performance.now() < deadline, code);
      await new Promise<void>(resolve => setTimeout(resolve, 5));
    }
    live();
  }
  async function readyTarget(id: string) {
    await waitFor(() => targets.get(id)?.ready === true, 'TARGET_GUARD_NOT_READY', 5000);
    const target = targets.get(id)!;
    requireValue(!target.detached, 'TARGET_GUARD_DETACHED');
    return target;
  }
  async function initialize(target: Target) {
    requireValue(!['service_worker', 'shared_worker'].includes(target.type), 'UNQUALIFIED_AUXILIARY_TARGET');
    await sendPhysical('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, target.session);
    if (['page', 'iframe', 'worker'].includes(target.type)) {
      await sendPhysical('Network.enable', {}, target.session);
      if (target.type === 'worker') {
        const parent = target.parent ? sessions.get(target.parent) : undefined;
        requireValue(parent && ['page', 'iframe'].includes(parent.type), 'WORKER_PARENT_MISSING');
        await initializing.get(parent.session);
        requireValue(parent.ready && !parent.detached, 'WORKER_PARENT_GUARD_UNAVAILABLE');
        target.inherited = parent;
      } else {
        if (target.type === 'page') {
          await sendPhysical('Page.enable', {}, target.session);
          const tree = await sendPhysical('Page.getFrameTree', {}, target.session);
          requireValue(record(tree.frameTree) && record(tree.frameTree.frame) && text(tree.frameTree.frame.id, 256)
            && tree.frameTree.frame.parentId === undefined, 'ROOT_FRAME_UNAVAILABLE');
          target.rootFrameId = tree.frameTree.frame.id;
          target.frames = new Map();
          const remember = (branch: Json, parent?: string): void => {
            requireValue(record(branch.frame) && text(branch.frame.id, 256) && branch.frame.parentId === parent
              && !target.frames!.has(branch.frame.id) && target.frames!.size < 100, 'FRAME_TREE_INVALID');
            target.frames!.set(branch.frame.id, parent);
            if (branch.childFrames !== undefined) {
              requireValue(Array.isArray(branch.childFrames), 'FRAME_TREE_INVALID');
              for (const child of branch.childFrames) { requireValue(record(child), 'FRAME_TREE_INVALID'); remember(child, branch.frame.id); }
            }
          };
          remember(tree.frameTree);
        }
        await sendPhysical('Fetch.enable', { handleAuthRequests: true, patterns: [{ urlPattern: '*', requestStage: 'Request' }] }, target.session);
        mark('guard-ack',target.session,'Fetch.enable');
        if(target.type==='page')await sendPhysical('Page.setDownloadBehavior', { behavior: 'deny' }, target.session);
      }
    } else requireValue(['tab', 'browser', 'browser_ui'].includes(target.type), 'UNSUPPORTED_TARGET');
    live(); target.ready = true;
    mark('ready',target.session);
    if (!['tab', 'browser'].includes(target.type)) {
      target.resumed = true;
      await sendPhysical('Runtime.runIfWaitingForDebugger', {}, target.session);
      mark('resumed',target.session,'Runtime.runIfWaitingForDebugger');
    }
  }
  async function attach(params: Json, parent?: string) {
    requireValue(text(params.sessionId, 256) && record(params.targetInfo) && typeof params.waitingForDebugger === 'boolean', 'TARGET_ATTACHMENT_SHAPE');
    const info = params.targetInfo;
    requireValue(text(info.targetId, 256) && text(info.type, 64), 'TARGET_INFO_SHAPE');
    if (info.type === 'browser_ui') requireValue(typeof info.url === 'string' && /^chrome:\/\/omnibox-popup\.top-chrome(?:[/?#]|$)/.test(info.url), 'UNEXPECTED_BROWSER_UI');
    const session = params.sessionId;
    const observer = parent ? observerSessions.get(parent) : undefined;
    if (observer) {
      requireValue(!observer.closed && observer.sessions.size < 96, 'OBSERVER_SESSION_LIMIT');
      observer.sessions.set(session, info.targetId);
      observer.types.set(session, info.type);
      observerSessions.set(session, observer);
      if (info.type !== 'browser' && info.type !== 'tab') await readyTarget(info.targetId);
      live();
      if (!observer.closed) emit(observer, { method: 'Target.attachedToTarget', params, ...(parent === observer.root ? {} : { sessionId: parent }) });
      return;
    }
    requireValue(sessions.size < 96, 'GUARD_SESSION_LIMIT');
    const existing = targets.get(info.targetId);
    if (existing && !existing.detached) {
      await initializing.get(existing.session);
      requireValue(existing.ready && !existing.detached, 'DUPLICATE_GUARD_NOT_READY');
      if (!['browser', 'tab'].includes(info.type)) await sendPhysical('Runtime.runIfWaitingForDebugger', {}, session);
      await sendPhysical('Target.detachFromTarget', { sessionId: session }, parent);
      return;
    }
    requireValue(targets.size < 24, 'TARGET_LIMIT');
    const target: Target = { id: info.targetId, session, parent, type: info.type, ready: false, detached: false, resumed: false };
    sessions.set(session, target); targets.set(target.id, target);
    mark('bind',session,undefined,parent?'child':'root');
    const promise = initialize(target);
    initializing.set(session, promise);
    await promise;
  }
  function recordFrame(method: string, params: Json, target: Target) {
    if (target.type !== 'page') return;
    // Page.enable may emit initial events before its authoritative frame-tree reply.
    if (!target.rootFrameId || !target.frames) { requireValue(!target.ready, 'ROOT_FRAME_UNAVAILABLE'); return; }
    const frames = target.frames;
    if (method === 'Page.frameDetached') {
      requireValue(text(params.frameId, 256) && ['remove', 'swap'].includes(params.reason as string), 'FRAME_EVENT_SHAPE');
      requireValue(params.frameId !== target.rootFrameId, 'ROOT_FRAME_DETACHED');
      if (params.reason === 'swap') return;
      const removed = new Set([params.frameId]);
      for (let changed = true; changed;) {
        changed = false;
        for (const [id, parent] of frames) if (parent && removed.has(parent) && !removed.has(id)) { removed.add(id); changed = true; }
      }
      for (const id of removed) frames.delete(id);
      return;
    }
    const frame = method === 'Page.frameNavigated' ? params.frame : { id: params.frameId, parentId: params.parentFrameId };
    requireValue(record(frame) && text(frame.id, 256), 'FRAME_EVENT_SHAPE');
    if (frame.id === target.rootFrameId) { requireValue(frame.parentId === undefined, 'ROOT_FRAME_REPARENTED'); return; }
    requireValue(text(frame.parentId, 256), 'ROOT_FRAME_CHANGED');
    requireValue(frames.has(frame.parentId) && (!frames.has(frame.id) || frames.get(frame.id) === frame.parentId)
      && (frames.has(frame.id) || frames.size < 100), 'FRAME_PARENT_UNVERIFIED');
    frames.set(frame.id, frame.parentId);
  }
  function recordNetwork(params: Json, session: string) {
    const target = sessions.get(session);
    requireValue(target && target.ready && !target.detached && target.resumed, 'NETWORK_WITHOUT_GUARD');
    requireValue(text(params.requestId, 256) && record(params.request) && text(params.request.url) && text(params.request.method, 32), 'NETWORK_REQUEST_SHAPE');
    const owner = target.inherited ?? target;
    requireValue(owner.ready && !owner.detached && (!target.inherited || target.parent === owner.session), 'NETWORK_OWNER_INVALID');
    requireValue(network.length < maxRequests * 3, 'NETWORK_RECORD_LIMIT');
    requireValue(!network.some(item => item.session === session && item.id === params.requestId && item.url === (params.request as Json).url && item.method === (params.request as Json).method && !item.used), 'NETWORK_ID_AMBIGUOUS');
    network.push({ session, owner, ...(target.inherited ? { worker: target } : {}), id: params.requestId, url: params.request.url,
      method: params.request.method, frame: text(params.frameId, 256) ? params.frameId : undefined, used: false });
  }
  async function paused(params: Json, session: string) {
    mark('pause',session,undefined,undefined,typeof params.requestId==='string'?params.requestId.slice(0,256):undefined);
    requireValue(++counts.requests <= maxRequests, 'REQUEST_LIMIT');
    const owner = sessions.get(session);
    requireValue(owner?.ready && !owner.detached && !owner.inherited, 'FETCH_OWNER_INVALID');
    requireValue(text(params.requestId, 256) && record(params.request) && text(params.request.url) && text(params.request.method, 32) && record(params.request.headers), 'FETCH_REQUEST_SHAPE');
    const request = params.request;
    const deny = async (reason: DenialReason) => {
      counts.denials++;
      deniedRequests.push({ reason, resourceType: resourceTypes.find(type => type === params.resourceType) ?? 'Unknown',
        method: request.method === 'GET' || request.method === 'HEAD' || request.method === 'POST' ? request.method : 'Other',
        targetType: owner.type === 'page' || owner.type === 'iframe' || owner.type === 'worker' ? owner.type : 'other' });
      if (deniedRequests.length > 32) deniedRequests.shift();
      await sendPhysical('Fetch.failRequest', { requestId: params.requestId, errorReason: 'BlockedByClient' }, session);
    };
    let url: URL;
    try { url = safeUrl(request.url as string); } catch { await deny('unsupported-url'); return; }
    let mainNavigation = false;
    if (owner.id === mainTargetId && params.resourceType === 'Document') {
      requireValue(text(params.frameId, 256), 'DOCUMENT_FRAME_MISSING');
      // Never query the renderer while Fetch has navigation paused: that can deadlock.
      requireValue(owner.rootFrameId && owner.frames?.has(params.frameId), 'DOCUMENT_FRAME_UNVERIFIED');
      mainNavigation = params.frameId === owner.rootFrameId;
    }
    if (!['GET', 'HEAD'].includes(request.method as string) || request.hasPostData === true || request.postData !== undefined) {
      await deny('unsupported-method');
      requireValue(!mainNavigation, 'MAIN_STATE_CHANGING_NAVIGATION');
      return;
    }
    if (mainNavigation && url.origin !== origin) {
      await deny('main-origin-changed'); throw new Error('MAIN_ORIGIN_CHANGED');
    }
    if (!text(params.networkId, 256)) {
      // Protocol-created resources may lack Network identity. Deny them without inventing a correlation.
      reportIncomplete = true;
      await deny('network-identity-unavailable');
      requireValue(params.resourceType !== 'Document', 'FETCH_NETWORK_ID_MISSING');
      return;
    }
    const matches = () => network.filter(item => !item.used && item.owner === owner && item.id === params.networkId && item.url === request.url && item.method === request.method
      && (item.worker !== undefined || text(params.frameId, 256) && item.frame === params.frameId));
    // The Fetch request remains paused until its actual page/worker Network identity is observed.
    await waitFor(() => matches().length > 0, 'REQUEST_CORRELATION_MISSING');
    const candidates = matches();
    const workerMatches = candidates.filter(item => item.worker !== undefined);
    const match = workerMatches.length ? workerMatches : candidates;
    requireValue(match.length === 1, 'REQUEST_CORRELATION_AMBIGUOUS');
    const identity = match[0]!;
    requireValue(identity.owner === owner && !owner.detached && owner.ready && (!identity.worker || identity.worker.inherited === owner && identity.worker.parent === session && identity.worker.ready && identity.worker.resumed && !identity.worker.detached), 'REQUEST_CORRELATION_OWNER_CHANGED');
    // Reserve before awaiting native authority so two pauses cannot consume the same identity.
    identity.used = true;
    mark('authorize-start',session,undefined,undefined,params.requestId as string);
    const authorized = await options.authorize(url);
    mark('authorize-finish',session,undefined,undefined,params.requestId as string);
    live();
    requireValue(record(authorized) && Object.keys(authorized).length <= 64 && (url.origin === origin || Object.keys(authorized).length === 0), 'AUTHORIZATION_HEADER_SCOPE');
    for (const [name, value] of Object.entries(authorized)) {
      requireValue(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) && text(value, 16384) && !/[\r\n\0]/.test(value)
        && !['proxy-authorization', 'host', 'connection', 'content-length', 'transfer-encoding'].includes(name.toLowerCase()), 'AUTHORIZATION_HEADER_INVALID');
      sensitive.add(name.toLowerCase());
    }
    const headers: Array<{ name: string; value: string }> = [];
    for (const [name, value] of Object.entries(request.headers as Json)) {
      requireValue(text(value, 16384) && !/[\r\n\0]/.test(value), 'REQUEST_HEADER_INVALID');
      if (!sensitive.has(name.toLowerCase())) headers.push({ name, value });
    }
    for (const [name, value] of Object.entries(authorized)) headers.push({ name, value });
    requireValue(!owner.detached && (!identity.worker || !identity.worker.detached), 'AUTHORIZATION_OWNER_CHANGED');
    counts.admissions++;
    mark('continue',session,'Fetch.continueRequest',undefined,params.requestId as string);
    await sendPhysical('Fetch.continueRequest', { requestId: params.requestId, headers }, session);
  }
  async function authenticate(params: Json, session: string) {
    const owner = sessions.get(session);
    requireValue(owner?.ready && !owner.detached && text(params.requestId, 256) && record(params.authChallenge), 'AUTH_CHALLENGE_SHAPE');
    const challenge = params.authChallenge;
    const key = `${session}:${params.requestId}`;
    requireValue(challenge.source === 'Proxy' && challenge.origin === proxyOrigin && typeof challenge.scheme === 'string' && challenge.scheme.toLowerCase() === 'basic'
      && challenge.realm === 'audit' && !auth.has(key) && auth.size < maxRequests, 'UNEXPECTED_AUTH_CHALLENGE');
    auth.add(key); counts.proxyChallenges++;
    await sendPhysical('Fetch.continueWithAuth', { requestId: params.requestId, authChallengeResponse: { response: 'ProvideCredentials', username: 'audit', password: options.proxyToken } }, session);
  }
  function emit(observer: Observer, message: Json) {
    if (!observer.closed) observer.transport.onmessage?.(JSON.stringify(message));
  }
  function releaseStreams(observer: Observer, session?: string) {
    for (const [handle, stream] of streams) {
      if (stream.owner === observer && (session === undefined || stream.session === session)) {
        streamBytes -= stream.bytes.byteLength; streams.delete(handle);
      }
    }
  }
  function nativeIO(observer: Observer, method: string, params: Json, session?: string): Json {
    requireValue(typeof params.handle === 'string', 'NATIVE_STREAM_HANDLE');
    const stream = streams.get(params.handle);
    if (!stream || stream.owner !== observer || stream.session !== session || observer.closed) throw new ProtocolError('AUDIT_STREAM_NOT_OWNED', -32000);
    if (method === 'IO.close') {
      streams.delete(params.handle); streamBytes -= stream.bytes.byteLength; return {};
    }
    if (method !== 'IO.read') throw new ProtocolError('AUDIT_STREAM_COMMAND_UNSUPPORTED', -32000);
    const offset = params.offset ?? stream.offset;
    const size = params.size ?? 65536;
    if (typeof offset !== 'number' || !Number.isSafeInteger(offset) || offset < 0 || offset > stream.bytes.byteLength
      || typeof size !== 'number' || !Number.isSafeInteger(size) || size < 1 || size > 65536) {
      throw new ProtocolError('AUDIT_STREAM_READ_BOUNDS', -32000);
    }
    const end = Math.min(offset + size, stream.bytes.byteLength);
    stream.offset = end;
    return { base64Encoded: true, data: Buffer.from(stream.bytes.subarray(offset, end)).toString('base64'), eof: end === stream.bytes.byteLength };
  }
  async function loadNativeResource(observer: Observer, params: Json, session?: string): Promise<Json> {
    requireValue(options.loadResource && session && observer.sessions.has(session) && ['page', 'iframe'].includes(observer.types.get(session) ?? ''), 'NATIVE_RESOURCE_TARGET');
    requireValue(text(params.url) && text(params.frameId, 256) && record(params.options)
      && typeof params.options.disableCache === 'boolean' && typeof params.options.includeCredentials === 'boolean', 'NATIVE_RESOURCE_ARGUMENTS');
    const target = await readyTarget(observer.sessions.get(session)!);
    const href = safeUrl(params.url).href;
    const frameTree = await sendPhysical('Page.getFrameTree', {}, session);
    requireValue(record(frameTree.frameTree) && record(frameTree.frameTree.frame) && frameTree.frameTree.frame.id === params.frameId, 'NATIVE_RESOURCE_FRAME');
    requireValue(++counts.requests <= maxRequests, 'REQUEST_LIMIT');
    if (streams.size + pendingResourceLoads >= 16) {
      reportIncomplete = true; throw new ProtocolError('AUDIT_STREAM_LIMIT', -32000);
    }
    pendingResourceLoads++;
    try {
      const authorized = await options.authorize(new URL(href));
      live();
      if (observer.closed) throw new ProtocolError('AUDIT_NATIVE_RESOURCE_CANCELLED', -32000);
      requireValue(record(authorized) && Object.keys(authorized).length <= 64 && !target.detached && target.ready, 'NATIVE_RESOURCE_AUTHORITY');
      counts.nativeResourceRequests++;
      const signal = AbortSignal.any([internal.signal, observer.abort.signal]);
      let result: NativeBrowserResource;
      try { result = await options.loadResource(new URL(href), signal); }
      catch {
        live();
        if (observer.closed) throw new ProtocolError('AUDIT_NATIVE_RESOURCE_CANCELLED', -32000);
        signal.throwIfAborted(); reportIncomplete = true;
        return { resource: { success: false, netErrorName: 'AUDIT_NATIVE_RESOURCE_FAILED' } };
      }
      live();
      if (observer.closed) throw new ProtocolError('AUDIT_NATIVE_RESOURCE_CANCELLED', -32000);
      signal.throwIfAborted();
      requireValue(!observer.closed && !target.detached && target.ready && observer.sessions.get(session) === target.id, 'NATIVE_RESOURCE_OWNER_CHANGED');
      requireValue(record(result) && (result.status === null || Number.isInteger(result.status) && result.status >= 100 && result.status <= 599)
        && (result.body === null || result.body instanceof Uint8Array), 'NATIVE_RESOURCE_RESULT');
      const headers = result.headers ?? {};
      requireValue(record(headers) && Object.keys(headers).length <= 128 && Object.entries(headers).every(([name, value]) =>
        /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) && typeof value === 'string' && value.length <= 16384 && !/[\r\n\0]/.test(value))
        && Buffer.byteLength(JSON.stringify(headers)) <= 65536, 'NATIVE_RESOURCE_HEADERS');
      const response = { ...(result.status !== null ? { httpStatusCode: result.status } : {}), headers };
      if (result.status === null || result.status < 200 || result.status > 299 || result.body === null) {
        if (result.status === null || result.status >= 200 && result.status <= 299) reportIncomplete = true;
        return { resource: { success: false, ...response } };
      }
      if (result.body.byteLength > maxStreamBytes || streamBytes + result.body.byteLength > maxStreamBytes) {
        reportIncomplete = true; throw new ProtocolError('AUDIT_STREAM_BYTE_LIMIT', -32000);
      }
      const bytes = Uint8Array.from(result.body);
      const handle = nativeStreamPrefix + randomUUID();
      streams.set(handle, { owner: observer, session, bytes, offset: 0 });
      streamBytes += bytes.byteLength; counts.nativeResourceBytes += bytes.byteLength;
      return { resource: { success: true, ...response, stream: handle } };
    } finally { pendingResourceLoads--; }
  }
  function handleMessage(event: MessageEvent) {
    if(closed)return;
    try {
      requireValue(typeof event.data === 'string' && Buffer.byteLength(event.data) <= 8 * 1024 * 1024, 'CDP_MESSAGE_LIMIT');
      receivedBytes += Buffer.byteLength(event.data);
      requireValue(receivedBytes <= 128 * 1024 * 1024, 'CDP_TOTAL_BYTES_LIMIT');
      const message: unknown = JSON.parse(event.data);
      requireValue(record(message), 'CDP_MESSAGE_SHAPE');
      if (message.id !== undefined) {
        requireValue(typeof message.id === 'number' && Number.isSafeInteger(message.id), 'CDP_REPLY_ID');
        const reply = pending.get(message.id); requireValue(reply, 'CDP_UNKNOWN_REPLY');
        clearTimeout(reply.timer); pending.delete(message.id);
        if (message.error !== undefined) {
          mark('command-error',reply.sessionId,reply.method,'reply');
          requireValue(record(message.error) && text(message.error.message), 'CDP_ERROR_SHAPE');
          reply.reject(new ProtocolError(message.error.message, typeof message.error.code === 'number' ? message.error.code : -32000));
        } else { requireValue(record(message.result), 'CDP_RESULT_SHAPE'); reply.resolve(message.result); }
        return;
      }
      requireValue(text(message.method, 128) && record(message.params) && (message.sessionId === undefined || text(message.sessionId, 256)), 'CDP_EVENT_SHAPE');
      const session = message.sessionId as string | undefined;
      if (message.method === 'Target.attachedToTarget') { void attach(message.params, session).catch(fail); return; }
      if (message.method === 'Target.detachedFromTarget') {
        requireValue(text(message.params.sessionId, 256), 'DETACH_SHAPE');
        const detached = sessions.get(message.params.sessionId);
        if (detached) {
          detached.detached = true;mark('detach',detached.session);
          if(['page','iframe','worker'].includes(detached.type)){fail(new Error('TARGET_GUARD_DETACHED'));return;}
        }
        const observer = observerSessions.get(message.params.sessionId);
        if (observer) { releaseStreams(observer, message.params.sessionId); observer.sessions.delete(message.params.sessionId); observer.types.delete(message.params.sessionId); observerSessions.delete(message.params.sessionId); }
      }
      const observer = session ? observerSessions.get(session) : undefined;
      if (observer) {
        if (!message.method.startsWith('Fetch.')) emit(observer, { ...message, ...(session === observer.root ? { sessionId: undefined } : {}) });
        return;
      }
      if (session && sessions.has(session)) {
        if (['Page.frameAttached', 'Page.frameNavigated', 'Page.frameDetached'].includes(message.method)) recordFrame(message.method, message.params, sessions.get(session)!);
        else if (message.method === 'Network.requestWillBeSent') recordNetwork(message.params, session);
        else if (message.method === 'Fetch.requestPaused') void paused(message.params, session).catch(fail);
        else if (message.method === 'Fetch.authRequired') void authenticate(message.params, session).catch(fail);
        else if (message.method === 'Network.webSocketCreated') throw new Error('WEBSOCKET_FORBIDDEN');
      }
    } catch (error) { fail(error); }
  }
  async function observerCommand(observer: Observer, message: Json) {
    live(); requireValue(!observer.closed && typeof message.id === 'number' && Number.isSafeInteger(message.id) && text(message.method, 128)
      && (message.params === undefined || record(message.params)) && (message.sessionId === undefined || text(message.sessionId, 256)), 'OBSERVER_COMMAND_SHAPE');
    const params = (message.params ?? {}) as Json;
    const session = message.sessionId as string | undefined;
    requireValue(session === undefined || observer.sessions.has(session), 'OBSERVER_SESSION_UNOWNED');
    const method = message.method;
    requireValue(/^[A-Za-z][A-Za-z0-9]*\.[A-Za-z][A-Za-z0-9]*$/.test(method), 'OBSERVER_METHOD_SHAPE');
    recentObserverMethods.push(method);
    if (recentObserverMethods.length > 32) recentObserverMethods.shift();
    requireValue(!method.startsWith('Fetch.') && !['Network.setRequestInterception', 'Network.setExtraHTTPHeaders', 'Network.setCookie', 'Network.setCookies',
      'Browser.close', 'Browser.setDownloadBehavior', 'Page.setDownloadBehavior', 'Target.attachToBrowserTarget', 'Target.autoAttachRelated', 'Target.sendMessageToTarget'].includes(method), 'OBSERVER_COMMAND_FORBIDDEN');
    if (method === 'Target.setAutoAttach') requireValue(params.autoAttach === true && params.waitForDebuggerOnStart === true && params.flatten === true, 'OBSERVER_AUTOATTACH_UNSAFE');
    if (method === 'Runtime.runIfWaitingForDebugger') {
      requireValue(session, 'OBSERVER_RESUME_SESSION');
      if (!['tab', 'browser'].includes(observer.types.get(session) ?? '')) await readyTarget(observer.sessions.get(session)!);
    }
    if (method === 'Target.detachFromTarget') {
      requireValue(text(params.sessionId, 256) && observer.sessions.has(params.sessionId), 'OBSERVER_DETACH_UNOWNED');
      const id = observer.sessions.get(params.sessionId)!;
      if (!['tab', 'browser'].includes(observer.types.get(params.sessionId) ?? '')) await readyTarget(id);
    }
    if (method === 'Target.attachToTarget' || method === 'Target.closeTarget') {
      requireValue(text(params.targetId, 256), 'OBSERVER_TARGET_ID'); await readyTarget(params.targetId);
    }
    if (method === 'Target.createTarget') requireValue(params.url === 'about:blank', 'INITIAL_TARGET_URL');
    const result = method === 'Network.loadNetworkResource' && options.loadResource
      ? await loadNativeResource(observer, params, session)
      : method.startsWith('IO.') && typeof params.handle === 'string' && params.handle.startsWith(nativeStreamPrefix)
        ? nativeIO(observer, method, params, session)
        : await sendPhysical(method, params, session ?? observer.root);
    if (method === 'Target.createBrowserContext') {
      requireValue(text(result.browserContextId, 256), 'BROWSER_CONTEXT_ID');
      await sendPhysical('Browser.setDownloadBehavior', { behavior: 'deny', browserContextId: result.browserContextId });
    }
    emit(observer, { id: message.id, ...(session ? { sessionId: session } : {}), result });
  }
  async function createObserverTransport(): Promise<ObserverTransport> {
    live(); requireValue(!observerAttaching && observers.size === 0, 'OBSERVER_LIMIT');
    // Reserve before awaiting CDP so concurrent callers cannot both attach.
    observerAttaching = true;
    try {
      const result = await sendPhysical('Target.attachToBrowserTarget');
      live();
      requireValue(text(result.sessionId, 256), 'OBSERVER_BROWSER_SESSION');
      const observer: Observer = { root: result.sessionId, sessions: new Map(), types: new Map(), closed: false, abort: new AbortController(), transport: {} as ObserverTransport };
      const transport: ObserverTransport = {
        send(value) {
          try {
            requireValue(typeof value === 'string' && Buffer.byteLength(value) <= 1024 * 1024, 'OBSERVER_MESSAGE_LIMIT');
            const message: unknown = JSON.parse(value); requireValue(record(message), 'OBSERVER_MESSAGE_SHAPE');
            void observerCommand(observer, message).catch(error => {
              emit(observer, { id: message.id, ...(message.sessionId ? { sessionId: message.sessionId } : {}), error: { code: error instanceof ProtocolError ? error.code : -32000, message: error instanceof Error ? error.message : 'OBSERVER_ERROR' } });
              if (!(error instanceof ProtocolError)) fail(error);
            });
          } catch (error) { fail(error); }
        },
        close() {
          if (observer.closed) return;
          observer.closed = true;
          observer.abort.abort(new Error('OBSERVER_CLOSED')); releaseStreams(observer);
          void sendPhysical('Target.detachFromTarget', { sessionId: observer.root }).catch(fail);
          for (const id of observer.sessions.keys()) observerSessions.delete(id);
          observerSessions.delete(observer.root); observers.delete(observer);
          transport.onclose?.();
        },
      };
      observer.transport = transport;
      observers.add(observer); observerSessions.set(observer.root, observer);
      return transport;
    } finally { observerAttaching = false; }
  }
  async function send(method: string, params: Json = {}, sessionId?: string) {
    requireValue(!method.startsWith('Fetch.') && !['Browser.close','Target.setAutoAttach', 'Target.autoAttachRelated', 'Runtime.runIfWaitingForDebugger', 'Target.detachFromTarget', 'Target.attachToTarget', 'Target.attachToBrowserTarget'].includes(method), 'GUARD_COMMAND_RESERVED');
    if (sessionId) { const target = sessions.get(sessionId); requireValue(target?.ready && !target.detached, 'RENDER_SESSION_UNAVAILABLE'); }
    if (method === 'Target.createTarget') requireValue(params.url === 'about:blank', 'INITIAL_TARGET_URL');
    const result = await sendPhysical(method, params, sessionId);
    if (method === 'Target.createBrowserContext') {
      requireValue(text(result.browserContextId, 256), 'BROWSER_CONTEXT_ID');
      await sendPhysical('Browser.setDownloadBehavior', { behavior: 'deny', browserContextId: result.browserContextId });
    }
    if (method === 'Target.createTarget' && !mainTargetId) { requireValue(text(result.targetId, 256), 'MAIN_TARGET_ID'); mainTargetId = result.targetId; }
    return result;
  }
  async function close(): Promise<void> {
    if (closePromise) return closePromise;
    closed = true;
    const stopped=stopAdmission();
    internal.abort(failure ?? new Error('CONTROLLER_CLOSED'));
    options.signal.removeEventListener('abort', onAbort);
    for (const reply of pending.values()) { clearTimeout(reply.timer); reply.reject(failure ?? new Error('CONTROLLER_CLOSED')); }
    pending.clear();
    for (const observer of observers) { observer.closed = true; observer.abort.abort(new Error('CONTROLLER_CLOSED')); observer.transport.onclose?.(); }
    streams.clear(); streamBytes = 0;
    observers.clear(); observerSessions.clear();
    closePromise = (async()=>{
      await new Promise<void>((resolve,reject)=>{
        const timer=setTimeout(()=>reject(new Error('EGRESS_STOP_TIMEOUT')),2000);
        stopped.then(()=>{clearTimeout(timer);mark('egress-closed');resolve();},()=>{clearTimeout(timer);reject(new Error('EGRESS_STOP_FAILED'));});
      });
      if (!physicalClosed && socket.readyState === WebSocket.OPEN) {
        const prepare = new URL('/control/prepare-close', endpoint);
        prepare.protocol = endpoint.protocol === 'wss:' ? 'https:' : 'http:';
        mark('prepare-close');
        const response = await fetch(prepare, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(2000),
          headers: { Authorization: `Bearer ${options.closeCapability}`, 'X-Ten98-Browser-Path': endpoint.pathname } });
        await response.body?.cancel();
        requireValue(response.status === 200, 'CAPSULE_CLOSE_REJECTED');
        requireValue(!physicalClosed && socket.readyState === WebSocket.OPEN, 'CDP_CLOSED_BEFORE_PREPARE');
        mark('close-prepared');
      }
      await new Promise<void>((resolve, reject) => {
      if (physicalClosed) { resolve(); return; }
      const timer = setTimeout(() => reject(new Error('CDP_CLOSE_TIMEOUT')), 5000);
      socket.addEventListener('close', () => { clearTimeout(timer);mark('socket-closed');resolve(); }, { once: true });
      if(socket.readyState===WebSocket.OPEN){
        mark('browser-close',undefined,'Browser.close');
        socket.send(JSON.stringify({id:++nextId,method:'Browser.close',params:{}}));
      }
      mark('socket-close');
      socket.close();
      });
    })().catch(error => {
      failure ??= error instanceof Error ? error : new Error('CLOSE_FAILED');
      throw error;
    });
    return closePromise;
  }
  const onAbort = () => fail(options.signal.reason instanceof Error ? options.signal.reason : new Error('ABORTED'));
  socket.addEventListener('message', handleMessage);
  socket.addEventListener('error', () => fail(new Error('CDP_SOCKET_ERROR')));
  socket.addEventListener('close', () => { physicalClosed = true; if (!closed) fail(new Error('CDP_SOCKET_CLOSED')); });
  options.signal.addEventListener('abort', onAbort, { once: true });
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('CDP_CONNECT_TIMEOUT')), 5000);
      socket.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      internal.signal.addEventListener('abort', () => { clearTimeout(timer); reject(internal.signal.reason); }, { once: true });
    });
    await sendPhysical('Browser.setDownloadBehavior', { behavior: 'deny' });
    await sendPhysical('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
    return { send, createObserverTransport, close, signal: internal.signal,
      sessionForTarget: async (id: string) => (await readyTarget(id)).session,
      get stats() { return { ...counts, mainTargetId, closed, socketClosed: physicalClosed, failure: failure?.message,
        reportIncomplete, deniedRequests: deniedRequests.map(item => ({ ...item })), deniedCommands: deniedCommands.map(item => ({ ...item })),
        recentObserverMethods: [...recentObserverMethods],
        trace:trace.map(item=>({...item})),
        nativeResourceReading: options.loadResource ? 'stateless-authorized-native' : 'unavailable', activeStreams: streams.size, streamBytes, pendingResourceLoads,
        targets: [...targets.values()].map(target => ({ targetId: target.id, sessionId: target.session, type: target.type, ready: target.ready, detached: target.detached })) }; },
    };
  } catch (error) { fail(error); await close(); throw error; }
}
