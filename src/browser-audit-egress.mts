import http from 'node:http';
import net from 'node:net';
import { timingSafeEqual } from 'node:crypto';
import { Transform, type Duplex } from 'node:stream';
import {
  addressKey, pinnedNetworkPeer, publicNetworkAddress,
  resolveNetworkHost, type NetworkAddress,
} from './public-network.mjs';
import { normalizePublicHostname } from './public-hostname.mjs';

const limits = Object.freeze({ connections: 32, admissions: 1000, forwardedBytes: 40 * 1024 * 1024,
  headerBytes: 16 * 1024, dialMs: 5000, idleMs: 15000, lifetimeMs: 120000 });
const hopHeaders = new Set(['connection', 'proxy-connection', 'proxy-authorization', 'proxy-authenticate',
  'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

type Target = { url: string; hostname: string; host: string; port: number; path: string };
class ProxyAuthenticationRequired extends Error {}
export type PublicEgressOptions = {
  token: string;
  signal: AbortSignal;
  expiresAt: number;
  authorize?: (targetUrl: string, signal: AbortSignal) => boolean | Promise<boolean>;
};

function targetFor(value: string, tunnel: boolean): Target {
  if (/[\s\u0000-\u001f\u007f\\]/u.test(value)) throw new Error('Blocked');
  const match = tunnel ? /^([^/?#]+)$/.exec(value) : /^http:\/\/([^/?#]+)([^#]*)$/.exec(value);
  if (!match) throw new Error('Blocked');
  const authority = match[1]!;
  const parts = /^(\[[0-9a-fA-F:]+\]|[^:@%\[\]]+)(?::([0-9]+))?$/.exec(authority);
  if (!parts || (tunnel ? parts[2] !== '443' : parts[2] !== undefined && parts[2] !== '80')) {
    throw new Error('Blocked');
  }
  const input = parts[1]!;
  const hostname = input.startsWith('[') ? input.slice(1, -1) : input;
  const key = addressKey(hostname);
  if (key ? !publicNetworkAddress(hostname) || key !== hostname.toLowerCase()
    : normalizePublicHostname(hostname) !== hostname.toLowerCase()) throw new Error('Blocked');
  const host = key && net.isIP(key) === 6 ? `[${key}]` : hostname.toLowerCase();
  const url = new URL(`${tunnel ? 'https' : 'http'}://${host}${tunnel ? '/' : match[2] || '/'}`);
  return { url: url.href, hostname: key || hostname.toLowerCase(), host,
    port: tunnel ? 443 : 80, path: `${url.pathname}${url.search}` };
}

function cleanHeaders(headers: http.IncomingHttpHeaders): http.OutgoingHttpHeaders {
  const removed = new Set(hopHeaders);
  for (const name of (headers.connection || '').split(',')) removed.add(name.trim().toLowerCase());
  const result: http.OutgoingHttpHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!removed.has(name.toLowerCase()) && value !== undefined) result[name] = value;
  }
  return result;
}

function withAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(new Error('Stopped')); };
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    promise.then(value => { signal.removeEventListener('abort', abort); resolve(value); },
      () => { signal.removeEventListener('abort', abort); reject(new Error('Blocked')); });
  });
}

/** Job-local transport only. The caller creates one random 32-byte token and owns native access checks. */
export function createPublicEgressProxy(options: PublicEgressOptions) {
  const token = Buffer.from(options.token, 'base64url');
  if (token.length !== 32 || token.toString('base64url') !== options.token) throw new Error('Invalid token');
  if (!Number.isFinite(options.expiresAt) || options.expiresAt <= Date.now()
    || options.expiresAt - Date.now() > limits.lifetimeMs) throw new Error('Invalid expiry');
  const expected = Buffer.from(`audit:${options.token}`);
  const lifetime = new AbortController();
  const sockets = new Set<net.Socket>();
  let stopped = false;
  let admissions = 0;
  let forwardedBytes = 0;
  let closedRead = 0;
  let closedWritten = 0;
  let closing: Promise<void> | undefined;
  const server = http.createServer({ maxHeaderSize: limits.headerBytes, requestTimeout: limits.idleMs,
    headersTimeout: limits.idleMs, connectionsCheckingInterval: 1000 });
  server.maxHeadersCount = 128;
  server.keepAliveTimeout = limits.idleMs;
  // Unlike native Server.close(), a job shutdown is permanent, including before the first listen.
  const nativeListen = server.listen;
  server.listen = function (...args: unknown[]) {
    if (!usable()) throw new Error('Proxy closed');
    return Reflect.apply(nativeListen, server, args);
  };
  server.on('listening', () => { if (!usable()) server.close(); });
  const stats = Object.freeze({ limits,
    get admissions() { return admissions; },
    get activeConnections() { return sockets.size; },
    get forwardedBytes() { return forwardedBytes; },
    // These include headers and both proxy legs; forwardedBytes counts each proxied payload once.
    get networkBytesRead() { return closedRead + [...sockets].reduce((n, s) => n + s.bytesRead, 0); },
    get networkBytesWritten() { return closedWritten + [...sockets].reduce((n, s) => n + s.bytesWritten, 0); },
    get stopped() { return stopped; },
  });

  function usable() { return !stopped && !options.signal.aborted && Date.now() < options.expiresAt; }
  function close(): Promise<void> {
    if (closing) return closing;
    stopped = true;
    lifetime.abort();
    clearTimeout(expiry);
    options.signal.removeEventListener('abort', stop);
    for (const socket of sockets) socket.destroy();
    closing = new Promise(resolve => { server.close(() => resolve()); });
    return closing;
  }
  const stop = () => { void close(); };
  const expiry = setTimeout(stop, Math.max(1, options.expiresAt - Date.now()));
  expiry.unref();
  options.signal.addEventListener('abort', stop, { once: true });

  function track(socket: net.Socket): boolean {
    socket.on('error', () => {});
    if (!usable() || sockets.size >= limits.connections) { socket.destroy(); return false; }
    sockets.add(socket);
    socket.setTimeout(limits.idleMs, () => socket.destroy());
    socket.once('close', () => {
      closedRead += socket.bytesRead;
      closedWritten += socket.bytesWritten;
      sockets.delete(socket);
    });
    return true;
  }
  server.on('connection', track);

  function authenticated(req: http.IncomingMessage): boolean {
    const raw = req.headers['proxy-authorization'];
    if (typeof raw !== 'string' || !raw.startsWith('Basic ')) return false;
    const encoded = raw.slice(6);
    const credentials = Buffer.from(encoded, 'base64');
    return credentials.toString('base64') === encoded && credentials.length === expected.length
      && timingSafeEqual(credentials, expected);
  }
  function admit(req: http.IncomingMessage, tunnel: boolean): Target {
    if (!usable()) throw new Error('Stopped');
    if (!authenticated(req)) throw new ProxyAuthenticationRequired();
    if (admissions >= limits.admissions
      || req.headers.upgrade !== undefined || req.headers['transfer-encoding'] !== undefined
      || req.headers['content-length'] !== undefined && req.headers['content-length'] !== '0'
      || (!tunnel && req.method !== 'GET' && req.method !== 'HEAD')) throw new Error('Blocked');
    const target = targetFor(req.url || '', tunnel);
    admissions++;
    return target;
  }
  async function pin(target: Target, signal: AbortSignal): Promise<NetworkAddress> {
    const dnsDeadline = new AbortController();
    const timer = setTimeout(() => dnsDeadline.abort(), limits.dialMs);
    const dnsSignal = AbortSignal.any([signal, dnsDeadline.signal]);
    let addresses: NetworkAddress[];
    try { addresses = await withAbort(resolveNetworkHost(target.hostname, dnsSignal), dnsSignal); }
    finally { clearTimeout(timer); }
    if (addresses.length < 1 || addresses.length > 32 || addresses.some(item =>
      !addressKey(item.address) || !publicNetworkAddress(item.address) || net.isIP(item.address) !== item.family)) {
      throw new Error('Blocked');
    }
    if (!usable() || signal.aborted) throw new Error('Stopped');
    if (options.authorize && await withAbort(Promise.resolve().then(() => options.authorize!(target.url, signal)), signal) !== true) {
      throw new Error('Blocked');
    }
    if (!usable() || signal.aborted) throw new Error('Stopped');
    return addresses[0]!;
  }
  function dial(target: Target, pinned: NetworkAddress, signal: AbortSignal): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      if (!usable() || signal.aborted || sockets.size >= limits.connections) { reject(new Error('Stopped')); return; }
      const socket = net.createConnection({ host: pinned.address, port: target.port, family: pinned.family });
      let settled = false;
      const finish = (ok: boolean) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal.removeEventListener('abort', aborted);
        socket.removeListener('error', failed);
        socket.removeListener('close', failed);
        if (ok) resolve(socket);
        else { socket.destroy(); reject(new Error('Connection blocked')); }
      };
      const aborted = () => finish(false);
      const failed = () => finish(false);
      const timer = setTimeout(aborted, limits.dialMs);
      socket.once('error', failed);
      socket.once('close', failed);
      signal.addEventListener('abort', aborted, { once: true });
      if (!track(socket)) { finish(false); return; }
      socket.once('connect', () => finish(usable() && !signal.aborted
        && socket.remotePort === target.port && pinnedNetworkPeer(socket.remoteAddress, pinned.address)));
      if (signal.aborted) finish(false);
    });
  }
  function consume(bytes: number): boolean {
    if (!usable() || forwardedBytes + bytes > limits.forwardedBytes) { stop(); return false; }
    forwardedBytes += bytes;
    return true;
  }
  function meter(): Transform {
    return new Transform({ transform(chunk: Buffer, _encoding, callback) {
      if (consume(chunk.length)) callback(null, chunk);
      else callback(new Error('Stopped'));
    } });
  }
  function rejectSocket(socket: Duplex, error?: unknown) {
    const authentication = error instanceof ProxyAuthenticationRequired;
    const status = authentication ? '407 Proxy Authentication Required' : '403 Forbidden';
    const challenge = authentication ? 'Proxy-Authenticate: Basic realm="audit"\r\n' : '';
    if (!socket.destroyed) socket.end(`HTTP/1.1 ${status}\r\n${challenge}Connection: close\r\nContent-Length: 7\r\n\r\nBlocked`);
  }
  server.on('clientError', (_error, socket) => rejectSocket(socket));
  server.on('upgrade', (_req, socket) => rejectSocket(socket));
  server.on('checkContinue', (_req, res) => { res.writeHead(403, { Connection: 'close' }); res.end('Blocked'); });
  server.on('checkExpectation', (_req, res) => { res.writeHead(403, { Connection: 'close' }); res.end('Blocked'); });

  server.on('request', (req, res) => {
    const ended = new AbortController();
    const signal = AbortSignal.any([lifetime.signal, ended.signal]);
    let upstream: http.ClientRequest | undefined;
    const agent = new http.Agent({ keepAlive: false, maxSockets: 1, maxTotalSockets: 1, proxyEnv: {} });
    const cleanup = () => { ended.abort(); upstream?.destroy(); agent.destroy(); };
    let failed = false;
    const rejectUpstream = () => {
      if (failed) return;
      failed = true;
      cleanup();
      if (!res.headersSent && !res.destroyed) { res.writeHead(502, { Connection: 'close' }); res.end('Unavailable'); }
      else res.destroy();
    };
    res.once('close', cleanup);
    req.once('aborted', cleanup);
    void (async () => {
      const target = admit(req, false);
      const pinned = await pin(target, signal);
      agent.createConnection = (_connectionOptions, callback) => {
        // Node supports callback-only async creation; the installed Agent types require a synchronous return.
        void dial(target, pinned, signal).then(socket => callback!(null, socket),
          () => callback!(new Error('Connection blocked'), undefined as never));
        return undefined as never;
      };
      if (!usable() || signal.aborted) throw new Error('Stopped');
      const headers = cleanHeaders(req.headers);
      headers.host = target.host;
      headers.connection = 'close';
      upstream = http.request({ hostname: target.hostname, port: target.port, path: target.path,
        method: req.method, headers, agent, maxHeaderSize: limits.headerBytes }, response => {
        if (!usable() || signal.aborted) { response.destroy(); return; }
        if (response.statusCode === 101) { response.destroy(); rejectUpstream(); return; }
        const responseHeaders = cleanHeaders(response.headers);
        responseHeaders.connection = 'close';
        res.writeHead(response.statusCode || 502, responseHeaders);
        const body = meter();
        const fail = () => { response.destroy(); body.destroy(); res.destroy(); cleanup(); };
        response.once('aborted', fail);
        response.once('error', fail);
        body.once('error', fail);
        res.once('close', () => { response.destroy(); body.destroy(); });
        response.pipe(body).pipe(res);
      });
      upstream.once('error', rejectUpstream);
      upstream.once('upgrade', (response, socket) => {
        socket.destroy();
        response.destroy();
        rejectUpstream();
      });
      upstream.end();
    })().catch(error => {
      if (!res.headersSent && !res.destroyed) {
        const authentication = error instanceof ProxyAuthenticationRequired;
        res.writeHead(authentication ? 407 : 403, { Connection: 'close',
          ...(authentication ? { 'Proxy-Authenticate': 'Basic realm="audit"' } : {}) });
        res.end('Blocked');
      }
      else res.destroy();
    });
  });
  server.on('connect', (req, client, head) => {
    client.pause();
    const ended = new AbortController();
    const signal = AbortSignal.any([lifetime.signal, ended.signal]);
    client.once('close', () => ended.abort());
    void (async () => {
      const target = admit(req, true);
      const pinned = await pin(target, signal);
      const origin = await dial(target, pinned, signal);
      if (!usable() || signal.aborted) { origin.destroy(); throw new Error('Stopped'); }
      const outgoing = meter();
      const incoming = meter();
      const cleanup = () => { client.destroy(); origin.destroy(); outgoing.destroy(); incoming.destroy(); };
      client.once('close', cleanup);
      origin.once('close', cleanup);
      outgoing.once('error', cleanup);
      incoming.once('error', cleanup);
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length && (!consume(head.length) || !origin.write(head))) {
        if (origin.destroyed) return;
        await withAbort(new Promise<void>(resolve => origin.once('drain', resolve)), signal);
      }
      client.pipe(outgoing).pipe(origin);
      origin.pipe(incoming).pipe(client);
      client.resume();
    })().catch(error => rejectSocket(client, error));
  });
  if (options.signal.aborted) stop();
  return { server, close, stats };
}
