import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import http from 'node:http';
import net from 'node:net';
import dns from 'node:dns/promises';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createPublicEgressProxy } from '../../../browser-audit-egress.mjs';

const nativeConnect = net.createConnection.bind(net);
const publicIp = '93.184.216.34';
const token = randomBytes(32).toString('base64url');
const authorization = `Basic ${Buffer.from(`audit:${token}`).toString('base64')}`;
const noData = () => Promise.reject(Object.assign(new Error('No data'), { code: 'ENODATA' }));
const pause = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));

async function fixture(t: TestContext, handler?: http.RequestListener) {
  const server = handler ? http.createServer(handler) : net.createServer();
  const sockets = new Set<net.Socket>();
  server.on('connection', socket => { sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => server.close(() => resolve())); });
  return { server, port: address.port, sockets };
}

async function proxy(t: TestContext, overrides: Partial<Parameters<typeof createPublicEgressProxy>[0]> = {}) {
  const controller = new AbortController();
  const value = createPublicEgressProxy({ token, signal: controller.signal, expiresAt: Date.now() + 10000, ...overrides });
  value.server.listen(0, '127.0.0.1');
  await once(value.server, 'listening');
  const address = value.server.address();
  assert.ok(address && typeof address !== 'string');
  t.after(() => value.close());
  return { ...value, controller, port: address.port };
}

function dnsFixture(t: TestContext, answers = [publicIp]) {
  let calls = 0;
  t.mock.method(dns.Resolver.prototype, 'resolve4', async () => { calls++; return answers; });
  t.mock.method(dns.Resolver.prototype, 'resolve6', async () => { calls++; return noData(); });
  return () => calls;
}

function dialFixture(t: TestContext, port: number, peer = publicIp, delayConnectMs = 0) {
  let calls = 0;
  t.mock.method(net, 'createConnection', (options: net.NetConnectOpts) => {
    calls++;
    assert.ok('host' in options && options.host === publicIp, 'the dial must use the admitted literal pin');
    const socket = nativeConnect({ host: '127.0.0.1', port });
    Object.defineProperty(socket, 'remoteAddress', { get: () => peer });
    Object.defineProperty(socket, 'remotePort', { get: () => 'port' in options ? options.port : undefined });
    if (delayConnectMs) {
      const emit = socket.emit.bind(socket);
      socket.emit = (event: string | symbol, ...args: unknown[]) => {
        if (event === 'connect') { setTimeout(() => emit(event, ...args), delayConnectMs); return true; }
        return emit(event, ...args);
      };
    }
    return socket;
  });
  return () => calls;
}

function request(port: number, target = 'http://public.site/path', extra = '', auth = authorization): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = nativeConnect({ host: '127.0.0.1', port });
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('Fixture timeout')); }, 3000);
    socket.on('data', chunk => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('close', () => { clearTimeout(timer); resolve(Buffer.concat(chunks).toString()); });
    socket.on('connect', () => socket.write(`GET ${target} HTTP/1.1\r\nHost: attacker.site\r\n${auth ? `Proxy-Authorization: ${auth}\r\n` : ''}${extra}Connection: close\r\n\r\n`));
  });
}

test('shutdown prevents later listening after pre-aborted construction', async t => {
  const controller = new AbortController();
  controller.abort();
  const p = createPublicEgressProxy({ token, signal: controller.signal, expiresAt: Date.now() + 10000 });
  t.after(async () => {
    await pause(20);
    await new Promise<void>(resolve => p.server.close(() => resolve()));
    await p.close();
  });
  await p.close();
  assert.throws(() => p.server.listen(0, '127.0.0.1'), /closed/i);
  assert.equal(p.server.listening, false);
  assert.equal(p.server.address(), null);
});

test('shutdown prevents later listening after close-before-listen', async t => {
  const p = createPublicEgressProxy({ token, signal: new AbortController().signal, expiresAt: Date.now() + 10000 });
  t.after(async () => {
    await pause(20);
    await new Promise<void>(resolve => p.server.close(() => resolve()));
    await p.close();
  });
  await p.close();
  assert.throws(() => p.server.listen(0, '127.0.0.1'), /closed/i);
  assert.equal(p.server.listening, false);
  assert.equal(p.server.address(), null);
});

test('public egress proxy security boundaries', { timeout: 30000 }, async t => {
  await t.test('invalid options reject before listening', () => {
    const signal = new AbortController().signal;
    assert.throws(() => createPublicEgressProxy({ token: 'bad', signal, expiresAt: Date.now() + 1000 }));
    assert.throws(() => createPublicEgressProxy({ token, signal, expiresAt: Infinity }));
    assert.throws(() => createPublicEgressProxy({ token, signal, expiresAt: Date.now() + 121000 }));
  });

  await t.test('authentication and malformed authorities fail before DNS and dial', async t => {
    const dnsCalls = dnsFixture(t);
    let dials = 0;
    t.mock.method(net, 'createConnection', () => { dials++; throw new Error('Unexpected dial'); });
    const p = await proxy(t);
    const challenge = await request(p.port, undefined, '', '');
    assert.match(challenge, /^HTTP\/1.1 407/);
    assert.match(challenge, /proxy-authenticate: Basic realm="audit"/i);
    assert.match(await request(p.port, undefined, '', `Basic ${Buffer.from('audit:wrong').toString('base64')}`), /^HTTP\/1.1 407/);
    for (const target of ['http://127.1/', 'http://2130706433/', 'http://0x7f000001/', 'http://u:p@public.site/',
      'http://public%2esite/', 'http://public.site:8080/', 'http://localhost/', 'http://public.site\\@evil.site/',
      'http://[::1]/', 'https://public.site/', 'http://public.site:080/', 'http://public.site./']) {
      assert.match(await request(p.port, target), /^HTTP\/1.1 403/, target);
    }
    assert.equal(dnsCalls(), 0);
    assert.equal(dials, 0);
  });

  await t.test('the complete DNS answer set must be public and both families must succeed', async t => {
    const dnsCalls = dnsFixture(t, [publicIp, '127.0.0.1']);
    let dials = 0;
    t.mock.method(net, 'createConnection', () => { dials++; throw new Error('Unexpected dial'); });
    const p = await proxy(t);
    assert.match(await request(p.port), /^HTTP\/1.1 403/);
    assert.equal(dnsCalls(), 2);
    t.mock.method(dns.Resolver.prototype, 'resolve4', async () => [publicIp]);
    t.mock.method(dns.Resolver.prototype, 'resolve6', async () => { throw Object.assign(new Error('Timeout'), { code: 'ETIMEOUT' }); });
    assert.match(await request(p.port), /^HTTP\/1.1 403/);
    assert.equal(dials, 0);
  });

  await t.test('a mismatched connected peer receives zero HTTP origin bytes', async t => {
    const origin = await fixture(t);
    let bytes = 0;
    origin.server.on('connection', socket => socket.on('data', chunk => { bytes += chunk.length; }));
    dnsFixture(t);
    const dials = dialFixture(t, origin.port, '127.0.0.1');
    const p = await proxy(t);
    assert.match(await request(p.port), /^HTTP\/1.1 502/);
    await pause(20);
    assert.equal(dials(), 1);
    assert.equal(bytes, 0);
    assert.equal(p.stats.forwardedBytes, 0);
  });

  await t.test('CONNECT head waits for verified peer; a mismatched peer receives none', async t => {
    const origin = await fixture(t);
    const received: Buffer[] = [];
    origin.server.on('connection', socket => socket.on('data', chunk => { received.push(chunk); socket.write('reply'); }));
    dnsFixture(t);
    dialFixture(t, origin.port, publicIp, 80);
    const p = await proxy(t);
    const client = nativeConnect({ host: '127.0.0.1', port: p.port });
    client.on('error', () => {});
    t.after(() => client.destroy());
    let response = '';
    client.on('data', chunk => { response += chunk.toString(); });
    await once(client, 'connect');
    client.write(`CONNECT public.site:443 HTTP/1.1\r\nHost: public.site:443\r\nProxy-Authorization: ${authorization}\r\n\r\nsecret-head`);
    await pause(30);
    assert.equal(response, '');
    assert.equal(received.length, 0);
    await pause(120);
    assert.match(response, /^HTTP\/1.1 200 Connection Established/);
    assert.ok(response.includes('reply'));
    assert.equal(Buffer.concat(received).toString(), 'secret-head');
    assert.equal(p.stats.forwardedBytes, 'secret-headreply'.length);
    client.destroy();
    t.mock.restoreAll();
    dnsFixture(t);
    dialFixture(t, origin.port, '127.0.0.1');
    const before = Buffer.concat(received).length;
    const rejected = nativeConnect({ host: '127.0.0.1', port: p.port });
    rejected.on('error', () => {});
    t.after(() => rejected.destroy());
    let rejectedResponse = '';
    rejected.on('data', chunk => { rejectedResponse += chunk.toString(); });
    await once(rejected, 'connect');
    rejected.write(`CONNECT public.site:443 HTTP/1.1\r\nProxy-Authorization: ${authorization}\r\n\r\nforbidden-head`);
    await once(rejected, 'close');
    assert.match(rejectedResponse, /^HTTP\/1.1 403/);
    assert.equal(Buffer.concat(received).length, before);
  });

  await t.test('HTTP strips proxy and Connection-listed headers on both legs and validates Host', async t => {
    let seen: http.IncomingHttpHeaders | undefined;
    const origin = await fixture(t, (req, res) => {
      seen = req.headers;
      res.writeHead(200, { Connection: 'x-origin-secret, close', 'X-Origin-Secret': 'hidden',
        'Proxy-Authenticate': 'hidden', 'Proxy-Authorization': 'hidden', 'X-Preserved': 'yes' });
      res.end('body');
    });
    dnsFixture(t);
    dialFixture(t, origin.port);
    const p = await proxy(t);
    const response = await request(p.port, undefined,
      'Connection: x-client-secret\r\nX-Client-Secret: hidden\r\nProxy-Connection: keep-alive\r\nX-Preserved: yes\r\n');
    assert.match(response, /^HTTP\/1.1 200/);
    assert.equal(seen?.host, 'public.site');
    assert.equal(seen?.['proxy-authorization'], undefined);
    assert.equal(seen?.['proxy-connection'], undefined);
    assert.equal(seen?.['x-client-secret'], undefined);
    assert.equal(seen?.['x-preserved'], 'yes');
    assert.doesNotMatch(response, /x-origin-secret|proxy-authenticate|proxy-authorization/i);
    assert.match(response, /x-preserved: yes/i);
    assert.equal(p.stats.forwardedBytes, 4);
    assert.ok(p.stats.networkBytesRead > p.stats.forwardedBytes);
    assert.ok(p.stats.networkBytesWritten > p.stats.forwardedBytes);
  });

  await t.test('HTTP uses an explicitly empty environment proxy configuration', async t => {
    const origin = await fixture(t, (_req, res) => res.end('direct'));
    dnsFixture(t);
    const dials = dialFixture(t, origin.port);
    const NativeAgent = http.Agent;
    const captured: http.AgentOptions[] = [];
    t.mock.method(http, 'Agent', function (options: http.AgentOptions) {
      captured.push(options);
      return new NativeAgent(options);
    });
    const p = await proxy(t);
    assert.match(await request(p.port), /^HTTP\/1.1 200/);
    assert.equal(dials(), 1);
    assert.equal(captured.length, 1);
    assert.deepEqual(captured[0]!.proxyEnv, {});
  });

  await t.test('unexpected upstream 101 is rejected and both connections close promptly', async t => {
    const origin = await fixture(t);
    origin.server.on('connection', socket => socket.once('data', () => {
      socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nforbidden');
    }));
    dnsFixture(t);
    dialFixture(t, origin.port);
    const p = await proxy(t);
    const response = await request(p.port);
    assert.match(response, /^HTTP\/1.1 502/);
    assert.doesNotMatch(response, /forbidden|websocket|101 Switching/);
    await pause(20);
    assert.equal(origin.sockets.size, 0);
    assert.equal(p.stats.activeConnections, 0);
    assert.equal(p.stats.forwardedBytes, 0);
  });

  await t.test('redirects require a new admission and a fresh authorization', async t => {
    const origin = await fixture(t, (_req, res) => { res.writeHead(302, { Location: 'http://foreign.site/next' }); res.end(); });
    dnsFixture(t);
    const dials = dialFixture(t, origin.port);
    const checked: string[] = [];
    const p = await proxy(t, { authorize: url => { checked.push(url); return !url.includes('foreign.site'); } });
    const response = await request(p.port);
    assert.match(response, /^HTTP\/1.1 302/);
    assert.match(response, /location: http:\/\/foreign.site\/next/i);
    assert.equal(dials(), 1);
    assert.deepEqual(checked, ['http://public.site/path']);
    assert.match(await request(p.port, 'http://foreign.site/next'), /^HTTP\/1.1 403/);
    assert.equal(dials(), 1);
    assert.deepEqual(checked, ['http://public.site/path', 'http://foreign.site/next']);
  });

  await t.test('abort and expiry destroy open tunnels and pending authorization never dials', async t => {
    const origin = await fixture(t);
    dnsFixture(t);
    const dials = dialFixture(t, origin.port);
    const p = await proxy(t);
    const client = nativeConnect({ host: '127.0.0.1', port: p.port });
    client.on('error', () => {});
    await once(client, 'connect');
    client.write(`CONNECT public.site:443 HTTP/1.1\r\nProxy-Authorization: ${authorization}\r\n\r\n`);
    await once(client, 'data');
    p.controller.abort();
    await once(client, 'close');
    await p.close();
    await pause(20);
    assert.equal(p.stats.activeConnections, 0);
    assert.equal(p.stats.stopped, true);
    assert.equal(origin.sockets.size, 0);
    const expiring = await proxy(t, { expiresAt: Date.now() + 100, authorize: () => new Promise<boolean>(resolve => setTimeout(() => resolve(true), 200)) });
    assert.equal(await request(expiring.port), '');
    await pause(150);
    assert.equal(dials(), 1);
    assert.equal(expiring.stats.stopped, true);
    assert.equal(expiring.stats.activeConnections, 0);
  });

  await t.test('connection, header, and payload caps are enforced', async t => {
    const p = await proxy(t);
    const clients: net.Socket[] = [];
    t.after(() => { for (const client of clients) client.destroy(); });
    for (let i = 0; i < 33; i++) {
      const client = nativeConnect({ host: '127.0.0.1', port: p.port });
      client.on('error', () => {});
      clients.push(client);
      await once(client, 'connect');
    }
    await pause(20);
    assert.equal(p.stats.activeConnections, 32);
    assert.equal(clients[32]!.destroyed, true);
    await p.close();
    const headerProxy = await proxy(t);
    assert.match(await request(headerProxy.port, undefined, `X-Oversized: ${'x'.repeat(17000)}\r\n`), /^HTTP\/1.1 403/);
    assert.equal(headerProxy.stats.admissions, 0);
    const origin = await fixture(t, (_req, res) => {
      res.writeHead(200, { 'Content-Length': String(41 * 1024 * 1024) });
      res.end(Buffer.alloc(41 * 1024 * 1024));
    });
    dnsFixture(t);
    dialFixture(t, origin.port);
    const bodyProxy = await proxy(t);
    await request(bodyProxy.port);
    assert.equal(bodyProxy.stats.stopped, true);
    assert.ok(bodyProxy.stats.forwardedBytes <= 40 * 1024 * 1024);
    assert.ok(bodyProxy.stats.forwardedBytes > 39 * 1024 * 1024);
    assert.equal(bodyProxy.stats.limits.admissions, 1000);
  });
});
