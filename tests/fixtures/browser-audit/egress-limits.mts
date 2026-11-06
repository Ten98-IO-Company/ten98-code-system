import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import dns from 'node:dns/promises';
import { once } from 'node:events';
import net from 'node:net';
import { performance } from 'node:perf_hooks';
import test, { type TestContext } from 'node:test';
import { createPublicEgressProxy } from '../../../browser-audit-egress.mjs';

const nativeConnect = net.createConnection.bind(net);
const publicIp = '93.184.216.34';
const token = randomBytes(32).toString('base64url');
const authorization = `Basic ${Buffer.from(`audit:${token}`).toString('base64')}`;

async function proxy(t: TestContext, authorize?: Parameters<typeof createPublicEgressProxy>[0]['authorize']) {
  const value = createPublicEgressProxy({
    token, signal: new AbortController().signal, expiresAt: Date.now() + 40_000, authorize,
  });
  t.after(() => value.close());
  value.server.listen(0, '127.0.0.1');
  await once(value.server, 'listening');
  const address = value.server.address();
  assert.ok(address && typeof address !== 'string');
  return { ...value, port: address.port };
}

function publicDns(t: TestContext): () => number {
  let calls = 0;
  t.mock.method(dns.Resolver.prototype, 'resolve4', async () => { calls++; return [publicIp]; });
  t.mock.method(dns.Resolver.prototype, 'resolve6', async () => {
    calls++;
    throw Object.assign(new Error('No data'), { code: 'ENODATA' });
  });
  return () => calls;
}

function request(port: number, timeoutMs = 3_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = nativeConnect({ host: '127.0.0.1', port });
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('Local request exceeded its acceptance deadline'));
    }, timeoutMs);
    socket.on('data', chunk => chunks.push(chunk));
    socket.once('error', reject);
    socket.once('close', () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks).toString());
    });
    socket.once('connect', () => socket.write(
      `GET http://public.site/path HTTP/1.1\r\nHost: public.site\r\nProxy-Authorization: ${authorization}\r\nConnection: close\r\n\r\n`,
    ));
  });
}

async function tcpFixture(t: TestContext) {
  const server = net.createServer();
  const sockets = new Set<net.Socket>();
  let receivedBytes = 0;
  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('data', chunk => { receivedBytes += chunk.length; });
    socket.on('error', () => {});
    socket.once('close', () => sockets.delete(socket));
  });
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => server.close(() => resolve()));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  return { port: address.port, sockets, receivedBytes: () => receivedBytes };
}

function closedWithin(socket: net.Socket, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('Socket remained open beyond its acceptance deadline'));
    }, timeoutMs);
    socket.once('close', () => { clearTimeout(timer); resolve(); });
  });
}

test('fixed public-egress admission and elapsed-time limits', { timeout: 45_000 }, async t => {
  await t.test('exactly 1000 admissions reach DNS; the next authenticated request does not', { timeout: 12_000, skip: process.env.TEN98_BROWSER_AUDIT_LIMIT_TESTS !== '1' ? 'opt in to 1001 local requests with TEN98_BROWSER_AUDIT_LIMIT_TESTS=1' : false }, async t => {
    const dnsCalls = publicDns(t);
    let dialCalls = 0;
    let authorizationCalls = 0;
    t.mock.method(net, 'createConnection', () => { dialCalls++; throw new Error('Unexpected upstream dial'); });
    // An explicit authorization denial lets us exhaust admission without forwarding 1000 requests.
    const p = await proxy(t, () => { authorizationCalls++; return false; });
    for (let count = 1; count <= 1000; count++) {
      assert.match(await request(p.port), /^HTTP\/1\.1 403/, `admission ${count}`);
      assert.equal(p.stats.admissions, count);
    }
    assert.equal(dnsCalls(), 2000);
    assert.equal(authorizationCalls, 1000);
    assert.match(await request(p.port), /^HTTP\/1\.1 403/);
    assert.equal(p.stats.admissions, 1000);
    assert.equal(dnsCalls(), 2000, 'admission 1001 must not start DNS');
    assert.equal(authorizationCalls, 1000, 'admission 1001 must not reach native authorization');
    assert.equal(dialCalls, 0);
    assert.equal(p.stats.stopped, false, 'the admission ceiling must be observed before job expiry');
    t.diagnostic('1001 authenticated local HTTP requests; 1000 admissions; 2000 mocked DNS calls; zero upstream dials');
  });

  await t.test('unresolved DNS is cancelled and denied around 5 seconds without dialing', { timeout: 10_000 }, async t => {
    let dnsCalls = 0;
    let dialCalls = 0;
    let authorizationCalls = 0;
    let cancelledAt: number | undefined;
    const pending: Array<(reason: Error) => void> = [];
    const unresolved = () => {
      dnsCalls++;
      return new Promise<string[]>((_resolve, reject) => pending.push(reject));
    };
    t.mock.method(dns.Resolver.prototype, 'resolve4', unresolved);
    t.mock.method(dns.Resolver.prototype, 'resolve6', unresolved);
    t.mock.method(dns.Resolver.prototype, 'cancel', () => {
      cancelledAt ??= performance.now();
      for (const reject of pending.splice(0)) {
        reject(Object.assign(new Error('Cancelled'), { code: 'ECANCELLED' }));
      }
    });
    t.mock.method(net, 'createConnection', () => { dialCalls++; throw new Error('Unexpected upstream dial'); });
    const p = await proxy(t, () => { authorizationCalls++; return true; });
    const startedAt = performance.now();
    const response = await request(p.port, 8_000);
    const elapsed = performance.now() - startedAt;
    assert.match(response, /^HTTP\/1\.1 403/);
    assert.ok(elapsed >= 4_500 && elapsed <= 7_500, `DNS denial took ${elapsed.toFixed(0)} ms`);
    assert.ok(cancelledAt !== undefined, 'the shared resolver must receive cancellation');
    const cancelElapsed = cancelledAt - startedAt;
    assert.ok(cancelElapsed >= 4_500 && cancelElapsed <= 7_500, `DNS cancellation took ${cancelElapsed.toFixed(0)} ms`);
    assert.equal(pending.length, 0);
    assert.equal(dnsCalls, 2);
    assert.equal(dialCalls, 0);
    assert.equal(authorizationCalls, 0);
    assert.equal(p.stats.admissions, 1);
    assert.equal(p.stats.stopped, false, 'the DNS deadline must precede the 40-second job expiry');
    t.diagnostic(`DNS cancelled after ${cancelElapsed.toFixed(0)} ms; denied after ${elapsed.toFixed(0)} ms; zero upstream dials`);
  });

  await t.test('an established idle CONNECT tunnel closes both legs around 15 seconds', { timeout: 23_000 }, async t => {
    const origin = await tcpFixture(t);
    const dnsCalls = publicDns(t);
    let dialCalls = 0;
    t.mock.method(net, 'createConnection', (options: net.NetConnectOpts) => {
      dialCalls++;
      assert.ok('host' in options && options.host === publicIp);
      assert.ok('port' in options && options.port === 443);
      const socket = nativeConnect({ host: '127.0.0.1', port: origin.port });
      Object.defineProperty(socket, 'remoteAddress', { get: () => publicIp });
      Object.defineProperty(socket, 'remotePort', { get: () => 443 });
      return socket;
    });
    const p = await proxy(t);
    const client = nativeConnect({ host: '127.0.0.1', port: p.port });
    client.on('error', () => {});
    t.after(() => client.destroy());
    await once(client, 'connect');
    const handshake = once(client, 'data', { signal: AbortSignal.timeout(3_000) });
    client.write(`CONNECT public.site:443 HTTP/1.1\r\nHost: public.site:443\r\nProxy-Authorization: ${authorization}\r\n\r\n`);
    const [response] = await handshake;
    assert.match(String(response), /^HTTP\/1\.1 200 Connection Established\r\n\r\n$/);
    assert.equal(p.stats.activeConnections, 2);
    assert.equal(origin.sockets.size, 1);
    const originSocket = [...origin.sockets][0]!;
    const startedAt = performance.now();
    await Promise.all([closedWithin(client, 20_000), closedWithin(originSocket, 20_000)]);
    const elapsed = performance.now() - startedAt;
    assert.ok(elapsed >= 14_000 && elapsed <= 18_500, `idle tunnel closed after ${elapsed.toFixed(0)} ms`);
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(client.destroyed, true);
    assert.equal(origin.sockets.size, 0);
    assert.equal(p.stats.activeConnections, 0);
    assert.equal(p.stats.stopped, false, 'idle closure must precede the 40-second job expiry');
    assert.equal(p.stats.admissions, 1);
    assert.equal(p.stats.forwardedBytes, 0);
    assert.equal(origin.receivedBytes(), 0);
    assert.equal(dnsCalls(), 2);
    assert.equal(dialCalls, 1);
    t.diagnostic(`both idle tunnel legs closed after ${elapsed.toFixed(0)} ms; no application payload forwarded`);
  });
});
