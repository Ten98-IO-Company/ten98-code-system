export const image = 'node:24.22.1-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205';
export interface Probe { kind: 'tcp' | 'udp' | 'dns'; host: string; port: number; nonce: string }

// These self-contained typed functions are serialized after Node's type stripping.
export async function canary(role: 'worker' | 'capsule') {
  const net = await import('node:net'), udp = await import('node:dgram');
  const bindings: [string, number][] = role === 'worker'
    ? [['0.0.0.0', 3138], ['0.0.0.0', 3139], ['0.0.0.0', 53]]
    : [['0.0.0.0', 9223], ['0.0.0.0', 9224], ['127.0.0.1', 9222], ['127.0.0.1', 9221], ['::1', 9222]];
  for (const [host, port] of bindings) {
    const server = net.createServer(socket => {
      socket.setTimeout(1000, () => socket.destroy());
      socket.once('data', data => {
        if (data.length > 256) return socket.destroy();
        console.log(JSON.stringify({ kind: 'tcp', port, nonce: data.toString() }));
        socket.end(data);
      });
    });
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  }
  if (role === 'worker') for (const port of [53, 3138, 443]) {
    const socket = udp.createSocket('udp4');
    socket.on('message', (data, peer) => {
      if (data.length > 256) return;
      console.log(JSON.stringify({ kind: 'udp', port, nonce: data.toString() }));
      socket.send(data, peer.port, peer.address);
    });
    await new Promise<void>((resolve, reject) => { socket.once('error', reject); socket.bind(port, '0.0.0.0', resolve); });
  }
  console.log('READY');
  setTimeout(() => process.exit(0), 110_000);
}
export async function probe(input: Probe) {
  if (input.kind === 'dns') {
    const { Resolver } = await import('node:dns/promises');
    const resolver = new Resolver({ timeout: 500, tries: 1 }); resolver.setServers(['127.0.0.11']);
    try { return { ok: (await resolver.resolve4('worker')).includes('172.30.98.2'), nonce: input.nonce }; }
    catch { return { ok: false, nonce: input.nonce }; } finally { resolver.cancel(); }
  }
  if (input.kind === 'tcp') {
    const { createConnection } = await import('node:net');
    return await new Promise<{ ok: boolean; nonce: string }>(resolve => {
      const socket = createConnection({ host: input.host, port: input.port });
      const finish = (ok: boolean) => { socket.destroy(); resolve({ ok, nonce: input.nonce }); };
      socket.setTimeout(500, () => finish(false)); socket.once('error', () => finish(false));
      socket.once('connect', () => socket.write(input.nonce));
      socket.once('data', data => finish(data.toString() === input.nonce));
    });
  }
  const { createSocket } = await import('node:dgram');
  return await new Promise<{ ok: boolean; nonce: string }>(resolve => {
    const socket = createSocket('udp4');
    let settled = false;
    const timer = setTimeout(() => finish(false), 500);
    const finish = (ok: boolean) => { if (settled) return; settled = true; clearTimeout(timer); socket.close(); resolve({ ok, nonce: input.nonce }); };
    socket.once('error', () => finish(false)); socket.once('message', data => finish(data.toString() === input.nonce));
    socket.send(input.nonce, input.port, input.host);
  });
}
