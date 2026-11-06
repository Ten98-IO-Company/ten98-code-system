import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { createBrowserAuditNetworkPolicy, verifyBrowserAuditNetworkPolicy, pinBrowserAuditNetwork, createBrowserAuditNetworkAdapter } from '../browser-audit-launcher-network.mjs';
import type { BrowserAuditNetworkIdentity, BrowserAuditNetworkAdapter, BrowserAuditNamespaceCommand } from '../browser-audit-launcher-network.mjs';

const network = '1'.repeat(64), installation = '11111111-1111-4111-8111-111111111111';
function fixture() {
  const expected: BrowserAuditNetworkIdentity = { networkId: network,
    capsule: { id: '2'.repeat(64), image: 'sha256:' + '3'.repeat(64), pid: 101, startTicks: '100', startedAt: '2026-11-06T09:00:00.123456789Z', restartCount: 0, running: true,
      labels: { 'io.ten98.installation': installation, 'io.ten98.operation': '22222222-2222-4222-8222-222222222222', 'io.ten98.generation': '1', 'io.ten98.ownership': '4'.repeat(64) }, networks: { [network]: { ipv4: '172.20.0.3', ipv6: '' } } },
    worker: { id: '5'.repeat(64), image: 'sha256:' + '6'.repeat(64), pid: 102, startTicks: '200', startedAt: '2026-11-06T08:00:00Z', restartCount: 0, running: true,
      labels: { 'io.ten98.installation': installation }, networks: { [network]: { ipv4: '172.20.0.2', ipv6: '' } } },
  };
  let observed = structuredClone(expected);
  const policy = createBrowserAuditNetworkPolicy('172.20.0.3', '172.20.0.2');
  const commands: BrowserAuditNamespaceCommand[] = [], closed: number[] = [];
  const adapter: BrowserAuditNetworkAdapter = {
    inspect: async () => structuredClone(observed), processStart: pid => pid === 101 ? '100' : '200',
    namespace: pid => ({ dev: '4', ino: pid === 101 ? '30' : pid === 102 ? '20' : '10' }),
    openNamespace: () => 17, descriptor: () => ({ dev: '4', ino: '30' }), close: fd => { closed.push(fd); },
    execute: async command => { commands.push(command); return command.args[2] === '/usr/sbin/iptables-legacy-save' ? policy.ipv4 : command.args[2] === '/usr/sbin/ip6tables-legacy-save' ? policy.ipv6 : ''; },
  };
  return { expected, policy, commands, closed, adapter, get observed() { return observed; }, set observed(value) { observed = value; } };
}

test('policy has only eight exact TCP tuple rules, default DROP and no IPv6 exceptions', () => {
  const p = createBrowserAuditNetworkPolicy('172.20.0.3', '172.20.0.2');
  assert.equal(p.ipv4.split('\n').filter(line => line.startsWith('-A ')).length, 8);
  assert.equal(p.ipv6, '*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n');
  assert.ok(p.ipv4.includes('-A OUTPUT -s 172.20.0.3/32 -d 172.20.0.2/32 -p tcp -m tcp --dport 3138 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT'));
  assert.ok(p.ipv4.includes('-A INPUT -s 172.20.0.2/32 -d 172.20.0.3/32 -p tcp -m tcp --dport 9223 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT'));
  for (const line of p.ipv4.split('\n').filter(line => line.startsWith('-A '))) {
    assert.match(line, /-s [0-9.]+\/32 -d [0-9.]+\/32/); assert.match(line, /--(?:s|d)port (3138|9223|9222) /);
    if (line.includes('127.0.0.1')) assert.match(line, /-[io] lo /);
  }
  assert.doesNotMatch(p.ipv4, /127\.0\.0\.11|RELATED|udp|:FORWARD ACCEPT/);
  assert.equal(p.sha256.length, 64);
});

for (const address of ['127.0.0.1', '127.0.0.11', '169.254.169.254', '8.8.8.8', '172.020.0.3', '172.20.0.3\n', '::1', '172.20.0.3;id', '192.168.1.1/24']) {
  test(`rejects noncanonical/nonprivate policy address ${JSON.stringify(address)}`, () => assert.throws(() => createBrowserAuditNetworkPolicy(address, '172.20.0.2')));
}
test('rejects same capsule and worker address', () => assert.throws(() => createBrowserAuditNetworkPolicy('10.0.0.1', '10.0.0.1')));

test('readback accepts counters/comments/state ordering but rejects missing, extra or weakened policy', () => {
  const f = fixture();
  verifyBrowserAuditNetworkPolicy(f.policy, '# tool header\n' + f.policy.ipv4.replaceAll('[0:0]', '[123:456]').replaceAll('NEW,ESTABLISHED', 'ESTABLISHED,NEW'), f.policy.ipv6, '');
  for (const mutated of [f.policy.ipv4.replace(':INPUT DROP', ':INPUT ACCEPT'), f.policy.ipv4.replace('--dport 3138', '--dport 3139'),
    f.policy.ipv4.replace('-s 172.20.0.2/32 ', ''), f.policy.ipv4.replace('COMMIT', '-A OUTPUT -j ACCEPT\nCOMMIT'),
    f.policy.ipv4.replace('COMMIT', '-A OUTPUT -d 127.0.0.11 -j ACCEPT\nCOMMIT'), f.policy.ipv4.replace('ESTABLISHED', 'RELATED,ESTABLISHED'), '', 'x'.repeat(65537)]) {
    assert.throws(() => verifyBrowserAuditNetworkPolicy(f.policy, mutated, f.policy.ipv6, ''));
  }
  assert.throws(() => verifyBrowserAuditNetworkPolicy(f.policy, f.policy.ipv4, f.policy.ipv6.replace('OUTPUT DROP', 'OUTPUT ACCEPT'), ''));
});

test('pins fd, installs both policies, verifies readback and exposes only fixed sanitized host commands', async () => {
  const f = fixture(), pinned = await pinBrowserAuditNetwork(f.expected, f.adapter);
  f.expected.capsule.id = '7'.repeat(64); // Caller mutation must not change the retained expected identity.
  assert.deepEqual(await pinned.apply(), { policySha256: f.policy.sha256, namespace: { dev: '4', ino: '30' } });
  assert.deepEqual(f.commands.map(c => c.args[2]), ['/usr/sbin/nft', '/usr/sbin/iptables-legacy-restore', '/usr/sbin/ip6tables-legacy-restore', '/usr/sbin/iptables-legacy-save', '/usr/sbin/ip6tables-legacy-save', '/usr/sbin/nft']);
  for (const c of f.commands) {
    assert.equal(c.fd, 17); assert.equal(c.executable, '/usr/bin/nsenter'); assert.deepEqual(c.args.slice(0, 2), ['--net=/proc/self/fd/3', '--']);
    assert.equal(c.shell, false); assert.equal(c.timeoutMs, 2000); assert.equal(c.maxOutputBytes, 65536);
    assert.deepEqual(c.environment, { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' });
    assert.doesNotMatch(JSON.stringify(c), /CAPABILITY|TOKEN|DOCKER_HOST|LD_PRELOAD|--target|--all/);
  }
  assert.equal(f.commands[1]!.input, f.policy.ipv4); assert.equal(f.commands[2]!.input, f.policy.ipv6);
  assert.deepEqual(f.commands[3]!.args.slice(3), []); assert.deepEqual(f.commands[4]!.args.slice(3), []);
  assert.deepEqual(f.commands[0]!.args.slice(3), ['-n', 'list', 'ruleset']);
  assert.deepEqual(f.commands[5]!.args.slice(3), ['-n', 'list', 'ruleset']);
  await pinned.verify(); pinned.close(); pinned.close(); assert.deepEqual(f.closed, [17]);
  await assert.rejects(pinned.apply());
});

const mutations: Record<string, (value: BrowserAuditNetworkIdentity) => void> = {
  pid: x => { x.capsule.pid++; }, start: x => { x.capsule.startTicks = '101'; }, image: x => { x.capsule.image = 'sha256:' + '9'.repeat(64); },
  labels: x => { x.capsule.labels['io.ten98.ownership'] = '8'.repeat(64); }, network: x => { x.capsule.networks['9'.repeat(64)] = { ipv4: '10.0.0.1', ipv6: '' }; },
  worker: x => { x.worker.id = '7'.repeat(64); }, ipv6: x => { x.capsule.networks[network]!.ipv6 = 'fd00::1'; },
  stopped: x => { x.capsule.running = false; }, restarted: x => { x.capsule.restartCount++; }, address: x => { x.worker.networks[network]!.ipv4 = '172.20.0.9'; },
};
for (const [name, mutate] of Object.entries(mutations)) {
  test(`changed ${name} rejects before host commands`, async () => {
    const f = fixture(); mutate(f.observed); await assert.rejects(pinBrowserAuditNetwork(f.expected, f.adapter)); assert.equal(f.commands.length, 0);
  });
}
for (const ino of ['10', '20', '', '0']) {
  test(`host, worker or unknown namespace ${ino} rejects before pin or command`, async () => {
    const f = fixture(), original = f.adapter.namespace;
    f.adapter.namespace = pid => pid === 101 ? { dev: '4', ino } : original(pid);
    await assert.rejects(pinBrowserAuditNetwork(f.expected, f.adapter)); assert.equal(f.commands.length, 0); assert.deepEqual(f.closed, []);
  });
}
test('wrong descriptor identity and PID start fail, with owned descriptor cleanup', async () => {
  const f = fixture(); f.adapter.descriptor = () => ({ dev: '4', ino: '99' });
  await assert.rejects(pinBrowserAuditNetwork(f.expected, f.adapter)); assert.deepEqual(f.closed, [17]); assert.equal(f.commands.length, 0);
  const g = fixture(); g.adapter.processStart = () => '999'; await assert.rejects(pinBrowserAuditNetwork(g.expected, g.adapter)); assert.deepEqual(g.closed, []);
});

test('rechecks namespace and descriptor before every command, not just when pinning', async () => {
  const f = fixture(), pinned = await pinBrowserAuditNetwork(f.expected, f.adapter);
  f.adapter.descriptor = () => ({ dev: '4', ino: '99' });
  await assert.rejects(pinned.apply()); assert.equal(f.commands.length, 0); assert.deepEqual(f.closed, [17]);
});

for (const kind of ['restore', 'readback', 'overflow', 'changed-after-command']) {
  test(`${kind} failure invalidates the pin and never returns accepted policy`, async () => {
    const f = fixture(), execute = f.adapter.execute;
    f.adapter.execute = async c => {
      if (kind === 'restore') throw Error('private-secret');
      if (kind === 'readback' && c.args[2]!.endsWith('-save')) return '*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n';
      if (kind === 'overflow') return 'x'.repeat(65537);
      const result = await execute(c); if (kind === 'changed-after-command') f.observed.capsule.restartCount++; return result;
    };
    const pinned = await pinBrowserAuditNetwork(f.expected, f.adapter);
    await assert.rejects(pinned.apply(), { message: 'browser-audit-network-rejected' }); assert.deepEqual(f.closed, [17]); await assert.rejects(pinned.verify());
  });
}

test('invalid expected labels/UUID/IDs cannot reach the adapter', async () => {
  const f = fixture(); let inspected = false; f.adapter.inspect = async () => { inspected = true; return f.observed; };
  f.expected.capsule.labels['io.ten98.operation'] = 'arbitrary;command';
  await assert.rejects(pinBrowserAuditNetwork(f.expected, f.adapter)); assert.equal(inspected, false);
});

test('module import and native adapter construction do not inspect or mutate the host', () => {
  const adapter = createBrowserAuditNetworkAdapter(async () => { throw Error('must not inspect'); }); assert.equal(typeof adapter.execute, 'function');
  const entry = new URL('../browser-audit-launcher-network.mjs', import.meta.url);
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', `const m=await import(${JSON.stringify(entry.href)});m.createBrowserAuditNetworkAdapter(async()=>{throw Error('called')});console.log('passive');`], { encoding: 'utf8', timeout: 5000, windowsHide: true });
  assert.equal(child.status, 0, child.stderr); assert.equal(child.stdout.trim(), 'passive');
});

test('hung inspection aborts at the bounded deadline without opening a namespace', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(); let signal: AbortSignal | undefined, opened = false;
  f.adapter.inspect = async value => { signal = value; return new Promise(() => {}); };
  f.adapter.openNamespace = () => { opened = true; return 17; };
  const pending = pinBrowserAuditNetwork(f.expected, f.adapter);
  const rejected = assert.rejects(pending, { message: 'browser-audit-network-rejected' });
  await Promise.resolve(); t.mock.timers.tick(2000); await rejected;
  assert.equal(signal?.aborted, true); assert.equal(opened, false); assert.equal(f.commands.length, 0);
});

test('invalid descriptor number cannot be inherited or sent to a policy command', async () => {
  const f = fixture(); f.adapter.openNamespace = () => -1;
  await assert.rejects(pinBrowserAuditNetwork(f.expected, f.adapter)); assert.equal(f.commands.length, 0); assert.deepEqual(f.closed, []);
});

test('unexpected DNAT rejects admission even when the filter table is identical', async () => {
  const f = fixture(), execute = f.adapter.execute;
  f.adapter.execute = async command => {
    const output = await execute(command);
    if (command.args[2]!.includes('iptables') && command.args[2]!.endsWith('-save') && !command.args.includes('-t')) {
      return output.replace(':POSTROUTING ACCEPT [0:0]\n', ':POSTROUTING ACCEPT [0:0]\n-A OUTPUT -d 172.20.0.2/32 -p tcp --dport 3138 -j DNAT --to-destination 169.254.169.254:80\n');
    }
    return output;
  };
  const pinned = await pinBrowserAuditNetwork(f.expected, f.adapter);
  await assert.rejects(pinned.verify(), { message: 'browser-audit-network-rejected' });
});

for (const nft of ['table ip nat {}', 'table inet other {}', 'table bridge other {}']) {
  test('nonempty nft ruleset rejects before restore: ' + nft, async () => {
    const f = fixture(), execute = f.adapter.execute;
    f.adapter.execute = async c => { const result = await execute(c); return c.args[2] === '/usr/sbin/nft' ? nft : result; };
    const pinned = await pinBrowserAuditNetwork(f.expected, f.adapter);
    await assert.rejects(pinned.apply()); assert.equal(f.commands.length, 1); assert.deepEqual(f.closed, [17]);
  });
}
test('requires NAT in both families and rejects unknown or nonempty ancillary tables', () => {
  const f = fixture();
  const empty = (name: string, chains: string[]) => ['*' + name, ...chains.map(c => ':' + c + ' ACCEPT [0:0]'), 'COMMIT', ''].join('\n');
  for (const [name, chains] of [['raw', ['PREROUTING', 'OUTPUT']], ['mangle', ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING']], ['security', ['INPUT', 'FORWARD', 'OUTPUT']]] as const) {
    const table = empty(name, [...chains]);
    verifyBrowserAuditNetworkPolicy(f.policy, table + f.policy.ipv4, f.policy.ipv6, '');
    assert.throws(() => verifyBrowserAuditNetworkPolicy(f.policy, table.replace('COMMIT', '-A OUTPUT -j ACCEPT\nCOMMIT') + f.policy.ipv4, f.policy.ipv6, ''));
  }
  assert.throws(() => verifyBrowserAuditNetworkPolicy(f.policy, f.policy.ipv4.split('*nat')[0]!, f.policy.ipv6, ''));
  assert.throws(() => verifyBrowserAuditNetworkPolicy(f.policy, f.policy.ipv4, f.policy.ipv6.replace(':POSTROUTING ACCEPT', ':POSTROUTING DROP'), ''));
  assert.throws(() => verifyBrowserAuditNetworkPolicy(f.policy, f.policy.ipv4 + empty('unknown', ['OUTPUT']), f.policy.ipv6, ''));
  assert.throws(() => verifyBrowserAuditNetworkPolicy(f.policy, f.policy.ipv4 + empty('nat', ['OUTPUT']), f.policy.ipv6, ''));
});
