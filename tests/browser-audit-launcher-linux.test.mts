import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { randomUUID, randomBytes } from 'node:crypto';
import { closeSync, existsSync, fstatSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { createBrowserAuditNetworkAdapter, pinBrowserAuditNetwork } from '../browser-audit-launcher-network.mjs';
import type { BrowserAuditContainerIdentity } from '../browser-audit-launcher-network.mjs';
import type * as LinuxFixture from './fixtures/browser-audit/launcher-linux.mts';
const { image, canary, probe } = await import(new URL('./fixtures/browser-audit/launcher-linux.mts', import.meta.url).href) as typeof LinuxFixture;
import type { Probe } from './fixtures/browser-audit/launcher-linux.mts';

const dir = 'work/d9-linux-proof', leasePath = dir + '/lease.json';
const enabled = process.env.TEN98_LINUX_PROOF === '1';
let deadline = 0;
function guard() {
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid?.(), 0);
  assert.equal(process.env.GITHUB_ACTIONS, 'true'); assert.equal(process.env.RUNNER_ENVIRONMENT, 'github-hosted');
  assert.equal(process.version, 'v24.22.1');
}
function command(executable: string, args: string[], fd?: number, input = '', signal?: AbortSignal): Promise<string> {
  signal?.throwIfAborted();
  const remaining = deadline - Date.now(); assert(remaining > 0, 'absolute test deadline');
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { shell: false, env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' },
      stdio: fd === undefined ? ['pipe', 'pipe', 'pipe'] : ['pipe', 'pipe', 'pipe', fd] });
    let bytes = 0, failed = false, output = '', error = '';
    const fail = () => { failed = true; child.kill('SIGKILL'); };
    const timer = setTimeout(fail, Math.min(8000, remaining));
    signal?.addEventListener('abort', fail, { once: true });
    child.stdout!.on('data', (data: Buffer) => { bytes += data.length; if (bytes > 65536) fail(); else output += data.toString(); });
    child.stderr!.on('data', (data: Buffer) => { bytes += data.length; if (bytes > 65536) fail(); else error += data.toString(); });
    child.stdin!.on('error', fail);
    child.once('error', cause => { clearTimeout(timer); signal?.removeEventListener('abort', fail); reject(cause); });
    child.once('close', code => { clearTimeout(timer); signal?.removeEventListener('abort', fail); if (failed || code !== 0) reject(new Error(executable + ': ' + code + ': ' + error.slice(0, 500))); else resolve(output.trim()); });
    child.stdin!.end(input);
  });
}
const docker = (...args: string[]) => command('/usr/bin/docker', ['--host', 'unix:///var/run/docker.sock', ...args]);
interface Lease { nonce: string; networkName: string; names: string[]; imageId: string; cleaned: boolean }
function save(lease: Lease) { mkdirSync(dir, { recursive: true }); writeFileSync(leasePath, JSON.stringify(lease, null, 2) + '\n', { mode: 0o600 }); }
async function cleanup(lease: Lease) {
  assert.match(lease.nonce, /^[a-f0-9]{64}$/); assert.match(lease.imageId, /^sha256:[a-f0-9]{64}$/);
  const filter = 'label=io.ten98.ownership=' + lease.nonce;
  const ids = (await docker('ps', '-aq', '--filter', filter)).split('\n').filter(Boolean);
  assert(ids.length <= 2, 'unexpected owned container count');
  for (const id of ids) {
    const [item] = JSON.parse(await docker('inspect', id));
    assert.equal(item.Config.Labels['io.ten98.ownership'], lease.nonce);
    assert.equal(item.Image, lease.imageId); assert(lease.names.includes(item.Name.slice(1)));
    await docker('rm', '-f', item.Id);
  }
  const networks = (await docker('network', 'ls', '-q', '--filter', filter)).split('\n').filter(Boolean);
  assert(networks.length <= 1, 'unexpected owned network count');
  for (const id of networks) {
    const [item] = JSON.parse(await docker('network', 'inspect', id));
    assert.equal(item.Labels['io.ten98.ownership'], lease.nonce); assert.equal(item.Name, lease.networkName);
    assert.equal(Object.keys(item.Containers ?? {}).length, 0); await docker('network', 'rm', item.Id);
  }
  assert.equal(await docker('ps', '-aq', '--filter', filter), '');
  assert.equal(await docker('network', 'ls', '-q', '--filter', filter), '');
  lease.cleaned = true; save(lease);
}
if (process.env.TEN98_LINUX_CLEANUP === '1') {
  guard(); deadline = Date.now() + 20_000;
  if (existsSync(leasePath)) await cleanup(JSON.parse(readFileSync(leasePath, 'utf8')));
} else {
  test('Linux canary and probe bootstrap remain executable after type stripping', () => {
    assert.doesNotThrow(() => new Function('return (' + canary.toString() + ')'));
    assert.doesNotThrow(() => new Function('return (' + probe.toString() + ')'));
  });
  test('native Linux namespace policy: actual adapter, traffic, refusals and cleanup', {
  skip: !enabled && 'set TEN98_LINUX_PROOF=1 only in the disposable hosted Linux job', timeout: 120_000,
}, async () => {
  guard(); const hardDeadline = Date.now() + 110_000; deadline = hardDeadline - 20_000;
  const hostNamespace = statSync('/proc/self/ns/net', { bigint: true }).ino.toString();
  const openBefore = readdirSync('/proc/self/fd').length;
  const installation = randomUUID(), operation = randomUUID(), nonce = randomBytes(32).toString('hex');
  const prefix = 'ten98-proof-' + nonce.slice(0, 12), names = [prefix + '-worker', prefix + '-capsule'];
  const imageId = await docker('image', 'inspect', '--format', '{{.Id}}', image);
  assert.match(imageId, /^sha256:[a-f0-9]{64}$/);
  const lease: Lease = { nonce, names, networkName: prefix, imageId, cleaned: false };
  save(lease);
  const evidence: Record<string, unknown> = { image, imageId, hostNamespace, probes: [], nativeAccepted: false };
  const pins: Awaited<ReturnType<typeof pinBrowserAuditNetwork>>[] = [];
  let probes = 0;
  const interrupt = () => { deadline = Date.now(); };
  process.once('SIGTERM', interrupt); process.once('SIGINT', interrupt);
  try {
    evidence.tools = await command('/usr/bin/nsenter', ['--version']);
    evidence.docker = await docker('version', '--format', '{{json .Server}}');
    for (const tool of ['iptables-legacy-restore', 'ip6tables-legacy-restore', 'iptables-legacy-save', 'ip6tables-legacy-save', 'nft']) {
      assert(statSync('/usr/sbin/' + tool).isFile(), 'missing fixed tool: ' + tool);
    }
    const networkId = await docker('network', 'create', '--internal', '--subnet', '172.30.98.0/24',
      '--label', 'io.ten98.ownership=' + nonce, lease.networkName);
    assert.match(networkId, /^[a-f0-9]{64}$/);
    const ids: string[] = [];
    for (const [index, role] of (['worker', 'capsule'] as const).entries()) {
      const id = await docker('create', '--name', names[index]!, '--network', networkId, '--network-alias', role,
        '--ip', '172.30.98.' + (index + 2), '--read-only', '--user', '65532:65532', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--restart', 'no', '--pids-limit', '32', '--memory', '128m', '--cpus', '0.5',
        '--sysctl', 'net.ipv4.ip_unprivileged_port_start=0', '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0',
        '--label', 'io.ten98.installation=' + installation, '--label', 'io.ten98.operation=' + operation,
        '--label', 'io.ten98.generation=1', '--label', 'io.ten98.ownership=' + nonce,
        '--entrypoint', 'node', image, '--input-type=module', '-e', '(' + canary.toString() + ')(' + JSON.stringify(role) + ').catch(e=>{console.error(e);process.exit(1)})');
      assert.match(id, /^[a-f0-9]{64}$/); ids.push(id); await docker('start', id);
    }
    const worker = ids[0]!, capsule = ids[1]!;
    for (const id of ids) {
      const until = Date.now() + 5000;
      while (!(await docker('logs', id)).split('\n').includes('READY')) {
        assert(Date.now() < until, 'canary readiness timeout'); await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    const adapter = createBrowserAuditNetworkAdapter(async signal => {
      signal.throwIfAborted();
      const items = JSON.parse(await command('/usr/bin/docker', ['--host', 'unix:///var/run/docker.sock', 'inspect', capsule, worker], undefined, '', signal));
      signal.throwIfAborted();
      const convert = (item: { Id: string; Image: string; State: { Pid: number; StartedAt: string; Running: boolean }; RestartCount: number;
        Config: { Labels: Record<string, string> }; NetworkSettings: { Networks: Record<string, { NetworkID: string; IPAddress: string; GlobalIPv6Address: string }> } }): BrowserAuditContainerIdentity => ({
        id: item.Id, image: item.Image, pid: item.State.Pid, startTicks: adapter.processStart(item.State.Pid),
        startedAt: item.State.StartedAt, restartCount: item.RestartCount, running: item.State.Running, labels: item.Config.Labels,
        networks: Object.fromEntries(Object.values(item.NetworkSettings.Networks).map(n => [n.NetworkID, { ipv4: n.IPAddress, ipv6: n.GlobalIPv6Address }])),
      });
      return { networkId, capsule: convert(items[0]), worker: convert(items[1]) };
    });
    const expected = await adapter.inspect(new AbortController().signal);
    assert.equal(expected.capsule.id, capsule); assert.equal(expected.worker.id, worker);
    assert.equal(expected.capsule.image, imageId); assert.equal(expected.worker.image, imageId);
    assert.deepEqual(expected.capsule.networks[networkId], { ipv4: '172.30.98.3', ipv6: '' });
    assert.deepEqual(expected.worker.networks[networkId], { ipv4: '172.30.98.2', ipv6: '' });
    const namespace = adapter.namespace(expected.capsule.pid);
    async function inCapsule(tool: string, args: string[], input = '') {
      assert.deepEqual(await adapter.inspect(new AbortController().signal), expected);
      const fd = adapter.openNamespace(expected.capsule.pid);
      try {
        assert.deepEqual(adapter.descriptor(fd), namespace);
        for (const pid of ['self', 1, expected.worker.pid] as const) assert.notDeepEqual(namespace, adapter.namespace(pid));
        return await command('/usr/bin/nsenter', ['--net=/proc/self/fd/3', '--', tool, ...args], fd, input);
      } finally { adapter.close(fd); }
    }
    evidence.fd3 = JSON.parse(await inCapsule(process.execPath, ['--input-type=module', '-e',
      "import{fstatSync,statSync}from'node:fs';console.log(JSON.stringify([fstatSync(3,{bigint:true}),statSync('/proc/self/ns/net',{bigint:true})].map(s=>({dev:String(s.dev),ino:String(s.ino)}))))"]));
    assert.deepEqual(evidence.fd3, [namespace, namespace]);
    async function exchange(id: string, kind: Probe['kind'], host: string, port: number, wanted: boolean) {
      assert(++probes <= 100);
      const input: Probe = { kind, host, port, nonce: randomBytes(12).toString('hex') };
      const actual = JSON.parse(await docker('exec', id, 'node', '--input-type=module', '-e',
        '(' + probe.toString() + ')(' + JSON.stringify(input) + ').then(x=>console.log(JSON.stringify(x)))'));
      (evidence.probes as unknown[]).push({ ...input, source: id === capsule ? 'capsule' : 'worker', wanted, actual });
      assert.equal(actual.nonce, input.nonce); assert.equal(actual.ok, wanted, kind + ' ' + host + ':' + port);
      if (kind !== 'dns') {
        const target = host === '172.30.98.2' ? worker : capsule;
        const logs = await docker('logs', target);
        assert.equal(logs.includes(input.nonce), wanted, 'receiver nonce evidence');
      }
    }
    const cases: [string, Probe['kind'], string, number, boolean][] = [
      [capsule, 'tcp', '172.30.98.2', 3138, true], [worker, 'tcp', '172.30.98.3', 9223, true],
      [capsule, 'tcp', '127.0.0.1', 9222, true], [capsule, 'tcp', '172.30.98.2', 3139, false],
      [worker, 'tcp', '172.30.98.3', 9224, false], [capsule, 'tcp', '127.0.0.1', 9221, false],
      [capsule, 'tcp', '172.30.98.2', 53, false], [capsule, 'udp', '172.30.98.2', 53, false],
      [capsule, 'udp', '172.30.98.2', 3138, false], [capsule, 'udp', '172.30.98.2', 443, false],
      [capsule, 'tcp', '::1', 9222, false], [capsule, 'dns', '127.0.0.11', 53, false],
    ];
    for (const [id, kind, host, port] of cases) await exchange(id, kind, host, port, true);
    evidence.beforeNft = await inCapsule('/usr/sbin/nft', ['-n', 'list', 'ruleset']);
    async function apply() {
      const pin = await pinBrowserAuditNetwork(expected, adapter); pins.push(pin);
      await pin.apply(); await pin.verify(); return pin;
    }
    let pin = await apply();
    evidence.applied = { ipv4: await inCapsule('/usr/sbin/iptables-legacy-save', []), ipv6: await inCapsule('/usr/sbin/ip6tables-legacy-save', []) };
    for (const [id, kind, host, port, wanted] of cases) await exchange(id, kind, host, port, wanted);
    const weakened = pin.policy.ipv4.replace('COMMIT',
      '-A OUTPUT -s 172.30.98.3/32 -d 172.30.98.2/32 -p tcp --dport 3139 -j ACCEPT\n-A INPUT -s 172.30.98.2/32 -d 172.30.98.3/32 -p tcp --sport 3139 -m conntrack --ctstate ESTABLISHED -j ACCEPT\nCOMMIT');
    await inCapsule('/usr/sbin/iptables-legacy-restore', ['--wait', '2'], weakened);
    await assert.rejects(exchange(capsule, 'tcp', '172.30.98.2', 3139, false), /tcp 172.30.98.2:3139/);
    await exchange(capsule, 'tcp', '172.30.98.2', 3139, true);
    await assert.rejects(pin.verify()); evidence.weakenedPolicyDetected = true;
    pin = await apply();
    const filter = await inCapsule('/usr/sbin/iptables-legacy-save', ['-t', 'filter']);
    await inCapsule('/usr/sbin/iptables-legacy', ['-t', 'nat', '-A', 'OUTPUT', '-d', '172.30.98.2/32', '-p', 'tcp', '--dport', '3138', '-j', 'DNAT', '--to-destination', '172.30.98.2:3139']);
    const normalize = (value: string) => value.split('\n').filter(line => !line.startsWith('#')).join('\n');
    assert.equal(normalize(await inCapsule('/usr/sbin/iptables-legacy-save', ['-t', 'filter'])), normalize(filter));
    assert.match(await inCapsule('/usr/sbin/iptables-legacy-save', ['-t', 'nat']), /DNAT/);
    await assert.rejects(pin.verify()); evidence.natRejected = true;
    pin = await apply();
    await inCapsule('/usr/sbin/nft', ['add', 'table', 'inet', 'ten98_negative']);
    await assert.rejects(pin.verify()); evidence.nftRejected = true;
    await inCapsule('/usr/sbin/nft', ['delete', 'table', 'inet', 'ten98_negative']);
    pin = await apply(); evidence.identityBaselineVerified = true;
    await docker('restart', '--time', '0', capsule);
    await assert.rejects(pin.verify()); evidence.identityRejected = true;
    const current = await adapter.inspect(new AbortController().signal);
    assert.notEqual(current.capsule.startedAt, expected.capsule.startedAt);
    const fd = adapter.openNamespace(current.capsule.pid); closeSync(fd);
    await assert.rejects(async () => adapter.execute({ executable: '/usr/bin/nsenter',
      args: ['--net=/proc/self/fd/3', '--', '/usr/sbin/iptables-legacy-save'], fd, input: '',
      environment: {}, timeoutMs: 2000, maxOutputBytes: 65536, shell: false }));
    evidence.closedFdRejected = true; evidence.nativeAccepted = true;
  } catch (error) {
    evidence.failure = error instanceof Error ? error.message : String(error); throw error;
  } finally {
    deadline = Math.min(Date.now() + 20_000, hardDeadline);
    try {
      const closeErrors: unknown[] = [];
      for (const pin of pins) { try { pin.close(); } catch (error) { closeErrors.push(error); } }
      await cleanup(lease);
      assert.equal(closeErrors.length, 0, 'owned pin cleanup failed');
      assert.equal(statSync('/proc/self/ns/net', { bigint: true }).ino.toString(), hostNamespace);
      assert(readdirSync('/proc/self/fd').length <= openBefore, 'namespace descriptor leak');
      evidence.cleaned = true;
    } finally {
      process.removeListener('SIGTERM', interrupt); process.removeListener('SIGINT', interrupt);
      evidence.probeCount = probes; writeFileSync(dir + '/result.json', JSON.stringify(evidence, null, 2) + '\n');
      console.log(JSON.stringify(evidence));
    }
  }
});
}
