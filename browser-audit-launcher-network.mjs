import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { closeSync, constants, fstatSync, openSync, readFileSync, statSync } from 'node:fs';
import { isIPv4 } from 'node:net';
const failure = () => new Error('browser-audit-network-rejected');
const hex = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) && value.length === 64;
const uuid = (value) => typeof value === 'string' && value.length === 36 && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const decimal = (value) => typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value);
const equalNamespace = (a, b) => a.dev === b.dev && a.ino === b.ino;
function namespaceIdentity(value) {
    if (!value || !decimal(value.ino) || typeof value.dev !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value.dev))
        throw failure();
    return value;
}
function privateIPv4(value) {
    if (!isIPv4(value))
        throw failure();
    const [a, b] = value.split('.').map(Number);
    if (!(a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)))
        throw failure();
    return value;
}
function emptyTable(name, chains) {
    return ['*' + name, ...chains.map(chain => ':' + chain + ' ACCEPT [0:0]'), 'COMMIT', ''].join('\n');
}
function table(rules) {
    return ['*filter', ':INPUT DROP [0:0]', ':FORWARD DROP [0:0]', ':OUTPUT DROP [0:0]', ...rules, 'COMMIT', ''].join('\n');
}
export function createBrowserAuditNetworkPolicy(capsuleAddress, workerAddress) {
    const capsule = privateIPv4(capsuleAddress), worker = privateIPv4(workerAddress);
    if (capsule === worker)
        throw failure();
    const tcp = (chain, source, destination, port, state, loopback = '') => `-A ${chain} -s ${source}/32 -d ${destination}/32${loopback} -p tcp -m tcp ${port} -m conntrack --ctstate ${state} -j ACCEPT`;
    const rules = [
        tcp('INPUT', worker, capsule, '--sport 3138', 'ESTABLISHED'),
        tcp('INPUT', worker, capsule, '--dport 9223', 'NEW,ESTABLISHED'),
        tcp('INPUT', '127.0.0.1', '127.0.0.1', '--dport 9222', 'NEW,ESTABLISHED', ' -i lo'),
        tcp('INPUT', '127.0.0.1', '127.0.0.1', '--sport 9222', 'ESTABLISHED', ' -i lo'),
        tcp('OUTPUT', capsule, worker, '--dport 3138', 'NEW,ESTABLISHED'),
        tcp('OUTPUT', capsule, worker, '--sport 9223', 'ESTABLISHED'),
        tcp('OUTPUT', '127.0.0.1', '127.0.0.1', '--dport 9222', 'NEW,ESTABLISHED', ' -o lo'),
        tcp('OUTPUT', '127.0.0.1', '127.0.0.1', '--sport 9222', 'ESTABLISHED', ' -o lo'),
    ];
    const ipv4 = table(rules) + emptyTable('nat', ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING']), ipv6 = table([]) + emptyTable('nat', ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING']);
    return Object.freeze({ ipv4, ipv6, sha256: createHash('sha256').update(ipv4).update('\0').update(ipv6).digest('hex') });
}
function normalizedPolicy(value) {
    if (Buffer.byteLength(value) > 65_536 || value.includes('\0'))
        throw failure();
    return value.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#'))
        .map(line => line.replace(/^(:(?:INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING) (?:DROP|ACCEPT)) \[[0-9]+:[0-9]+\]$/, '$1 [0:0]')
        .replace(/--ctstate ([A-Z,]+)/g, (_, states) => '--ctstate ' + states.split(',').sort().join(','))).join('\n');
}
function savedTables(value) {
    const tables = new Map();
    let name, lines = [];
    for (const line of normalizedPolicy(value).split('\n')) {
        if (!line)
            continue;
        if (line.startsWith('*')) {
            if (name || tables.has(line.slice(1)))
                throw failure();
            name = line.slice(1);
            lines = [line];
        }
        else {
            if (!name)
                throw failure();
            lines.push(line);
            if (line === 'COMMIT') {
                tables.set(name, lines.join('\n'));
                name = undefined;
            }
        }
    }
    if (name)
        throw failure();
    return tables;
}
// Supported backend: explicit x_tables legacy tools, no nftables objects, exact filter and empty NAT.
// Other loaded legacy tables are admitted only with their complete empty built-in ACCEPT chains.
export function verifyBrowserAuditNetworkPolicy(policy, ipv4, ipv6, nftRuleset) {
    if (typeof nftRuleset !== 'string' || nftRuleset.trim() !== '')
        throw failure();
    const optional = new Map([
        ['raw', emptyTable('raw', ['PREROUTING', 'OUTPUT'])],
        ['mangle', emptyTable('mangle', ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'])],
        ['security', emptyTable('security', ['INPUT', 'FORWARD', 'OUTPUT'])],
    ]);
    for (const [expected, actual] of [[policy.ipv4, ipv4], [policy.ipv6, ipv6]]) {
        const required = savedTables(expected), observed = savedTables(actual);
        for (const [name, contents] of required)
            if (observed.get(name) !== contents)
                throw failure();
        for (const [name, contents] of observed) {
            if (!required.has(name) && (!optional.has(name) || normalizedPolicy(optional.get(name)) !== contents))
                throw failure();
        }
    }
}
function validateIdentity(value) {
    if (!value || !hex(value.networkId))
        throw failure();
    for (const container of [value.capsule, value.worker]) {
        if (!container || !hex(container.id) || typeof container.image !== 'string' || !container.image.startsWith('sha256:') || !hex(container.image.slice(7))
            || !Number.isSafeInteger(container.pid) || container.pid <= 1 || !decimal(container.startTicks) || container.running !== true
            || !Number.isSafeInteger(container.restartCount) || container.restartCount < 0 || typeof container.startedAt !== 'string'
            || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(container.startedAt) || !Number.isFinite(Date.parse(container.startedAt))
            || !container.labels || !container.networks || Object.keys(container.labels).length > 64 || Object.keys(container.networks).length > 16)
            throw failure();
        for (const [key, label] of Object.entries(container.labels))
            if (key.length > 256 || typeof label !== 'string' || label.length > 256)
                throw failure();
        for (const [id, addresses] of Object.entries(container.networks)) {
            if (!hex(id) || !addresses || typeof addresses.ipv6 !== 'string' || addresses.ipv6.length > 64)
                throw failure();
            privateIPv4(addresses.ipv4);
        }
        const address = container.networks[value.networkId];
        if (!address || address.ipv6 !== '')
            throw failure();
    }
    const labels = value.capsule.labels;
    if (!uuid(labels['io.ten98.installation']) || !uuid(labels['io.ten98.operation']) || !hex(labels['io.ten98.ownership'])
        || !decimal(labels['io.ten98.generation']) || value.worker.labels['io.ten98.installation'] !== labels['io.ten98.installation']
        || Object.keys(value.capsule.networks).length !== 1 || value.capsule.id === value.worker.id || value.capsule.pid === value.worker.pid)
        throw failure();
    createBrowserAuditNetworkPolicy(value.capsule.networks[value.networkId].ipv4, value.worker.networks[value.networkId].ipv4);
}
function fingerprint(value) {
    const ordered = (record) => Object.fromEntries(Object.entries(record).sort(([a], [b]) => a.localeCompare(b)));
    return JSON.stringify([value.networkId, ...[value.capsule, value.worker].map(c => [c.id, c.image, c.pid, c.startTicks, c.startedAt, c.restartCount, c.running,
            ordered(c.labels), Object.entries(c.networks).sort(([a], [b]) => a.localeCompare(b)).map(([id, a]) => [id, a.ipv4, a.ipv6])])]);
}
function stamp(stat) { return { dev: String(stat.dev), ino: String(stat.ino) }; }
function nativeExecute(command) {
    const tool = command.args[2];
    if (!['/usr/sbin/iptables-legacy-restore', '/usr/sbin/ip6tables-legacy-restore', '/usr/sbin/iptables-legacy-save', '/usr/sbin/ip6tables-legacy-save', '/usr/sbin/nft'].includes(tool ?? ''))
        throw failure();
    const restore = tool.endsWith('-restore');
    if (command.executable !== '/usr/bin/nsenter' || command.shell !== false || command.timeoutMs !== 2000 || command.maxOutputBytes !== 65536
        || !Number.isSafeInteger(command.fd) || command.fd < 3 || typeof command.input !== 'string' || Buffer.byteLength(command.input) > 4096
        || (!restore && command.input !== '') || JSON.stringify(command.args) !== JSON.stringify(['--net=/proc/self/fd/3', '--', tool, ...(tool === '/usr/sbin/nft' ? ['-n', 'list', 'ruleset'] : restore ? ['--wait', '2'] : [])]))
        throw failure();
    const target = stamp(fstatSync(command.fd, { bigint: true }));
    if (['self', '1'].some(pid => equalNamespace(target, stamp(statSync(`/proc/${pid}/ns/net`, { bigint: true })))))
        throw failure();
    return new Promise((resolve, reject) => {
        const child = spawn(command.executable, [...command.args], { shell: false, windowsHide: true,
            env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' }, stdio: ['pipe', 'pipe', 'pipe', command.fd] });
        let failed = false, bytes = 0;
        const chunks = [];
        const fail = () => { failed = true; child.kill('SIGKILL'); };
        const timer = setTimeout(fail, command.timeoutMs);
        child.on('error', () => { clearTimeout(timer); reject(failure()); });
        child.stdout.on('data', (chunk) => { bytes += chunk.length; if (bytes > command.maxOutputBytes)
            fail();
        else
            chunks.push(chunk); });
        child.stderr.on('data', (chunk) => { bytes += chunk.length; if (bytes > command.maxOutputBytes)
            fail(); });
        child.stdin.on('error', fail);
        child.once('close', code => { clearTimeout(timer); if (failed || code !== 0)
            reject(failure());
        else
            resolve(Buffer.concat(chunks).toString('utf8')); });
        child.stdin.end(command.input);
    });
}
/** Native filesystem/process adapter; constructing it performs no host operation. */
export function createBrowserAuditNetworkAdapter(inspect) {
    const linux = () => { if (process.platform !== 'linux')
        throw failure(); };
    return {
        inspect,
        processStart(pid) {
            linux();
            const raw = readFileSync(`/proc/${pid}/stat`, 'utf8');
            const end = raw.lastIndexOf(')');
            if (end < 0)
                throw failure();
            const start = raw.slice(end + 2).trim().split(/\s+/)[19];
            if (!decimal(start))
                throw failure();
            return start;
        },
        namespace(pid) { linux(); return stamp(statSync(`/proc/${pid}/ns/net`, { bigint: true })); },
        openNamespace(pid) { linux(); return openSync(`/proc/${pid}/ns/net`, constants.O_RDONLY); },
        descriptor(fd) { linux(); return stamp(fstatSync(fd, { bigint: true })); },
        close(fd) { closeSync(fd); },
        execute(command) { linux(); return nativeExecute(command); },
    };
}
/** The passive gate must remain closed until apply() and the caller's final verify() both succeed. */
export async function pinBrowserAuditNetwork(expected, adapter) {
    const identity = structuredClone(expected);
    validateIdentity(identity);
    const expectedFingerprint = fingerprint(identity);
    const policy = createBrowserAuditNetworkPolicy(identity.capsule.networks[identity.networkId].ipv4, identity.worker.networks[identity.networkId].ipv4);
    let fd, pinned, closed = false, busy = false;
    function close() {
        if (busy)
            throw failure();
        if (!closed) {
            closed = true;
            if (fd !== undefined)
                adapter.close(fd);
        }
    }
    async function check() {
        if (closed)
            throw failure();
        const controller = new AbortController();
        let timer;
        const observed = await Promise.race([Promise.resolve().then(() => adapter.inspect(controller.signal)), new Promise((_, reject) => {
                timer = setTimeout(() => { controller.abort(); reject(failure()); }, 2000);
            })]).finally(() => clearTimeout(timer));
        validateIdentity(observed);
        if (fingerprint(observed) !== expectedFingerprint)
            throw failure();
        for (const c of [identity.capsule, identity.worker])
            if (adapter.processStart(c.pid) !== c.startTicks)
                throw failure();
        const capsule = namespaceIdentity(adapter.namespace(identity.capsule.pid));
        for (const pid of ['self', 1, identity.worker.pid])
            if (equalNamespace(capsule, namespaceIdentity(adapter.namespace(pid))))
                throw failure();
        if (pinned && (!equalNamespace(capsule, pinned) || fd === undefined || !equalNamespace(namespaceIdentity(adapter.descriptor(fd)), pinned)))
            throw failure();
        return capsule;
    }
    try {
        pinned = { ...await check() };
        fd = adapter.openNamespace(identity.capsule.pid);
        if (!Number.isSafeInteger(fd) || fd < 3) {
            const invalid = fd;
            fd = undefined;
            if (Number.isSafeInteger(invalid) && invalid >= 0)
                adapter.close(invalid);
            throw failure();
        }
        await check();
    }
    catch {
        close();
        throw failure();
    }
    async function command(tool, input = '') {
        await check();
        const restore = tool.endsWith('-restore');
        const output = await adapter.execute(Object.freeze({ executable: '/usr/bin/nsenter',
            args: Object.freeze(['--net=/proc/self/fd/3', '--', `/usr/sbin/${tool}`, ...(tool === 'nft' ? ['-n', 'list', 'ruleset'] : restore ? ['--wait', '2'] : [])]),
            fd: fd, input, environment: Object.freeze({ PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' }),
            timeoutMs: 2000, maxOutputBytes: 65536, shell: false }));
        if (typeof output !== 'string' || Buffer.byteLength(output) > 65_536)
            throw failure();
        await check();
        return output;
    }
    async function perform(restore) {
        if (closed || busy)
            throw failure();
        busy = true;
        try {
            if (restore) {
                if ((await command('nft')).trim() !== '')
                    throw failure();
                await command('iptables-legacy-restore', policy.ipv4);
                await command('ip6tables-legacy-restore', policy.ipv6);
            }
            const ipv4 = await command('iptables-legacy-save'), ipv6 = await command('ip6tables-legacy-save');
            verifyBrowserAuditNetworkPolicy(policy, ipv4, ipv6, await command('nft'));
            await check();
            return { policySha256: policy.sha256, namespace: { ...pinned } };
        }
        catch {
            busy = false;
            close();
            throw failure();
        }
        finally {
            busy = false;
        }
    }
    return { policy, apply: () => perform(true), verify: () => perform(false), close };
}
