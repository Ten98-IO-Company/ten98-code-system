import { createHash, timingSafeEqual } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
export function createCapsuleCloseIntent(capability) {
    if (!/^[a-f0-9]{64}$/.test(capability))
        throw new Error('close-capability-invalid');
    let phase = 'active';
    let deadline = 0;
    return {
        get phase() { return phase; },
        prepare(provided, identity, expected, connections, now = Date.now()) {
            if (phase !== 'active')
                throw new Error('close-intent-replayed');
            if (typeof provided !== 'string' || !/^[a-f0-9]{64}$/.test(provided)
                || !timingSafeEqual(Buffer.from(capability), Buffer.from(provided)))
                throw new Error('close-capability-rejected');
            if (!expected || identity !== expected)
                throw new Error('close-browser-rejected');
            if (connections !== 1)
                throw new Error('close-tunnel-rejected');
            phase = 'armed';
            deadline = now + 3000;
        },
        disconnected(now = Date.now()) { return phase === 'armed' && now < deadline; },
        exit(code, signal, now = Date.now()) {
            const success = phase === 'armed' && now < deadline && code === 0 && signal === null;
            phase = success ? 'exited' : 'failed';
            return success;
        },
        fail() { phase = 'failed'; },
    };
}
export async function runCapsule() {
    // Validate before creating a profile, opening a listener or launching Chromium.
    let intent;
    try {
        intent = createCapsuleCloseIntent(process.env.TEN98_CAPSULE_CLOSE_CAPABILITY ?? '');
    }
    catch {
        console.log(JSON.stringify({ state: 'stopped', reason: 'close-capability-invalid', phase: 'startup', code: null, signal: null }));
        process.exitCode = 1;
        return;
    }
    let observedCode = null;
    let observedSignal = null;
    const headerLimit = 16 * 1024;
    const sockets = new Set();
    const requests = new Set();
    const tunnels = new Set();
    let browser;
    let profilePath;
    let launchPending = true;
    let ready = false;
    let stopping = false;
    let closing = false;
    let operationStarted = false;
    let controlRequests = 0;
    let acceptedConnections = 0;
    let browserPath = '';
    let versionPayload = '';
    let watchdog;
    let completionTimer;
    let forceTimer;
    let finalReason = '';
    let finalCode = 0;
    const server = createServer({ maxHeaderSize: headerLimit, headersTimeout: 5_000, requestTimeout: 5_000 }, handleControl);
    server.maxConnections = 36;
    server.keepAliveTimeout = 1_000;
    server.on('connection', (socket) => {
        trackSocket(socket);
        socket.setTimeout(5_000, () => socket.destroy());
    });
    server.on('clientError', (_error, socket) => socket.destroy());
    server.on('error', () => stop('proxy-failure', 1));
    server.on('upgrade', handleUpgrade);
    function trackSocket(socket) {
        sockets.add(socket);
        socket.on('error', () => socket.destroy());
        socket.once('close', () => sockets.delete(socket));
    }
    function trackRequest(outgoing) {
        requests.add(outgoing);
        outgoing.once('close', () => requests.delete(outgoing));
        outgoing.once('socket', trackSocket);
    }
    function hasBody(incoming) {
        return incoming.headers['transfer-encoding'] !== undefined
            || (incoming.headers['content-length'] !== undefined && incoming.headers['content-length'] !== '0');
    }
    function reply(response, status, payload) {
        response.writeHead(status, {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'Cache-Control': 'no-store',
            Connection: 'close',
        });
        response.end(payload);
    }
    function handleControl(incoming, response) {
        const healthProbe = incoming.method === 'GET' && incoming.url === '/health' && !hasBody(incoming);
        if (!healthProbe && ++controlRequests > 32)
            return reply(response, 429, '{"error":"request-limit"}');
        if (incoming.method === 'POST' && incoming.url === '/control/prepare-close') {
            if (hasBody(incoming))
                return reply(response, 400, '{"error":"body"}');
            if (!ready || closing || stopping || !browser || browser.exitCode !== null || browser.signalCode !== null)
                return reply(response, 409, '{"error":"state"}');
            try {
                const authorization = incoming.headers.authorization;
                intent.prepare(typeof authorization === 'string' && authorization.startsWith('Bearer ') ? authorization.slice(7) : undefined, incoming.headers['x-ten98-browser-path'], browserPath, acceptedConnections);
            }
            catch {
                return reply(response, 403, '{"error":"close-rejected"}');
            }
            closing = true;
            completionTimer = setTimeout(() => stop('close-deadline', 1), 3000);
            return reply(response, 200, '{"prepared":true}');
        }
        if (incoming.method !== 'GET' || hasBody(incoming))
            return reply(response, 405, '{"error":"method"}');
        if (incoming.url !== '/health' && incoming.url !== '/json/version')
            return reply(response, 404, '{"error":"path"}');
        if (!ready || closing || stopping)
            return reply(response, 503, '{"ready":false}');
        reply(response, 200, incoming.url === '/health' ? '{"ready":true}' : versionPayload);
    }
    function rejectUpgrade(socket, status) {
        socket.end(`HTTP/1.1 ${status} Rejected\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    }
    function isUpgrade(headers) {
        return headers.upgrade?.toLowerCase() === 'websocket'
            && (headers.connection ?? '').toLowerCase().split(',').some((part) => part.trim() === 'upgrade');
    }
    function handleUpgrade(incoming, downstream, head) {
        if (!ready || stopping || closing)
            return rejectUpgrade(downstream, 503);
        if (incoming.method !== 'GET' || incoming.url !== browserPath || hasBody(incoming))
            return rejectUpgrade(downstream, 404);
        if (operationStarted || tunnels.size >= 1)
            return rejectUpgrade(downstream, 429);
        const key = incoming.headers['sec-websocket-key'];
        if (!isUpgrade(incoming.headers) || incoming.headers['sec-websocket-version'] !== '13'
            || typeof key !== 'string' || !/^[A-Za-z0-9+/]{22}==$/.test(key)
            || Buffer.from(key, 'base64').toString('base64') !== key || head.length > headerLimit) {
            return rejectUpgrade(downstream, 400);
        }
        tunnels.add(downstream);
        let accepted = false;
        let upstream;
        let handshakeTimer;
        const headers = {
            Host: 'localhost:9222',
            Connection: 'Upgrade',
            Upgrade: 'websocket',
            'Sec-WebSocket-Key': key,
            'Sec-WebSocket-Version': '13',
        };
        for (const name of ['sec-websocket-protocol', 'sec-websocket-extensions']) {
            const value = incoming.headers[name];
            if (typeof value === 'string')
                headers[name] = value;
        }
        const outgoing = request({
            host: '127.0.0.1', port: 9222, path: browserPath, method: 'GET',
            headers, agent: false, maxHeaderSize: headerLimit,
        });
        trackRequest(outgoing);
        const fail = () => {
            clearTimeout(handshakeTimer);
            outgoing.destroy();
            upstream?.destroy();
            downstream.destroy();
        };
        handshakeTimer = setTimeout(fail, 5_000);
        downstream.once('close', () => {
            tunnels.delete(downstream);
            clearTimeout(handshakeTimer);
            outgoing.destroy();
            upstream?.destroy();
            if (accepted) {
                acceptedConnections -= 1;
                if (acceptedConnections === 0 && !stopping) {
                    // Closing is permanent: reconnecting must not turn one capsule into a new job.
                    closing = true;
                    for (const pending of tunnels)
                        pending.destroy();
                    if (!intent.disconnected())
                        stop('unprepared-disconnect', 1);
                }
            }
        });
        outgoing.once('error', fail);
        outgoing.once('response', (response) => {
            response.destroy();
            fail();
        });
        outgoing.once('upgrade', (response, socket, upstreamHead) => {
            clearTimeout(handshakeTimer);
            upstream = socket;
            const expectedAccept = createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
            if (stopping || closing || downstream.destroyed || response.statusCode !== 101
                || !isUpgrade(response.headers) || response.headers['sec-websocket-accept'] !== expectedAccept
                || upstreamHead.length > headerLimit)
                return fail();
            const responseHeaders = [
                'HTTP/1.1 101 Switching Protocols', 'Connection: Upgrade', 'Upgrade: websocket',
                `Sec-WebSocket-Accept: ${expectedAccept}`,
            ];
            for (const name of ['sec-websocket-protocol', 'sec-websocket-extensions']) {
                const value = response.headers[name];
                if (typeof value === 'string')
                    responseHeaders.push(`${name}: ${value}`);
            }
            accepted = true;
            acceptedConnections += 1;
            if (!operationStarted) {
                operationStarted = true;
                watchdog = setTimeout(() => stop('deadline', 1), 120_000);
            }
            downstream.setTimeout(0);
            socket.setTimeout(0);
            socket.once('close', () => downstream.destroy());
            downstream.write(`${responseHeaders.join('\r\n')}\r\n\r\n`);
            if (upstreamHead.length)
                downstream.write(upstreamHead);
            if (head.length)
                socket.write(head);
            socket.pipe(downstream);
            downstream.pipe(socket);
        });
        outgoing.end();
    }
    function readVersion(timeoutMs = 5_000) {
        return new Promise((resolve, reject) => {
            const chunks = [];
            let size = 0;
            const outgoing = request({
                host: '127.0.0.1', port: 9222, path: '/json/version', method: 'GET',
                headers: { Host: '127.0.0.1:9222', Connection: 'close' },
                agent: false, maxHeaderSize: headerLimit,
            });
            trackRequest(outgoing);
            const fail = () => {
                outgoing.destroy();
                reject(new Error('version-unavailable'));
            };
            const timer = setTimeout(fail, timeoutMs);
            outgoing.once('error', fail);
            outgoing.once('close', () => clearTimeout(timer));
            outgoing.once('response', (response) => {
                if (response.statusCode !== 200)
                    return fail();
                response.on('error', fail);
                response.on('data', (chunk) => {
                    size += chunk.length;
                    if (size > 2_048)
                        return fail();
                    chunks.push(chunk);
                });
                response.once('end', () => {
                    try {
                        const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
                        if (payload === null || typeof payload !== 'object' || Array.isArray(payload)
                            || !('webSocketDebuggerUrl' in payload) || typeof payload.webSocketDebuggerUrl !== 'string')
                            throw new Error();
                        const match = /^ws:\/\/127\.0\.0\.1:9222(\/devtools\/browser\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/.exec(payload.webSocketDebuggerUrl);
                        if (!match)
                            throw new Error();
                        browserPath = match[1];
                        payload.webSocketDebuggerUrl = `ws://browser:9223${browserPath}`;
                        versionPayload = JSON.stringify(payload);
                        resolve();
                    }
                    catch {
                        fail();
                    }
                });
            });
            outgoing.end();
        });
    }
    function signalBrowser(signal) {
        if (!browser?.pid)
            return;
        try {
            // Chromium's descendants share this capsule-owned, detached process group.
            process.kill(-browser.pid, signal);
        }
        catch (error) {
            if (!(error instanceof Error && 'code' in error && error.code === 'ESRCH')) {
                finalCode = 1;
                finalReason = 'cleanup-failure';
                intent.fail();
                browser.kill(signal);
            }
        }
    }
    function finish() {
        clearTimeout(forceTimer);
        signalBrowser('SIGKILL');
        if (profilePath) {
            try {
                rmSync(profilePath, { recursive: true, force: true });
            }
            catch {
                finalCode = 1;
                finalReason = 'cleanup-failure';
                intent.fail();
            }
        }
        console.log(JSON.stringify({ state: 'stopped', reason: finalReason, phase: intent.phase, code: observedCode, signal: observedSignal }));
        process.exit(finalCode);
    }
    function closeBrowser() {
        if (!browser?.pid || browser.exitCode !== null || browser.signalCode !== null) {
            if (!launchPending)
                finish();
            return;
        }
        signalBrowser('SIGTERM');
    }
    function stop(reason, code) {
        if (stopping)
            return;
        stopping = true;
        ready = false;
        finalReason = reason;
        finalCode = code;
        if (code !== 0)
            intent.fail();
        clearTimeout(watchdog);
        clearTimeout(completionTimer);
        server.close();
        for (const outgoing of requests)
            outgoing.destroy();
        for (const socket of sockets)
            socket.destroy();
        forceTimer = setTimeout(() => {
            finalCode = 1;
            finish();
        }, 3_000);
        closeBrowser();
    }
    process.once('SIGTERM', () => stop('terminated', 1));
    process.once('SIGINT', () => stop('interrupted', 1));
    async function waitForVersion() {
        const deadline = Date.now() + 30_000;
        for (let attempt = 0; attempt < 100 && !stopping; attempt += 1) {
            const remaining = deadline - Date.now();
            if (remaining <= 0)
                break;
            try {
                await readVersion(Math.min(5_000, remaining));
                return;
            }
            catch {
                if (stopping || Date.now() >= deadline)
                    break;
                await delay(Math.min(300, deadline - Date.now()));
            }
        }
        throw new Error('version-unavailable');
    }
    try {
        profilePath = mkdtempSync('/tmp/ten98-capsule-process-only-');
        const browserEnvironment = { ...process.env };
        delete browserEnvironment.TEN98_CAPSULE_CLOSE_CAPABILITY;
        browser = spawn('/ms-playwright/chromium-1248/chrome-linux64/chrome', [
            // Captured from the frozen capsule; only the profile path and CDP pipe differ.
            '--disable-field-trial-config',
            '--disable-background-networking',
            '--disable-background-timer-throttling',
            '--disable-backgrounding-occluded-windows',
            '--disable-back-forward-cache',
            '--disable-breakpad',
            '--disable-client-side-phishing-detection',
            '--disable-component-extensions-with-background-pages',
            '--disable-component-update',
            '--no-default-browser-check',
            '--disable-default-apps',
            '--disable-dev-shm-usage',
            '--disable-edgeupdater',
            '--disable-extensions',
            '--disable-features=AvoidUnnecessaryBeforeUnloadCheckSync,DestroyProfileOnBrowserClose,DialMediaRouteProvider,GlobalMediaControls,HttpsUpgrades,LensOverlay,MediaRouter,PaintHolding,ThirdPartyStoragePartitioning,BlockOriginHeaderModificationOnRedirect,AvoidCorsURLLoaderRestartOnRedirect,Translate,AutoDeElevate,OptimizationHints,NetworkTimeServiceQuerying,AimEnabled,msForceBrowserSignIn,msEdgeUpdateLaunchServicesPreferredVersion',
            '--enable-features=CDPScreenshotNewSurface',
            '--allow-pre-commit-input',
            '--disable-hang-monitor',
            '--disable-ipc-flooding-protection',
            '--disable-popup-blocking',
            '--disable-prompt-on-repost',
            '--disable-renderer-backgrounding',
            '--disable-updater-scheduler',
            '--force-color-profile=srgb',
            '--metrics-recording-only',
            '--no-first-run',
            '--password-store=basic',
            '--use-mock-keychain',
            '--no-service-autorun',
            '--export-tagged-pdf',
            '--disable-search-engine-choice-screen',
            '--unsafely-disable-devtools-self-xss-warnings',
            '--edge-skip-compat-layer-relaunch',
            '--disable-infobars',
            '--disable-search-engine-choice-screen',
            '--disable-sync',
            '--enable-unsafe-swiftshader',
            '--headless',
            '--hide-scrollbars',
            '--mute-audio',
            '--blink-settings=primaryHoverType=2,availableHoverTypes=2,primaryPointerType=4,availablePointerTypes=4',
            '--remote-debugging-address=127.0.0.1',
            '--remote-debugging-port=9222',
            '--proxy-server=http://worker:3138',
            '--proxy-bypass-list=<-loopback>',
            `--user-data-dir=${profilePath}`,
            '--no-startup-window',
        ], {
            env: browserEnvironment,
            detached: true,
            windowsHide: true,
            stdio: ['ignore', 'ignore', 'pipe'],
        });
        // Drain browser stderr without retaining or forwarding unbounded output.
        browser.stderr?.resume();
        browser.once('error', () => stop('startup-failure', 1));
        browser.once('exit', (code, signal) => {
            observedCode = code;
            observedSignal = signal;
            if (stopping)
                finish();
            else
                stop(intent.exit(code, signal) ? 'completed' : 'browser-exit', intent.phase === 'exited' ? 0 : 1);
        });
        launchPending = false;
        if (stopping) {
            closeBrowser();
        }
        else {
            await waitForVersion();
            if (!stopping) {
                await new Promise((resolve, reject) => {
                    server.once('error', reject);
                    server.listen(9223, '0.0.0.0', () => {
                        server.off('error', reject);
                        resolve();
                    });
                });
                ready = true;
                console.log('{"state":"ready"}');
            }
        }
    }
    catch {
        launchPending = false;
        if (stopping)
            closeBrowser();
        else
            stop('startup-failure', 1);
    }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
    await runCapsule();
