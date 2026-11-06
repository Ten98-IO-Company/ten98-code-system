import { createHash, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { runCapsule } from './browser-audit-capsule.mjs';
/** Trusted process entry: the host alone supplies readiness through stdin after verifying isolation. */
export function runBrowserAuditLauncherGate(options = {}) {
    const input = options.input ?? process.stdin;
    const environment = options.environment ?? process.env;
    const run = options.run ?? runCapsule;
    const terminate = options.terminate ?? ((released) => {
        if (released)
            process.kill(process.pid, 'SIGTERM');
        else
            process.exit(1);
    });
    const forceExit = options.forceExit ?? (() => process.exit(1));
    const digest = environment.TEN98_CAPSULE_START_SHA256;
    // runCapsule copies its environment into Chromium; no start configuration may survive admission.
    for (const key of Object.keys(environment))
        if (key.startsWith('TEN98_CAPSULE_START_'))
            delete environment[key];
    let phase = 'waiting';
    const frame = Buffer.alloc(65);
    let size = 0;
    let waitTimer;
    let stopTimer;
    let hardTimer;
    let failureTimer;
    function detach() {
        input.off('data', receive);
        input.off('end', fail);
        input.off('close', fail);
        // Retain the error handler for late stream errors while the capsule shuts down.
        input.pause();
        frame.fill(0);
    }
    function force() {
        clearTimeout(waitTimer);
        clearTimeout(stopTimer);
        clearTimeout(hardTimer);
        clearTimeout(failureTimer);
        phase = 'failed';
        detach();
        forceExit();
    }
    function fail() {
        if (phase === 'failed')
            return;
        const released = phase === 'released';
        phase = 'failed';
        detach();
        clearTimeout(waitTimer);
        clearTimeout(stopTimer);
        if (released)
            failureTimer = setTimeout(force, 4_000);
        else
            clearTimeout(hardTimer);
        try {
            terminate(released);
        }
        catch {
            force();
        }
    }
    function receive(chunk) {
        if (phase !== 'waiting' || !Buffer.isBuffer(chunk) || chunk.length > frame.length - size)
            return fail();
        chunk.copy(frame, size);
        size += chunk.length;
        for (let index = 0; index < Math.min(size, 64); index++) {
            const byte = frame[index];
            if (!(byte >= 48 && byte <= 57) && !(byte >= 97 && byte <= 102))
                return fail();
        }
        if (size !== 65)
            return;
        if (frame[64] !== 10 || !timingSafeEqual(createHash('sha256').update(frame.subarray(0, 64)).digest(), Buffer.from(digest, 'hex')))
            return fail();
        phase = 'released';
        frame.fill(0);
        clearTimeout(waitTimer);
        // Resolution means ready, not finished: lifetime timers and stdin failure monitoring stay armed.
        try {
            void run().then(() => { if (process.exitCode)
                fail(); }, fail);
        }
        catch {
            fail();
        }
    }
    input.on('error', fail);
    if (typeof digest !== 'string' || digest.length !== 64 || !/^[a-f0-9]+$/.test(digest)
        || input.destroyed || input.readableEnded) {
        fail();
    }
    else {
        waitTimer = setTimeout(fail, 30_000);
        // Allow the capsule's three-second forced cleanup to finish before the hard process deadline.
        stopTimer = setTimeout(fail, 176_000);
        hardTimer = setTimeout(force, 180_000);
        input.on('end', fail);
        input.on('close', fail);
        input.on('data', receive);
    }
    return { get phase() { return phase; } };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
    runBrowserAuditLauncherGate();
