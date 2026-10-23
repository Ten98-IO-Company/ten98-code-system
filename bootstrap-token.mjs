// Ported from Ten98 Campaign (MIT), server/auth.ts storedSecret/bootstrapToken: a host-held first-boot token,
// generated once into the data directory when the operator sets none. Apps keep the claim transaction, rate limit,
// setup routes and the rule that the token is accepted only while the installation is unclaimed.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
/** File name of the generated token inside the app's data directory. */
export const BOOTSTRAP_TOKEN_FILE = 'bootstrap-token';
/** The shared token rule: 32 to 512 characters with no whitespace. */
export function isValidBootstrapToken(value) {
    return typeof value === 'string' && value.length >= 32 && value.length <= 512 && !/\s/u.test(value);
}
const invalid = (message) => Object.assign(new Error(message), { code: 'BOOTSTRAP_TOKEN_INVALID' });
/**
 * Returns the operator's `BOOTSTRAP_TOKEN` when set, otherwise the token saved in `<dataDir>/bootstrap-token`,
 * creating it exclusively with mode 0600 on first use (a concurrent creator's file wins). An invalid configured or
 * saved token throws with `code: 'BOOTSTRAP_TOKEN_INVALID'`; it is never replaced silently.
 */
export function loadBootstrapToken(dataDir, provided) {
    if (provided) {
        if (!isValidBootstrapToken(provided))
            throw invalid('BOOTSTRAP_TOKEN must contain 32 to 512 non-whitespace characters.');
        return { token: provided, source: 'environment' };
    }
    const path = join(dataDir, BOOTSTRAP_TOKEN_FILE);
    try {
        const token = readFileSync(path, 'utf8').trim();
        if (!isValidBootstrapToken(token))
            throw invalid(`The saved ${BOOTSTRAP_TOKEN_FILE} file is invalid.`);
        return { token, source: 'file', path };
    }
    catch (error) {
        if (error.code !== 'ENOENT')
            throw error;
    }
    const token = randomBytes(48).toString('base64url');
    try {
        writeFileSync(path, token, { flag: 'wx', mode: 0o600 });
        return { token, source: 'generated', path };
    }
    catch (error) {
        if (error.code === 'EEXIST')
            return loadBootstrapToken(dataDir);
        throw error;
    }
}
/** Compares a submitted token with the expected one in constant time, whatever their lengths. */
export function bootstrapTokenMatches(expected, supplied) {
    if (!isValidBootstrapToken(expected) || typeof supplied !== 'string' || supplied.length > 512)
        return false;
    const digest = (value) => createHash('sha256').update(value, 'utf8').digest();
    return timingSafeEqual(digest(expected), digest(supplied)) && isValidBootstrapToken(supplied);
}
