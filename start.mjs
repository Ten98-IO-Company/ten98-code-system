// The shared error and CSRF defaults for TanStack Start apps; exported as @ten98/runtime/start only. Every Start app
// calls ten98StartOptions once from src/start.ts and hydrateTen98Start once from src/client.tsx, and the architecture
// check refuses an app that does not. Needs the optional @tanstack/react-start, @tanstack/react-router, react and
// react-dom peers. src/start.ts is bundled for the browser too, so nothing here imports a server-only Start module.
import { StrictMode, createElement, startTransition } from 'react';
import { hydrateRoot } from 'react-dom/client';
import { createSerializationAdapter } from '@tanstack/react-router';
import { createCsrfMiddleware } from '@tanstack/react-start';
import { StartClient } from '@tanstack/react-start/client';
/**
 * An error whose message is written for the person using the app. Its message is the only part of it that reaches the
 * browser, where it arrives as a PublicError; a cause, the stack and any other field stay on the server.
 */
export class PublicError extends Error {
    name = 'PublicError';
}
// Start's own default, which it applies only when an app has no start instance: server functions answer a
// cross-origin request with 403.
const csrfMiddleware = createCsrfMiddleware({ filter: context => context.handlerType === 'serverFn' });
const references = new WeakMap();
const REFERENCE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
// One reference and one log line per error object, however often Start serialises it. Start gives a request no id, so
// each error gets a fresh UUID. This is the hook for ./log (#142): its requestId(request) replaces the UUID here, read
// through a server-only function, because a static import of Start's server module would reach the browser bundle.
function referenceFor(error, reporter) {
    let reference = references.get(error);
    if (reference)
        return reference;
    reference = crypto.randomUUID();
    references.set(error, reference);
    try {
        if (reporter)
            reporter(error, { reference });
        else
            console.error(`Error reference ${reference}:`, error);
    }
    catch {
        // A failing reporter must not break the response; the error still reaches the server log.
        try {
            console.error(`Error reference ${reference}:`, error);
        }
        catch { /* nothing left to log with */ }
    }
    return reference;
}
/** What the browser receives in place of an error that is not a PublicError. */
function referencedError(reference) {
    const shown = typeof reference === 'string' && REFERENCE.test(reference) ? reference : 'unavailable';
    return Object.assign(new Error(`Something went wrong. Reference ${shown}.`), { name: 'Error', reference: shown });
}
/**
 * The text an error component may show. An errorComponent also renders on the server with the original error, so it
 * shows this, never `error.message`: a PublicError's message, the fixed sentence with the reference for an error the
 * browser received as a reference, and the fixed sentence alone for anything else, the server's originals included.
 */
export function publicErrorMessage(error) {
    if (error instanceof PublicError)
        return error.message;
    const reference = error instanceof Error ? error.reference : undefined;
    return typeof reference === 'string' && REFERENCE.test(reference) ? `Something went wrong. Reference ${reference}.` : 'Something went wrong.';
}
/**
 * The options for `createStart(() => ten98StartOptions(...))` in src/start.ts. Every Error that crosses to the
 * browser, from a beforeLoad, a loader or a server function, crosses as a reference only and is logged in full on the
 * server; a PublicError crosses as its message only. Server functions keep Start's CSRF check.
 */
export function ten98StartOptions({ reporter, requestMiddleware } = {}) {
    const errorAdapter = createSerializationAdapter({
        key: 'ten98/error',
        test: (value) => value instanceof Error,
        toSerializable: (error) => error instanceof PublicError ? { public: String(error.message) } : { reference: referenceFor(error, reporter) },
        fromSerializable: (wire) => {
            const { public: message, reference } = (wire ?? {});
            return typeof message === 'string' ? new PublicError(message) : referencedError(reference);
        },
    });
    return {
        serializationAdapters: [errorAdapter],
        requestMiddleware: [csrfMiddleware, ...requestMiddleware ?? []],
    };
}
/**
 * React's root error callbacks. In development they log the error and its component stack; in production they write
 * nothing to the console. The reporter, when given, receives every error in both.
 */
export function ten98RootErrorOptions({ reporter, development = process.env.NODE_ENV !== 'production' } = {}) {
    const handle = (kind) => (error, info) => {
        if (development)
            console.error(`React ${kind} error:`, error, info?.componentStack ?? '');
        try {
            reporter?.(error, { kind, componentStack: info?.componentStack });
        }
        catch { /* a failing reporter stays silent */ }
    };
    return { onCaughtError: handle('caught'), onUncaughtError: handle('uncaught'), onRecoverableError: handle('recoverable') };
}
/** Start's default client entry with the root error callbacks above. Call it once from src/client.tsx. */
export function hydrateTen98Start({ reporter } = {}) {
    startTransition(() => {
        hydrateRoot(document, createElement(StrictMode, null, createElement(StartClient)), ten98RootErrorOptions({ reporter }));
    });
}
