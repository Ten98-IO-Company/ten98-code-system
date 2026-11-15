import { type HydrationOptions } from 'react-dom/client';
import { type AnyRequestMiddleware } from '@tanstack/react-start';
/**
 * An error whose message is written for the person using the app. Its message is the only part of it that reaches the
 * browser, where it arrives as a PublicError; a cause, the stack and any other field stay on the server.
 */
export declare class PublicError extends Error {
    name: string;
}
/**
 * Receives each server error that is replaced for the browser, with the reference the browser shows. It may be async;
 * when it throws or its promise rejects, the error goes to the default server log line instead.
 */
export type ServerErrorReporter = (error: Error, details: {
    reference: string;
}) => void | PromiseLike<void>;
export interface Ten98StartOptions<TMiddleware extends readonly AnyRequestMiddleware[]> {
    /** Replaces the default server log line, `console.error('Error reference <id>:', error)`. */
    reporter?: ServerErrorReporter;
    /** The app's own request middleware, run after the CSRF middleware, which cannot be removed or replaced. */
    requestMiddleware?: TMiddleware;
}
type ErrorWire = {
    reference: string;
} | {
    public: string;
};
declare const csrfMiddleware: () => import("@tanstack/react-start").RequestMiddlewareAfterServer<{}, undefined, undefined>;
/**
 * The text an error component may show. An errorComponent also renders on the server with the original error, so it
 * shows this, never `error.message`: a PublicError's message, the fixed sentence with the reference for an error the
 * browser received as a reference, and the fixed sentence alone for anything else, the server's originals included.
 * It always returns a string.
 */
export declare function publicErrorMessage(error: unknown): string;
/**
 * The options for `createStart(() => ten98StartOptions(...))` in src/start.ts. Every Error that crosses to the
 * browser, from a beforeLoad, a loader or a server function, crosses as a reference only and is logged in full on the
 * server; a PublicError crosses as its message only. Server functions keep Start's CSRF check.
 */
export declare function ten98StartOptions<const TMiddleware extends readonly AnyRequestMiddleware[] = []>({ reporter, requestMiddleware }?: Ten98StartOptions<TMiddleware>): {
    serializationAdapters: readonly [import("@tanstack/react-router").SerializationAdapter<Error, ErrorWire, never>];
    requestMiddleware: readonly [ReturnType<typeof csrfMiddleware>, ...TMiddleware];
};
/** Receives each error React reports in the browser, in production as well as development. It may be async. */
export type ClientErrorReporter = (error: unknown, details: {
    kind: 'caught' | 'uncaught' | 'recoverable';
    componentStack?: string;
}) => void | PromiseLike<void>;
type RootErrorOptions = Required<Pick<HydrationOptions, 'onCaughtError' | 'onUncaughtError' | 'onRecoverableError'>>;
/**
 * React's root error callbacks. In development they log the error and its component stack; in production they write
 * nothing to the console. The reporter, when given, receives every error in both.
 */
export declare function ten98RootErrorOptions({ reporter, development }?: {
    reporter?: ClientErrorReporter;
    development?: boolean;
}): RootErrorOptions;
/** Start's default client entry with the root error callbacks above. Call it once from src/client.tsx. */
export declare function hydrateTen98Start({ reporter }?: {
    reporter?: ClientErrorReporter;
}): void;
export {};
