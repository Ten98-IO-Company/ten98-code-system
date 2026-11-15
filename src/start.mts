// The shared error and CSRF defaults for TanStack Start apps; exported as @ten98/runtime/start only. Every Start app
// calls ten98StartOptions once from src/start.ts and hydrateTen98Start once from src/client.tsx, and the architecture
// check refuses an app that does not. Needs the optional @tanstack/react-start, @tanstack/react-router, react and
// react-dom peers. src/start.ts is bundled for the browser too, so nothing here imports a server-only Start module.
import { StrictMode, createElement, startTransition } from 'react';
import { hydrateRoot, type HydrationOptions } from 'react-dom/client';
import { createSerializationAdapter } from '@tanstack/react-router';
import { createCsrfMiddleware, type AnyRequestMiddleware } from '@tanstack/react-start';
import { StartClient } from '@tanstack/react-start/client';

/**
 * An error whose message is written for the person using the app. Its message is the only part of it that reaches the
 * browser, where it arrives as a PublicError; a cause, the stack and any other field stay on the server.
 */
export class PublicError extends Error {
  override name = 'PublicError';
}

/**
 * Receives each server error that is replaced for the browser, with the reference the browser shows. It may be async;
 * when it throws or its promise rejects, the error goes to the default server log line instead.
 */
export type ServerErrorReporter = (error: Error, details: { reference: string }) => void | PromiseLike<void>;

export interface Ten98StartOptions<TMiddleware extends readonly AnyRequestMiddleware[]> {
  /** Replaces the default server log line, `console.error('Error reference <id>:', error)`. */
  reporter?: ServerErrorReporter;
  /** The app's own request middleware, run after the CSRF middleware, which cannot be removed or replaced. */
  requestMiddleware?: TMiddleware;
}

type ErrorWire = { reference: string } | { public: string };

// Start's own default, which it applies only when an app has no start instance: server functions answer a
// cross-origin request with 403. Made afresh for each call, so changing one returned middleware changes no other.
const csrfMiddleware = () => createCsrfMiddleware({ filter: context => context.handlerType === 'serverFn' });
const references = new WeakMap<Error, string>();
const REFERENCE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

// One reference and one log line per error object, however often Start serialises it. Start gives a request no id, so
// each error gets a fresh UUID. This is the hook for ./log (#142): its requestId(request) replaces the UUID here, read
// through a server-only function, because a static import of Start's server module would reach the browser bundle.
function referenceFor(error: Error, reporter: ServerErrorReporter | undefined): string {
  let reference = references.get(error);
  if (reference) return reference;
  reference = crypto.randomUUID();
  references.set(error, reference);
  const log = (): void => {
    try { console.error(`Error reference ${reference}:`, error); } catch { /* nothing left to log with */ }
  };
  if (!reporter) log();
  else {
    // A failing reporter, synchronous or async, must not break the response or leave an unhandled rejection; the
    // error then reaches the server log instead.
    try { Promise.resolve(reporter(error, { reference })).catch(log); } catch { log(); }
  }
  return reference;
}

const FIXED_MESSAGE = 'Something went wrong.';
// The errors this module rebuilt from a reference, with that reference. publicErrorMessage reads the reference from
// here, never from the error, so an original server error with a reference-shaped field of its own never shows it.
const received = new WeakMap<Error, string>();

/** What the browser receives in place of an error that is not a PublicError. */
function referencedError(reference: unknown): Error & { reference: string } {
  const valid = typeof reference === 'string' && REFERENCE.test(reference), shown = valid ? reference : 'unavailable';
  const error = Object.assign(new Error(`${FIXED_MESSAGE} Reference ${shown}.`), { name: 'Error', reference: shown });
  if (valid) received.set(error, shown);
  return error;
}

/**
 * The text an error component may show. An errorComponent also renders on the server with the original error, so it
 * shows this, never `error.message`: a PublicError's message, the fixed sentence with the reference for an error the
 * browser received as a reference, and the fixed sentence alone for anything else, the server's originals included.
 * It always returns a string.
 */
export function publicErrorMessage(error: unknown): string {
  try {
    if (error instanceof PublicError) return typeof error.message === 'string' ? error.message : FIXED_MESSAGE;
    const reference = error instanceof Error ? received.get(error) : undefined;
    return reference ? `${FIXED_MESSAGE} Reference ${reference}.` : FIXED_MESSAGE;
  } catch { return FIXED_MESSAGE; }
}

/**
 * The options for `createStart(() => ten98StartOptions(...))` in src/start.ts. Every Error that crosses to the
 * browser, from a beforeLoad, a loader or a server function, crosses as a reference only and is logged in full on the
 * server; a PublicError crosses as its message only. Server functions keep Start's CSRF check.
 */
export function ten98StartOptions<const TMiddleware extends readonly AnyRequestMiddleware[] = []>(
  { reporter, requestMiddleware }: Ten98StartOptions<TMiddleware> = {},
) {
  const errorAdapter = createSerializationAdapter({
    key: 'ten98/error',
    test: (value: unknown): value is Error => value instanceof Error,
    toSerializable: (error: Error): ErrorWire => error instanceof PublicError ? { public: String(error.message) } : { reference: referenceFor(error, reporter) },
    fromSerializable: (wire: ErrorWire): Error => {
      const { public: message, reference } = (wire ?? {}) as { public?: unknown; reference?: unknown };
      return typeof message === 'string' ? new PublicError(message) : referencedError(reference);
    },
  });
  return {
    serializationAdapters: [errorAdapter] as const,
    requestMiddleware: [csrfMiddleware(), ...requestMiddleware ?? []] as unknown as readonly [ReturnType<typeof csrfMiddleware>, ...TMiddleware],
  };
}

/** Receives each error React reports in the browser, in production as well as development. It may be async. */
export type ClientErrorReporter = (error: unknown, details: { kind: 'caught' | 'uncaught' | 'recoverable'; componentStack?: string }) => void | PromiseLike<void>;

type RootErrorOptions = Required<Pick<HydrationOptions, 'onCaughtError' | 'onUncaughtError' | 'onRecoverableError'>>;

/**
 * React's root error callbacks. In development they log the error and its component stack; in production they write
 * nothing to the console. The reporter, when given, receives every error in both.
 */
export function ten98RootErrorOptions(
  { reporter, development = process.env.NODE_ENV !== 'production' }: { reporter?: ClientErrorReporter; development?: boolean } = {},
): RootErrorOptions {
  const handle = (kind: 'caught' | 'uncaught' | 'recoverable') => (error: unknown, info?: { componentStack?: string }): void => {
    if (development) console.error(`React ${kind} error:`, error, info?.componentStack ?? '');
    // A failing reporter, synchronous or async, stays silent: no console line in production, no unhandled rejection.
    if (reporter) try { Promise.resolve(reporter(error, { kind, componentStack: info?.componentStack })).catch(() => {}); } catch { /* silent */ }
  };
  return { onCaughtError: handle('caught'), onUncaughtError: handle('uncaught'), onRecoverableError: handle('recoverable') };
}

/** Start's default client entry with the root error callbacks above. Call it once from src/client.tsx. */
export function hydrateTen98Start({ reporter }: { reporter?: ClientErrorReporter } = {}): void {
  startTransition(() => {
    hydrateRoot(document, createElement(StrictMode, null, createElement(StartClient)), ten98RootErrorOptions({ reporter }));
  });
}
