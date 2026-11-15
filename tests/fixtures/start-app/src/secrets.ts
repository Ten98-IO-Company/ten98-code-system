import { createServerFn } from '@tanstack/react-start';
import { notFound, redirect } from '@tanstack/react-router';
import { PublicError } from '@ten98/runtime/start';

// Markers that must stay on the server; the tests search every response for each one.
export const SECRET = 'fixture-hidden-message /srv/app/hidden/path';
export const CAUSE_SECRET = 'fixture-hidden-cause';
export const FIELD_SECRET = 'fixture-hidden-field';
export const DIGEST_SECRET = 'fixture-hidden-digest';
export const NAME_SECRET = 'FixtureHiddenName';
export const PUBLIC_MESSAGE = 'Your plan has expired.';

/** An Error subclass with a custom name, own fields, a digest and a nested cause chain. */
export function detailedError(): Error {
  const cause = new AggregateError([new RangeError(CAUSE_SECRET)], CAUSE_SECRET, { cause: new Error(CAUSE_SECRET) });
  class FixtureError extends TypeError { override name = NAME_SECRET; }
  return Object.assign(new FixtureError(SECRET, { cause }), { code: FIELD_SECRET, digest: DIGEST_SECRET, details: { nested: FIELD_SECRET } });
}

export const publicError = (): PublicError => Object.assign(new PublicError(PUBLIC_MESSAGE, { cause: new Error(CAUSE_SECRET) }), { code: FIELD_SECRET });

export const failingFn = createServerFn({ method: 'POST' }).handler(async () => { throw detailedError(); });
export const publicFailingFn = createServerFn({ method: 'POST' }).handler(async () => { throw publicError(); });
export const redirectingFn = createServerFn({ method: 'POST' }).handler(async () => { throw redirect({ to: '/' }); });
export const missingFn = createServerFn({ method: 'POST' }).handler(async () => { throw notFound(); });
