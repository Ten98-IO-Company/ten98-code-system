import { createMiddleware, createStart } from '@tanstack/react-start';
import { ten98StartOptions } from '@ten98/runtime/start';

// One build serves each configuration under test: the server reads TEN98_FIXTURE_MODE when it starts.
const mode = typeof process === 'undefined' ? undefined : process.env.TEN98_FIXTURE_MODE;
const appMiddleware = createMiddleware().server(async ({ next }) => {
  const result = await next();
  result.response.headers.set('x-fixture-app-middleware', 'ran');
  return result;
});
const reporter = (error: Error, { reference }: { reference: string }) => console.log(`fixture reporter ${reference} ${error.message}`);

export const startInstance = createStart(() => ten98StartOptions(
  mode === 'middleware' ? { requestMiddleware: [appMiddleware] } : mode === 'reporter' ? { reporter } : undefined,
));
