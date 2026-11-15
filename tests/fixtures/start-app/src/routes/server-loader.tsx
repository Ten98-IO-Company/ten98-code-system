import { createFileRoute, type ErrorComponentProps } from '@tanstack/react-router';
import { failingFn } from '../secrets';

// On a client navigation the loader calls the server function over HTTP, so its error arrives deserialised. The
// message is shown only after hydration, because the server render holds the original error.
function Failure({ error }: ErrorComponentProps) {
  const reference = (error as { reference?: unknown }).reference;
  return <p id="server-loader" data-reference={typeof reference === 'string' ? reference : ''}>{typeof reference === 'string' ? error.message : 'Something went wrong.'}</p>;
}

export const Route = createFileRoute('/server-loader')({
  loader: () => failingFn(),
  component: () => <p>unreachable</p>,
  errorComponent: Failure,
});
