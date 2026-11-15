import { createFileRoute, type ErrorComponentProps } from '@tanstack/react-router';
import { publicErrorMessage } from '@ten98/runtime/start';
import { failingFn } from '../secrets';

// On a client navigation the loader calls the server function over HTTP, so its error arrives deserialised.
export const Route = createFileRoute('/server-loader')({
  loader: () => failingFn(),
  component: () => <p>unreachable</p>,
  errorComponent: ({ error }: ErrorComponentProps) => <p id="server-loader">{publicErrorMessage(error)}</p>,
});
