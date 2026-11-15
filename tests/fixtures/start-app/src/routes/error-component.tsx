import { createFileRoute, type ErrorComponentProps } from '@tanstack/react-router';
import { publicErrorMessage } from '@ten98/runtime/start';
import { detailedError } from '../secrets';

// A custom errorComponent renders on the server with the original error and in the browser with the one it received.
export const Route = createFileRoute('/error-component')({
  loader: () => { throw detailedError(); },
  component: () => <p>unreachable</p>,
  errorComponent: ({ error }: ErrorComponentProps) => <p id="error-component">{publicErrorMessage(error)}</p>,
});
