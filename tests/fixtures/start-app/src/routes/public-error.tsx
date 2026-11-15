import { createFileRoute, type ErrorComponentProps } from '@tanstack/react-router';
import { PublicError } from '@ten98/runtime/start';
import { publicError } from '../secrets';

// An errorComponent also renders on the server with the original error, so it shows only a PublicError's message.
export const Route = createFileRoute('/public-error')({
  loader: () => { throw publicError(); },
  component: () => <p>unreachable</p>,
  errorComponent: ({ error }: ErrorComponentProps) => <p id="public-error" data-public={String(error instanceof PublicError)}>{error instanceof PublicError ? error.message : 'Something went wrong.'}</p>,
});
