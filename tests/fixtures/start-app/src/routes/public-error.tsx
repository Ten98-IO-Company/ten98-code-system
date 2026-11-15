import { createFileRoute, type ErrorComponentProps } from '@tanstack/react-router';
import { PublicError, publicErrorMessage } from '@ten98/runtime/start';
import { publicError } from '../secrets';

export const Route = createFileRoute('/public-error')({
  loader: () => { throw publicError(); },
  component: () => <p>unreachable</p>,
  errorComponent: ({ error }: ErrorComponentProps) => <p id="public-error" data-public={String(error instanceof PublicError)}>{publicErrorMessage(error)}</p>,
});
