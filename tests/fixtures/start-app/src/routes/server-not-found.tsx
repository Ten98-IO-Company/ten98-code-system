import { createFileRoute } from '@tanstack/react-router';
import { missingFn } from '../secrets';

export const Route = createFileRoute('/server-not-found')({
  loader: () => missingFn(),
  component: () => <p>unreachable</p>,
  notFoundComponent: () => <p id="server-not-found">custom not found</p>,
});
