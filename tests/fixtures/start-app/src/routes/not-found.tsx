import { createFileRoute, notFound } from '@tanstack/react-router';

export const Route = createFileRoute('/not-found')({
  loader: () => { throw notFound(); },
  component: () => <p>unreachable</p>,
  notFoundComponent: () => <p id="not-found">custom not found</p>,
});
