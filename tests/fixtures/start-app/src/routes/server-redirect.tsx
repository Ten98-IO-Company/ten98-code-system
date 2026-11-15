import { createFileRoute } from '@tanstack/react-router';
import { redirectingFn } from '../secrets';

export const Route = createFileRoute('/server-redirect')({
  loader: () => redirectingFn(),
  component: () => <p>unreachable</p>,
});
