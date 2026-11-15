import { createFileRoute } from '@tanstack/react-router';
import { detailedError } from '../secrets';

export const Route = createFileRoute('/detailed')({
  loader: () => { throw detailedError(); },
  component: () => <p>unreachable</p>,
});
