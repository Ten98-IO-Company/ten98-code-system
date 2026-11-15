import { createFileRoute } from '@tanstack/react-router';
import { SECRET } from '../secrets';

export const Route = createFileRoute('/throw-loader')({
  loader: () => { throw new Error(SECRET); },
  component: () => <p>unreachable</p>,
});
