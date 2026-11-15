import { createFileRoute } from '@tanstack/react-router';
import { SECRET } from '../secrets';

export const Route = createFileRoute('/before-load')({
  beforeLoad: () => { throw new Error(SECRET); },
  component: () => <p>unreachable</p>,
});
