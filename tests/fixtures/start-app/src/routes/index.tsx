import { createFileRoute, Link } from '@tanstack/react-router';

const paths = ['/before-load', '/throw-loader', '/detailed', '/public-error', '/redirect', '/not-found', '/server-loader', '/server-redirect', '/server-not-found', '/server-fn'];

export const Route = createFileRoute('/')({
  component: () => <ul id="home">{paths.map(to => <li key={to}><Link to={to as '/'}>{to}</Link></li>)}</ul>,
});
