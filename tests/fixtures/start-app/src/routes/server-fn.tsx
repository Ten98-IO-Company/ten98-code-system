import { createFileRoute } from '@tanstack/react-router';
import { PublicError } from '@ten98/runtime/start';
import { useState } from 'react';
import { failingFn, missingFn, publicFailingFn, redirectingFn } from '../secrets';

const functions = { failing: failingFn, public: publicFailingFn, redirecting: redirectingFn, missing: missingFn };

// Each button calls one server function from the browser and shows what arrived; the links carry each function's URL
// for the HTTP tests.
function Page() {
  const [outcome, setOutcome] = useState('idle');
  const run = (name: keyof typeof functions) => functions[name]().then(
    () => setOutcome(`${name}: resolved`),
    (error: unknown) => setOutcome(`${name}: ${error instanceof PublicError ? 'PublicError' : error instanceof Error ? 'Error' : 'other'} ${error instanceof Error ? error.message : ''} ${String((error as { reference?: unknown }).reference ?? '')}`),
  );
  return <div>
    {Object.entries(functions).map(([name, fn]) => <button key={name} id={name} data-url={fn.url} onClick={() => run(name as keyof typeof functions)}>{name}</button>)}
    <pre id="outcome">{outcome}</pre>
  </div>;
}

export const Route = createFileRoute('/server-fn')({ component: Page });
