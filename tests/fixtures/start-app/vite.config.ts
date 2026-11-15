// A production Start app on the stack's pins, built by tests/start.test.mts from a copy under work/. The entry under
// test is this package's own built start.mjs, two folders above that copy.
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import react from '@vitejs/plugin-react';
import { nitro } from 'nitro/vite';

export default defineConfig({
  resolve: { alias: { '@ten98/runtime/start': fileURLToPath(new URL('../../start.mjs', import.meta.url)) } },
  plugins: [tanstackStart(), nitro({ preset: 'node-server' }), react()],
});
