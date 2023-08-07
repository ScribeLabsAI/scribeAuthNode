import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
    },
  },
  resolve: {
    alias: [{ find: '@scribelabsai/auth', replacement: resolve(__dirname, './dist') }],
  },
});
